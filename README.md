# Multiparty Consent Based Networks (MCBN)

Multiparty consent based networking (`mcbn`)is a mechanism with which a threshold of participants are required to establish distributed `client->server` connectivity using properties of `TLS` itself.

Its easier to describe in prose:

Suppose there are 

* three participants `Alice, Bob, Carol`
* two application components:  `client` and `server`
* the `client` can only connect to the `server` if all three participants agree to do so (or with a threshold of participants)
* `Frank` operates a compute infrastructure where the `client` and `server` run
* each participant needs to provide their share of an encryption key which when combined will allow `client->server` connectivity
* `Frank` cannot have  the ability to see any other participants partial keys or final derived key (neither can the participants see the others)
* network traffic must be TLS encrypted (of course)

There _maybe_ ways to achieve this programmatically using bearer tokens or `x509` certificates but they generally involve a trusted third party to broker secret.  

In this procedure outlined below, no trusted third party is required.  Instead, the TLS connection itself will use the same derived shared key using data from  the participants partial keys.

Each participant will release their share of the secret to both the client and server only after ensuring the specific VM that is requesting the share is running in [Google Confidential Space](https://cloud.google.com/blog/products/identity-security/announcing-confidential-space) and the codebase it is running is going to just use the combined keyshares to establish a TLS connection to the server.  The server will use the same set of keys to accept client connections.

Basically, the network connection itself is predicated on having access to all the keys for each participant in an environment where the codebase is trusted and `Frank` cannot access any data running on the VM.

All of this is achieved using a fairly uncommon mechanism built into `TLS`:

For TCP (`TLS-PSK`):
* [Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)](https://www.rfc-editor.org/rfc/rfc4279)

For UDP - `DTLS with PSK`
* [Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347)

Basically a common `PSK` will be constructed within `Confidential Space` VM  using all participants keys (or with modification using `t-of-n` [Threshold Cryptography](https://gist.github.com/salrashid123/a871efff662a047257879ce7bffb9f13)).   The partial keys will be released to the VM only after _it proves_ to each participant it is running trusted code and the operator (`Frank`), cannot access the system.

The combined keys will create the same PSK on both the client and server and and then facilitate network connectivity. 

For  more information on confidential space, see

* [Constructing Trusted Execution Environment (TEE) with GCP Confidential Space](https://github.com/salrashid123/confidential_space)

>> **NOTE** at the moment (`2/1/23`), `Confidential Space` does *not* allow inbound network connectivity so this is a hypothetical, academic construct. 


![image/mcbn.png](images/mcbn.png)


>>> **NOTE** this repo and sample is **not** supported by google. caveat emptor

---

The following describes how to generate a client/server using `TLS-PSK` and `DTLS` from partial keys where same predictable image hash is created for the client and another predictable hash for the server.

It does **NOT** actually deploy these services to `Confidential Space` since theres no point (i.,e no inbound connectivity).  I'll update this sample with full end-to-end when it does.

In both the TLS-PSK and DTLS examples below, we're going to "derive" the new key using a `sha256(alice+bob+carl)` (yes, i know...its suspect but its a demo)

In our case,its just
```javascript
const alice = '2c6f63f8c0f53a565db041b91c0a95add8913fc102670589db3982228dbfed90';
const bob = 'b15244faf36e5e4b178d3891701d245f2e45e881d913b6c35c0ea0ac14224cc2';               
const carol = '3e2078d5cd04beabfa4a7a1486bc626d679184df2e0a2b9942d913d4b835516c';
const key = crypto.createHash('sha256').update(alice+bob+carol).digest('hex');

//console.log(key);
// which is 
key = '6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4';
```

Other realistic possibilities to derive can be some sort of KDF function or using `Threshold Cryptography` with  the final recovered [private key](https://gist.github.com/salrashid123/a871efff662a047257879ce7bffb9f13#file-main-go-L158).  (I haven't though much about the best way of how to derive a new key)

Anyway, we'll just go with the scheme above.

---

## Pre-shared Key TLS (PSK)

This sample uses `nodeJS` stack ask there are only a few languages that I've come across that do support PSK's:

other language support is  still in flight or i didn't care to learn java again

* `go`: [crypto/tls: add PSK support ](https://github.com/golang/go/issues/6379)
* `java`: [TlsPSKKeyExchange](https://www.bouncycastle.org/docs/tlsdocs1.8on/org/bouncycastle/tls/TlsPSKKeyExchange.html)

Anyway, the following hardcodes the derived key and simply sets up a client/server to demo PSK.

### PSK Server

To test locally, you can directly run the client and server.


```bash
cd server

## using node cli
npm i
node main.js

## run using bazel
#### run static
# bazel run :main

#### run image
# bazel run :server_image
# docker run -p 8081:8081 us-central1-docker.pkg.dev/builder-project/repo1/node_server
```

To generate the image with cloud build will result in the predictable hash of:

* `node_server@sha256:b0749faba840a02329463ddd8c86e04f797a18ea6689e5fe34edb72cc2391976`

This would be the image hash that is bound to `Confidential Space` server VM

```bash
cd psk/nodejs/server/the env vars specified
gcloud builds submit .

export PROJECT_ID=$(gcloud config list --format="value(core.project)")
docker pull  us-central1-docker.pkg.dev/$PROJECT_ID/repo1/node_server
docker inspect  us-central1-docker.pkg.dev/$PROJECT_ID/repo1/node_server
```

### PSK Client

To run the client,

```bash
cd client

## run using node cli
npm i
node main.js

## run using bazel
### run static
# bazel run :main

#### run image
# bazel run :image
# docker run --net=host us-central1-docker.pkg.dev/builder-project/repo1/node_client

## or just with openssl client
export PSK=6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4
openssl s_client -psk $PSK -psk_identity Client1 \
   -connect localhost:8081  -tls1_3
```

To generate the image with cloud build which will result in the predictable hash of:

* `node_client@sha256:e0ac77103ab1e37369599cdf496b3c30eeb9acf5260305e9807d639f0f6a516e`

This would be the image hash that is bound to `Confidential Space` server VM

```bash
cd psk/nodejs/client/
gcloud builds submit .

export PROJECT_ID=$(gcloud config list --format="value(core.project)")
docker pull  us-central1-docker.pkg.dev/$PROJECT_ID/repo1/node_client
docker inspect  us-central1-docker.pkg.dev/$PROJECT_ID/repo1/node_client
```

### Openssl TLS1_3

Openssl also support PSK based TLS. 

TLS1.3 reworked the cipher/ciphersuites to the following and which is open to all key exchange mechanism (including PSK even if not declared in the iana name)

```bash
$ openssl ciphers -v -s -tls1_3 -psk
   TLS_AES_256_GCM_SHA384  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(256) Mac=AEAD
   TLS_CHACHA20_POLY1305_SHA256 TLSv1.3 Kx=any      Au=any  Enc=CHACHA20/POLY1305(256) Mac=AEAD
   TLS_AES_128_GCM_SHA256  TLSv1.3 Kx=any      Au=any  Enc=AESGCM(128) Mac=AEAD
```

As a demo, you can generate a new key or use the existing one

```bash
# to generate a new key
# openssl rand -hex 32

# or use the existing one:
export PSK=6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4
export PSK_HEX=`echo  -n $PSK |   xxd -p -c 64`

# start server
openssl s_server  -psk $PSK_HEX -nocert -accept 8081  -tls1_3 -www

# in a new window with the same PSK, run client
openssl s_client -psk $PSK_HEX -tls1_3 -connect localhost:8081

## once connected via client, make an HTTP request
# GET / HTTP/1.0
# <return>
# <return>

## or with full verbosity debug HTTP 
docker run --name server --net=host -p 8081 -v `pwd`/:/apps/ \
    -ti docker.io/salrashid123/openssl s_server -psk $PSK_HEX \
    -nocert -accept 8081  -tls1_3  \
         -tlsextdebug         -trace -www

## run client
docker run  --name client   --net=host  \
   -ti docker.io/salrashid123/openssl s_client -psk $PSK_HEX \
   -connect localhost:8081  -tls1_3  \
        -tlsextdebug         -trace

# to stop docker containers,
docker rm -f client server
```

For an example with openssl and c:

* [Openssl TLS-PSK sockets in C](https://gist.github.com/salrashid123/56f45cc54feae86014ecce16403a6c1a)


### Wireshark

The following decodes the PSK traffic using wireshark and openssl:

```bash
export PSK=6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4
export PSK_HEX=`echo  -n $PSK |   xxd -p -c 64`

# start server
openssl s_server  -psk $PSK_HEX  -nocert -accept 8081  -tls1_3  -www

# in a new window start the trace
sudo tcpdump -s0 -ilo -w psk.cap port 8081

# in a new window with the PSK env set, run the client 
openssl s_client -psk $PSK_HEX  -connect localhost:8081 \
   -tls1_3  -keylogfile=keylog.log

# shutdown the tcpdump trace and view the decoded data:
wireshark psk.cap -otls.keylog_file:`pwd`/psk_keylog.log


# for tls1.2, a sample trace is provided
wireshark psk_tls12.cap  -otls.keylog_file:`pwd`/keylog_tls12.log
```

![images/cipher_suites.png](images/cipher_suites.png)

![images/psk_identity.png](images/psk_identity.png)

The traces above used `TLS13`, for `TLS12` traces:

![images/cipher_suites_tls12.png](images/cipher_suites_tls12.png)

---

## Datagram TLS (DTLS)


For UDP based traffic, we will use [Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347) and the `pion` go library here which supports `PSK`:
 
* [pion SDK for DTLS](https://github.com/pion/dtls/#using-with-psk)


### Openssl

As a prelimanary demo using openssl PSK while using tcpdump and keylogging,

```bash
export PSK=6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4
export PSK_HEX=`echo  -n $PSK |   xxd -p -c 64`

openssl s_server  -dtls1_2 -psk_identity Client1 \
   -psk $PSK_HEX -cipher PSK-AES128-CCM8  -nocert -accept 8081

# sudo tcpdump -s0 -ilo -w psk.cap port 8081

openssl s_client -dtls1_2 -psk_identity Client1 \
      -connect 127.0.0.1:8081 -psk $PSK -cipher PSK-AES128-CCM8 -keylogfile=dtls_keylog.log

wireshark dtls.cap -otls.keylog_file:`pwd`/dtls_keylog.log
```

The trace would look like this for dtls

![images/dtls_trace.png](images/dtls_trace.png)

### DTLS Server

Now similar to the TLS-PSK, we can run the client/server locally and then followup with a bazel build so that someday we can deploy to `Confidential Space`

```bash
# run server locally
go run server/server.go

## or with bazel
## optionally regenerate bazel go dependency
# bazel run :gazelle -- update-repos -from_file=go.mod -prune=true -to_macro=repositories.bzl%go_repositories

## to run using bazel
# bazel run --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 server:server 

## or generate container image locally
# bazel run  --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 server:dtls_server_image

## run server image from bazel
# docker run --net=host -p 8081:8081 us-central1-docker.pkg.dev/builder-project/repo1/dtls_server/server:dtls_server_image
```

To generate the image with cloud build which will result in the predictable hash of:

* `dtls_server@sha256:ac99f049143b03a2934753ec73141e0e72e8e42a4f5012f462ebe628fd55ff9d`
* `dtls_client@sha256:aa4a078fc357ae679d0790a3161d7bcb09a4b3a3d9f2d9e02286edb76de86ab5`


```bash
gcloud builds submit .

export PROJECT_ID=$(gcloud config list --format="value(core.project)")

docker pull us-central1-docker.pkg.dev/$PROJECT_ID/repo1/dtls_client
docker pull us-central1-docker.pkg.dev/$PROJECT_ID/repo1/dtls_server
docker inspect us-central1-docker.pkg.dev/$PROJECT_ID/repo1/dtls_server
docker inspect us-central1-docker.pkg.dev/$PROJECT_ID/repo1/dtls_client
```

### DTLS Client

To run the client 

```bash
# to run locally

go run client/client.go

## or with bazel
## optionally regenerate bazel go dependency
# bazel run :gazelle -- update-repos -from_file=go.mod -prune=true -to_macro=repositories.bzl%go_repositories

# run client locally
# bazel run --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 client:client 

## to generate container image locally
# bazel run  --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 client:dtls_client_image
## to run the client image from bazel
# docker run --net=host us-central1-docker.pkg.dev/builder-project/repo1/dtls_client/client:dtls_client_image
```


## Service Discovery

As with any client/server system, the question of service discovery is important.  

This tutorial does not specify how the client and server will connect together but will outline several options:

* `xDS` using [Google Traffic Director](https://cloud.google.com/traffic-director/docs/proxyless-overview)
  [Proxyless gRPC with Google Traffic Director](https://github.com/salrashid123/grpc_xds_traffic_director) provides a generic example not specific to this tutorial
* [Istio Service Mesh](https://istio.io/latest/about/service-mesh/)
  (have not verified but using `PSK` or `DTLS` should be possible)
* [Hashicorp Consul](https://www.consul.io/)
  You can configure consul using its [jwt auth](https://developer.hashicorp.com/consul/docs/security/acl/auth-methods/jwt) mechanism similar to Hashicorp Vault as shown [here](https://github.com/salrashid123/confidential_space#using-hashicorp-vault) 
