# Multiparty Consent Based Networks (MCBN)

Multiparty consent based networking (`mcbn`)is a mechanism with which a threshold of participants are required to establish distributed `client->server` connectivity using properties of `TLS` itself.

Its easier to describe in prose:

Suppose there are 

* three participants `Alice, Bob, Carol`
* two application components:  `client` and `server`
* the `client` can only connect to the `server` if all three participants agree to do so (or with a threshold of participants)
* `Frank` operates a compute infrastructure where the `client` and `server` run.
  * (or in different infrastructures (eg, `Frank` runs `client`; `Dave` runs `server` ))
* each participant needs to provide their share of an encryption key which when combined will allow `client->server` connectivity
* `Frank` cannot have  the ability to see any other participants partial keys or final derived key (neither can the participants see the others)
* network traffic must be TLS encrypted (of course)

>>> **note**  all this is really experimental and just stuff i thought of; use caution and *never* in production.

There _maybe_ ways to achieve this programmatically using bearer tokens or `x509` certificates but they generally involve a trusted third party to broker secret.  

In this procedure outlined below, no trusted third party is required.  Well...`GCP Confidential Space` as a product is trusted in the sense the attestation it provides is legit (i.,e the product is doing what it says its supposed to do) and in this sense, its not the traditional 3rd party in context here)

Each participant will release their share of the secret to both the client and server only after ensuring the specific VM that is requesting the share is running in [Google Confidential Space](https://cloud.google.com/blog/products/identity-security/announcing-confidential-space) and the codebase it is running is going to just use the combined keyshares to establish a TLS connection to the server.  The server will use the same set of keys to accept client connections.

Basically, the network connection itself is predicated on having access to all the keys for each participant in an environment where the codebase is trusted and `Frank` cannot access any data running on the VM.

All of this is achieved using a fairly uncommon mechanism built into `TLS` or the way private keys are generated

For TCP - `TLS-PSK`:
* [Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)](https://www.rfc-editor.org/rfc/rfc4279)

For UDP - `DTLS with PSK`:
* [Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347)

  Basically a common `PSK` will be constructed within `Confidential Space` VM  using all participants keys (or with modification using `t-of-n` [Threshold Cryptography](https://gist.github.com/salrashid123/a871efff662a047257879ce7bffb9f13)).   The partial keys will be released to the VM only after _it proves_ to each participant it is running trusted code and the operator (`Frank`), cannot access the system.

  The combined keys will create the same PSK on both the client and server and and then facilitate network connectivity. 

Again for TCP - `Shared RSA key derivation using constructed seeds`:

*  The final way is to derive the same RSA private key on both ends by "seeding" the shared key into the RSA key generator.  
   This allows each side to use that common RSA key to create a CSR and then have a local CA issue a TLS x509 certificate.
   Each end trusts the remote TLS cert and issuer but critical bit that is used to grant access is the _comparing the remote peers TLS certificates public key against the local key_.   
   Since each end uses the same RSA key, this comparison can ensure both ends recieved the same set of partial keys.

For  more information on confidential space, see

* [Constructing Trusted Execution Environment (TEE) with GCP Confidential Space](https://github.com/salrashid123/confidential_space)

> at the moment (`2/1/23`), `Confidential Space` does *not* allow inbound network connectivity so this is a hypothetical, academic construct. 

Though we are using a hypothetical feature of GCP `Confidential Space`, this technique can be used extended to connect multiple cloud providers.  For example, the thereshold of keys can be decoded in a client running in [AWS Nitro Enclave](https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html) or [Azure SGX](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-computing-enclaves) while the server runs on GCP.

![image/mcbn.png](images/mcbn.png)


>>> **NOTE** this repo and sample is **not** supported by google. caveat emptor

---

The following describes how to generate a client/server using `TLS-PSK` and `DTLS` from partial keys where same predictable image hash is created for the client and another predictable hash for the server.

It does **NOT** actually deploy these services to `Confidential Space` since theres no point (i.,e no inbound connectivity).  I'll update this sample with full end-to-end when it does.

In both the TLS-PSK and DTLS examples below, we're going to "derive" the new key using a `sha256(alice+bob+carl)` (yes, i know...its suspect but its a demo).

In our case,its just

```javascript
const alice = '2c6f63f8c0f53a565db041b91c0a95add8913fc102670589db3982228dbfed90';
const bob = 'b15244faf36e5e4b178d3891701d245f2e45e881d913b6c35c0ea0ac14224cc2';               
const carol = '3e2078d5cd04beabfa4a7a1486bc626d679184df2e0a2b9942d913d4b835516c';
const key = crypto.createHash('sha256').update(alice+bob+carol).digest('hex');

//console.log(key);
// which is 
key = '6d1bbd1e6235c9d9ec8cdbdf9b32d4d08304a7f305f7c6c67775130d914f4dc4';

// alternatively, 
// successively chain keys with HMAC_SHA256(data,passphrase)
// key = HMAC_SHA256(HMAC_SHA256(alice,bob),carol)

// const k1 = crypto.createHmac('sha256', bob).update(alice).digest("hex");
// const key = crypto.createHmac('sha256', carol).update(k1).digest("hex");
// console.log(key);  // gives 2b6c5604e7b5a3a9832ec2590fd058d610807cee2f3e87bb08dafbb57475d976
```

Using hmac or sha256 in these formats requires the known ordering of keys (i.e  alice is key1, bob is key2, carols is key3)...and probably the assumption participants are not sending in degenerate keys like `000000...`

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
cd psk/nodejs/server/

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

## Deterministic RSA Key

This technique basically uses both alice and bob's key together to derive the 'seed' value to use during RSA key generation.

If the same partial keys are used with a hash or KDF function that results in the same seed value, that seed value can be the "randomness" that is fed into [rsa.GenerateKey(random io.Reader, bits int) (*PrivateKey, error)](https://pkg.go.dev/crypto/rsa#GenerateKey).

Basically, you're feeding the function above a _deterministic random key_ (right...)

Its best demonstrated with the following using `certtool`:

```bash
# start with a pair of secret keys
export alice=b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d

export bob=2d362ce19a804d12b85644abf3a0e9bbfbb0e0ba3c5dd7cc4b8e335bc5154496

# generate a new one...i'm using something suspect here like just hashing the combined key...there's certainly better ways like KDF or something

export S1=`echo -n "$alice$bob" | sha256sum | cut -d ' ' -f 1`
echo $S1

# you should see   cb488e9105faa7e26cf30dcc6042fea07fd71c38953973c356d8ecf80421880e

# now use that key as the 'seed' to generate a keypari and extract the RSA public keys
certtool --generate-privkey --outfile priv1.pem --key-type=rsa --sec-param=high --seed=$S1
openssl rsa -in priv1.pem -pubout -out pub1.pem

# do it again
certtool --generate-privkey  --outfile priv2.pem --key-type=rsa --sec-param=high --seed=$S1
openssl rsa -in priv1.pem -pubout -out pub2.pem

## compare both keys being the same...
diff priv1.pem priv2.pem
```


For more info, see:

* [Generating a public/private key pair using an initial key](https://stackoverflow.com/questions/18264314/generating-a-public-private-key-pair-using-an-initial-key)
* [Making OpenSSL generate deterministic key](https://stackoverflow.com/questions/22759465/making-openssl-generate-deterministic-key)
* [Using Go deterministically generate RSA Private Key with custom io.Reader](https://stackoverflow.com/questions/74869997/using-go-deterministicly-generate-rsa-private-key-with-custom-io-reader)
* [How can one securely generate an asymmetric key pair from a short passphrase?](https://crypto.stackexchange.com/questions/1662/how-can-one-securely-generate-an-asymmetric-key-pair-from-a-short-passphrase/1665#1665)
* [Golang Deterministic crypto/rand Reader](https://gist.github.com/jpillora/5a0471b246d541b984ab)
* [Golang: A tool to generate a deterministic RSA keypair from a passphrase.](https://github.com/joekir/deterministics)
* [Python: deterministic-rsa-keygen 0.0.1](https://pypi.org/project/deterministic-rsa-keygen/)


This repo contains a small demo about this feature that i extended for mTLS:

1. client and server recieve alice and bob's secret keys
2. client and server derive the same RSA key using a hash of partial keys
3. client and server uses the RSA key to create a CSR
4. client and server uses the _same_ local CA to issue an x509 certificate for the CSR
5. server starts mTLS http server  where it accepts certificates issued by the local CA.

  The server certificate is the one created in step 4
6. client contacts the server using the local certificate from step 4

  Client accepts the server certificate if it was issued by the local CA
7. During connection establishment, both the client and server checks if the remote peer's leaf RSA public key is the same


You'll notice the code contains a local CA keypair that is built into the sample...the CA only plays a bit part in this picture..

the 'thing' that allows connection isn't the CA or the certificate it signed (that bit is just for ease of use for mTLS)...the critical bit occurs when each end compares the RSA peer certificates are the same or not.


The following shows a simple client-server where each participants keys are set

The first step shows the derived key, then the RSA key and the RSA key's hash value.  This should be the same on both ends.

Once the client makes mTLS contact, it will accept the mTLS connection if it they peer was signed by a common 

```bash
## server
$ go run server/server.go  \
  --alice=b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d \
  --bob=2d362ce19a804d12b85644abf3a0e9bbfbb0e0ba3c5dd7cc4b8e335bc5154496

derived combined key y0iOkQX6p-Js8w3MYEL-oH_XHDiVOXPDVtjs-AQhiA4
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA14gGro/kwHL7tqLhRvUbsxiV8+hQh/nTwbXvwOrO82ffMgBtfw5r
8AB0hvsSVILcIQ8/6QvXplL4hfjhbg5L3HQ1wiSG8ha94Jayxe3bHpoQ7O0ENr/w
DioEePFyCFXdtq/JdpA2sqTpd9cG9B8HHw/C4tR40/PoJhyS/rUZjKoNuV6zOIUo
LUnIsNeKCFcqGJGhfsL8q4D0ntTvFdXWAIf/d1gYBj8NOFw+zj2KBYU1l/zRsBWU
JrvpMesBMFL/+8zOQkdR1T5fBOEU9n5eiIGWx9lP0J7UBRliSYKSpThB/FrmyMz6
vaXB5aj2LigGqvQzj2E2OM0eWzG76W9TFQIDAQAB
-----END RSA PUBLIC KEY-----

derived common certificate hash 8csxK9BpuvU24JNkWkET_HdvyNO60ak4ygldsH4Hzew
Creating CSR
Creating Cert
Issued x509 with serial number 144395073894613789882005151401037591406
Starting Server..
derived and remote certificate hash match 8csxK9BpuvU24JNkWkET_HdvyNO60ak4ygldsH4Hzew


## client
$ go run client/client.go \
  --alice=b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d \
  --bob=2d362ce19a804d12b85644abf3a0e9bbfbb0e0ba3c5dd7cc4b8e335bc5154496

derived combined key y0iOkQX6p-Js8w3MYEL-oH_XHDiVOXPDVtjs-AQhiA4
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEA14gGro/kwHL7tqLhRvUbsxiV8+hQh/nTwbXvwOrO82ffMgBtfw5r
8AB0hvsSVILcIQ8/6QvXplL4hfjhbg5L3HQ1wiSG8ha94Jayxe3bHpoQ7O0ENr/w
DioEePFyCFXdtq/JdpA2sqTpd9cG9B8HHw/C4tR40/PoJhyS/rUZjKoNuV6zOIUo
LUnIsNeKCFcqGJGhfsL8q4D0ntTvFdXWAIf/d1gYBj8NOFw+zj2KBYU1l/zRsBWU
JrvpMesBMFL/+8zOQkdR1T5fBOEU9n5eiIGWx9lP0J7UBRliSYKSpThB/FrmyMz6
vaXB5aj2LigGqvQzj2E2OM0eWzG76W9TFQIDAQAB
-----END RSA PUBLIC KEY-----

derived certificate hash 8csxK9BpuvU24JNkWkET_HdvyNO60ak4ygldsH4Hzew
Creating CSR
Creating Cert
Issued x509 with serial number 308506128143660537133484591602686761852
local and remote certificate hash match 8csxK9BpuvU24JNkWkET_HdvyNO60ak4ygldsH4Hzew
Connected to IP: 127.0.0.1
200 OK
```


The the client and server certificates itself will have a unique serial numbers and issue times since the certifiates are generated at each run but the RSA key underlying it will be the same

The server i used in the example above had:

```bash
$ openssl x509 -in s.crt  -noout -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            6c:a1:7a:cb:3b:3a:54:87:cb:65:a9:e8:d3:98:f3:6e
        Signature Algorithm: rsassaPss        
        Hash Algorithm: sha256
        Mask Algorithm: mgf1 with sha256
         Salt Length: 0x20
        Trailer Field: 0x01 (default)
        Issuer: C = US, O = Operator, OU = Enterprise, CN = Enterprise Root CA
        Validity
            Not Before: May  4 14:48:31 2023 GMT
            Not After : May  3 14:48:31 2024 GMT
        Subject: C = US, ST = California, L = Mountain View, O = Acme Co, OU = Enterprise, CN = server.domain.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:d7:88:06:ae:8f:e4:c0:72:fb:b6:a2:e1:46:f5:
                    1b:b3:18:95:f3:e8:50:87:f9:d3:c1:b5:ef:c0:ea:
                    ce:f3:67:df:32:00:6d:7f:0e:6b:f0:00:74:86:fb:
                    12:54:82:dc:21:0f:3f:e9:0b:d7:a6:52:f8:85:f8:
                    e1:6e:0e:4b:dc:74:35:c2:24:86:f2:16:bd:e0:96:
                    b2:c5:ed:db:1e:9a:10:ec:ed:04:36:bf:f0:0e:2a:
                    04:78:f1:72:08:55:dd:b6:af:c9:76:90:36:b2:a4:
                    e9:77:d7:06:f4:1f:07:1f:0f:c2:e2:d4:78:d3:f3:
                    e8:26:1c:92:fe:b5:19:8c:aa:0d:b9:5e:b3:38:85:
                    28:2d:49:c8:b0:d7:8a:08:57:2a:18:91:a1:7e:c2:
                    fc:ab:80:f4:9e:d4:ef:15:d5:d6:00:87:ff:77:58:
                    18:06:3f:0d:38:5c:3e:ce:3d:8a:05:85:35:97:fc:
                    d1:b0:15:94:26:bb:e9:31:eb:01:30:52:ff:fb:cc:
                    ce:42:47:51:d5:3e:5f:04:e1:14:f6:7e:5e:88:81:
                    96:c7:d9:4f:d0:9e:d4:05:19:62:49:82:92:a5:38:
                    41:fc:5a:e6:c8:cc:fa:bd:a5:c1:e5:a8:f6:2e:28:
                    06:aa:f4:33:8f:61:36:38:cd:1e:5b:31:bb:e9:6f:
                    53:15
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                48:98:22:67:C4:45:D7:BC:16:B9:65:28:1B:1B:21:A1:BD:6F:B0:83
            X509v3 Authority Key Identifier: 
                58:88:29:FD:AA:3A:F0:9F:51:CA:FD:F1:6B:FC:D7:F0:8E:67:CF:80
            X509v3 Subject Alternative Name: 
                DNS:server.domain.com
    Signature Algorithm: rsassaPss
    Signature Value:        
        Hash Algorithm: sha256
        Mask Algorithm: mgf1 with sha256
         Salt Length: 0x20
        Trailer Field: 0x01 (default)
        a5:cf:30:d2:9d:0d:c5:c0:f0:47:c3:ab:03:aa:b4:8e:4d:94:
        6f:88:74:a5:24:d1:fa:ce:f6:35:a0:fc:e9:1d:3f:7f:80:c9:
        a5:40:e7:99:9c:45:ce:9b:80:00:b3:55:7a:d5:b7:f1:6e:25:
        aa:7b:90:d1:cc:55:2f:f7:1e:cf:7a:ac:90:a4:90:78:fc:26:
        55:60:63:04:ac:4a:0c:67:ef:f6:77:87:aa:6d:5e:6c:58:68:
        a0:83:04:7d:4b:a0:23:f7:bf:ec:28:27:14:e2:a9:8a:d6:be:
        a6:f1:4b:d0:a8:c3:91:b7:40:c2:e9:b8:dd:83:e2:08:0a:eb:
        ee:5e:be:3b:5f:af:33:44:a4:1e:3e:32:bb:69:13:ac:47:b9:
        99:63:e2:af:0f:9c:13:ac:b8:5c:a4:01:f6:51:80:6e:fc:4c:
        c3:ab:0e:2d:23:a4:ba:45:7e:5e:86:25:1e:f2:4c:c5:f5:78:
        dd:79:eb:aa:0a:50:1c:9b:b6:e5:73:53:56:1d:77:db:19:7a:
        f8:85:11:1f:d3:53:c2:66:b7:0b:ec:69:c9:32:75:7d:85:fc:
        2e:a8:7a:61:5d:ff:87:1d:66:36:3c:7e:76:dd:ad:71:bc:59:
        7b:5b:6a:30:98:ca:f9:4c:fc:b8:23:45:fc:3a:28:df:05:04:
        94:91:77:54

```

## Service Discovery

As with any client/server system, the question of service discovery is important.  

This tutorial does not specify how the client and server will connect together but will outline several options:

* `xDS` using [Google Traffic Director](https://cloud.google.com/traffic-director/docs/proxyless-overview)
   - [Proxyless gRPC with Google Traffic Director](https://github.com/salrashid123/grpc_xds_traffic_director) provides a generic example not specific to this tutorial
* [Istio Service Mesh](https://istio.io/latest/about/service-mesh/)
   - (have not verified but using `PSK` or `DTLS` should be possible)
* [Hashicorp Consul](https://www.consul.io/)
   - You can configure consul using its [jwt auth](https://developer.hashicorp.com/consul/docs/security/acl/auth-methods/jwt) mechanism similar to Hashicorp Vault as shown [here](https://github.com/salrashid123/confidential_space#using-hashicorp-vault). and [Hashicorp Consul JWT Auth](https://github.com/salrashid123/consul_jwt_auth)
