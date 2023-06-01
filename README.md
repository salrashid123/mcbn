# Multiparty Consent Based Networks (MCBN)

Multiparty consent based networking (`mcbn`)is a mechanism with which a threshold of participants are required to establish distributed `client->server` connectivity using properties of `TLS` itself.

Its easier to describe in prose:

Suppose there are 

* three participants `Alice, Bob, Carol`
* two application components:  `client` and `server`
* the `client` can only connect to the `server` if all three participants agree to do so (or with a threshold of participants)
* `Frank` operates a compute infrastructure where the `client` and `server` run.
* each participant needs to provide their share of an encryption key which when combined will allow `client->server` connectivity
* `Frank` cannot have  the ability to see any other participants partial keys or final derived key (neither can the participants see the others)
* network traffic must be TLS encrypted (of course)

>>> **note**  all this is really experimental and just stuff i thought of; use caution

While there _maybe_ ways to achieve this programmatically using bearer tokens or `x509` certificates but they generally involve a trusted third party to broker secret.  

In this procedure outlined below, no trusted third party is required. 

Each participant will release their share of the secret to both the client and server only after ensuring the specific VM that is requesting the share is running in a  Trusted Execution Environment like [Google Confidential Space](https://cloud.google.com/blog/products/identity-security/announcing-confidential-space) and the codebase which is running is going to just use the combined keyshares to establish a TLS connection to the client and server.

Basically, the network connection itself is predicated on having access to all the keys for each participant in an environment where the codebase is trusted and `Frank` cannot access any data running on the VM.

All of this is achieved using fairly uncommon mechanisms built into `TLS` or seeding how private keys are generated:

- **TCP/UDP**: [Pre-shared Key TLS (PSK)](#pre-shared-key-tls-psk)

    A common `PSK` will be constructed within `Confidential Space` VM  using all participants keys (or with modification using `t-of-n` [Threshold Cryptography](https://gist.github.com/salrashid123/a871efff662a047257879ce7bffb9f13)).   The partial keys will be released to the VM only after _it proves_ to each participant it is running trusted code and the operator (`Frank`), cannot access the system.

    The combined keys will create the same PSK on both the client and server and and then facilitate network connectivity. 

    TCP - `TLS-PSK`:
    * [Pre-Shared Key Ciphersuites for Transport Layer Security (TLS)](https://www.rfc-editor.org/rfc/rfc4279)

    UDP - `DTLS with PSK`:
    * [Datagram Transport Layer Security Version 1.2](https://www.rfc-editor.org/rfc/rfc6347)


- **RSA**: [Deterministic RSA Key](#deterministic-rsa-key)

    The same RSA private key on both ends by "seeding" the shared key into the RSA key generator.  This allows each side to use that common RSA key to create a CSR and then have a local CA issue a TLS x509 certificate.
    Each end trusts the remote TLS cert and issuer but critical bit that is used to grant access is the _comparing the remote peers TLS certificates public key against the local key_.   
    Since each end uses the same RSA key, this comparison can ensure both ends recieved the same set of partial keys.

    TCP - `Shared RSA key derivation using constructed seeds`:
---

For  more information on confidential space, see

* [Constructing Trusted Execution Environment (TEE) with GCP Confidential Space](https://github.com/salrashid123/confidential_space)

Though we are referencing GCP `Confidential Space`, this technique can be used extended to connect multiple cloud providers.  For example, the threshold of keys can be decoded in a client running in [AWS Nitro Enclave](https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html) or [Azure SGX](https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-computing-enclaves) while the server runs on GCP.

![image/mcbn.png](images/mcbn.png)


>>> **NOTE** this repo and sample is **not** supported by google. caveat emptor

---

## Combining Partial Keys

In all the examples below, we're going to "derive" the new key using a `sha256(alice+bob+carl)` which can certainly be more secure.

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

Using `HMAC` or sha256 in these formats requires the known ordering of keys (though you could just `sha256(alice xor bob xor carl) == sha256(bob xor alice xor carl)` etc....and probably the assumption participants are not sending in degenerate keys like `000000...`.

Other realistic possibilities to derive can be some sort of KDF function or using `Threshold Cryptography` with  the final recovered [private key](https://gist.github.com/salrashid123/a871efff662a047257879ce7bffb9f13#file-main-go-L158).  (I haven't though much about the best way of how to derive a new key)

For alternatives see comments on [Proper way to combine multiple secrets into one HMAC key](https://security.stackexchange.com/questions/183344/proper-way-to-combine-multiple-secrets-into-one-hmac-key), [HKDF](https://security.stackexchange.com/questions/263842/key-derivation-for-hmac-concatenate-vs-multiple-hmac-passes) and [Combining Keys](https://crypto.stackexchange.com/questions/18572/combining-two-keys)

Anyway, we'll just go with the simple scheme above.

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
certtool --generate-privkey --outfile priv1.pem --key-type=rsa --sec-param=medium --provable --seed=$S1
openssl rsa -in priv1.pem -pubout -out pub1.pem
openssl rsa -pubin -in pub1.pem -RSAPublicKey_out

-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAsv9SPzFfsbJ/a2509qwgCJlEW6c66k7nVJssjpZnK/cwXA8L8wJ6
TwtlNackAuxxUFNGeTzBvCOWGRdKkAB/zPTfbfk+P+VoduRFARH1/LbBaYHCkdYr
3qHVpdYOoYL7QVaDFMZt3crtzqLqX6coV8CyCl2F+7XIgoZ7feghMsUpgRJ1i/Cb
oVJPnjmKL4nlRtbuQjvHB4eEbOXb4qXPVu/tm8nBzsCMYrfvdzh4Luiqzi6kBcKs
Fh8wgt77loNAY084sVNpqf1pTnJNozR9PP/U0aHsopmSdcbvwsudZBJ7E1wqDX/o
mefpnh5OhJUFQOihjFxNKO5kdHgOYBsCnwIDAQAB
-----END RSA PUBLIC KEY-----


$ certtool  --verify-provable-privkey --load-privkey priv1.pem --seed=$S1
Key was verified
```


For more info, see:

* [Generating a public/private key pair using an initial key](https://stackoverflow.com/questions/18264314/generating-a-public-private-key-pair-using-an-initial-key)
* [Deterministic Random Bit Generator (DRBG)](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final)
* [How to derive a private/public keypair from a random seed](https://crypto.stackexchange.com/questions/81487/how-to-derive-a-private-public-keypair-from-a-random-seed)
* [Making OpenSSL generate deterministic key](https://stackoverflow.com/questions/22759465/making-openssl-generate-deterministic-key)
* [Using Go deterministically generate RSA Private Key with custom io.Reader](https://stackoverflow.com/questions/74869997/using-go-deterministicly-generate-rsa-private-key-with-custom-io-reader)
* [How can one securely generate an asymmetric key pair from a short passphrase?](https://crypto.stackexchange.com/questions/1662/how-can-one-securely-generate-an-asymmetric-key-pair-from-a-short-passphrase/1665#1665)
* [Golang: A tool to generate a deterministic RSA keypair from a passphrase.](https://github.com/joekir/deterministics)
* [Python: deterministic-rsa-keygen 0.0.1](https://pypi.org/project/deterministic-rsa-keygen/)
* [Stackexchange: Proper way to combine multiple secrets into one HMAC key](https://security.stackexchange.com/questions/183344/proper-way-to-combine-multiple-secrets-into-one-hmac-key)


This repo contains a small demo about this feature that i extended for mTLS:

1. client and server recieve alice and bob's secret keys
2. client and server derive the same RSA key using a hash of partial keys
3. client and server uses the RSA key to create a CSR
4. client and server uses *any* CA to issue an x509 certificate for the CSR
5. server starts mTLS http server  where it accepts certificates issued by the remote peers CA.
6. client contacts the server using its local client certificate and accepts the server's cert issued by its peers CA
7. During connection establishment, both the client and server checks if the remote peer's leaf **RSA public key** is the same the local copy.

You'll notice the code contains a local CA keypair that is built into the sample...the CA only plays a bit part in this picture..

the 'thing' that allows connection isn't the CA or the certificate it signed (that bit is just for ease of use for mTLS)...the critical bit occurs when each end compares the RSA peer certificates are the same or not.

note, you could also conceive of a common public CA signer service which only accepts CSRs where the public rsa key is of the expected value (i.,e will only issue client or server certs to CSRs originating from a TEE)

This repo uses [Deterministic Random Bit Generator (DRBG)](https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final) implemented through [github.com/canonical/go-sp800.90a-drbg](https://pkg.go.dev/github.com/canonical/go-sp800.90a-drbg#NewHash) to generate the deterministic rsa key.

For example:

```golang
import (
    drbg "github.com/canonical/go-sp800.90a-drbg"
)

    combinedKey := "y0iOkQX6p-Js8w3MYEL-oH_XHDiVOXPDVtjs-AQhiA4"
	r, err := drbg.NewHash(crypto.SHA256, nil, bytes.NewReader([]byte(combinedKey)))
	privkey, err := rsa.GenerateKey(r, bitSize)
```




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
MIIBCgKCAQEAwdE0acCUALJSqt9UmWKvk/sc175VgZuuUwg+iSCWmtjD6Qd/u1bU
ldo0P8CLFhBEaxm8PZH5PnFydEDxmt7S3GFE1rzpY0/P99A+kmIIC1Zayff3YaWs
Dcl3OgooVl/yLeAa2MAB2ndS+eAfJiZG8UTPpUf3nKeS7ly/8JS8NV6+QI5flPBr
QWXgCstpkbDvDu6G26/h8SeEI0GXs6L/TjWMWfo7uucr/dzgLkVG0DwKidJf1H+b
MPrr/sPL6tP69O7vCQslWqUI1LT1J/prds2obORrTqAqNdJL5jqcBYhNMmXr6aca
DNhL2Ox6s1Llj1/k0CO8KAJcnlp4Ex57MQIDAQAB
-----END RSA PUBLIC KEY-----

derived common certificate hash gZsMz8rjAua3fQOBoNinyDwvRUXM72hU6cYUnHqGyow
Creating CSR
Creating Cert
Issued x509 with serial number 254409249534854011802637476841032193225
Starting Server..
derived and remote certificate hash match gZsMz8rjAua3fQOBoNinyDwvRUXM72hU6cYUnHqGyow


## client
$ go run client/client.go \
  --alice=b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d \
  --bob=2d362ce19a804d12b85644abf3a0e9bbfbb0e0ba3c5dd7cc4b8e335bc5154496

derived combined key y0iOkQX6p-Js8w3MYEL-oH_XHDiVOXPDVtjs-AQhiA4
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAwdE0acCUALJSqt9UmWKvk/sc175VgZuuUwg+iSCWmtjD6Qd/u1bU
ldo0P8CLFhBEaxm8PZH5PnFydEDxmt7S3GFE1rzpY0/P99A+kmIIC1Zayff3YaWs
Dcl3OgooVl/yLeAa2MAB2ndS+eAfJiZG8UTPpUf3nKeS7ly/8JS8NV6+QI5flPBr
QWXgCstpkbDvDu6G26/h8SeEI0GXs6L/TjWMWfo7uucr/dzgLkVG0DwKidJf1H+b
MPrr/sPL6tP69O7vCQslWqUI1LT1J/prds2obORrTqAqNdJL5jqcBYhNMmXr6aca
DNhL2Ox6s1Llj1/k0CO8KAJcnlp4Ex57MQIDAQAB
-----END RSA PUBLIC KEY-----

derived certificate hash gZsMz8rjAua3fQOBoNinyDwvRUXM72hU6cYUnHqGyow
Creating CSR
Creating Cert
Issued x509 with serial number 28378151564278790075530879622077036809
local and remote certificate hash match gZsMz8rjAua3fQOBoNinyDwvRUXM72hU6cYUnHqGyow
Connected to IP: 127.0.0.1
200 OK
ok
```


The the client and server certificates itself will have a unique serial numbers and issue times since the certifiates are generated at each run but the RSA key underlying it will be the same

The server i used in the example above had:

```bash
$ openssl x509 -in s.crt  -noout -text

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            2f:47:7f:70:a7:06:7a:4b:26:c6:c6:cb:b0:d4:1d:db
        Signature Algorithm: rsassaPss        
        Hash Algorithm: sha256
        Mask Algorithm: mgf1 with sha256
         Salt Length: 0x20
        Trailer Field: 0x01 (default)
        Issuer: C = US, O = Operator, OU = Enterprise, CN = Enterprise Root CA
        Validity
            Not Before: Jun  1 13:56:30 2023 GMT
            Not After : May 31 13:56:30 2024 GMT
        Subject: C = US, ST = California, L = Mountain View, O = Acme Co, OU = Enterprise, CN = server.domain.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:c1:d1:34:69:c0:94:00:b2:52:aa:df:54:99:62:
                    af:93:fb:1c:d7:be:55:81:9b:ae:53:08:3e:89:20:
                    96:9a:d8:c3:e9:07:7f:bb:56:d4:95:da:34:3f:c0:
                    8b:16:10:44:6b:19:bc:3d:91:f9:3e:71:72:74:40:
                    f1:9a:de:d2:dc:61:44:d6:bc:e9:63:4f:cf:f7:d0:
                    3e:92:62:08:0b:56:5a:c9:f7:f7:61:a5:ac:0d:c9:
                    77:3a:0a:28:56:5f:f2:2d:e0:1a:d8:c0:01:da:77:
                    52:f9:e0:1f:26:26:46:f1:44:cf:a5:47:f7:9c:a7:
                    92:ee:5c:bf:f0:94:bc:35:5e:be:40:8e:5f:94:f0:
                    6b:41:65:e0:0a:cb:69:91:b0:ef:0e:ee:86:db:af:
                    e1:f1:27:84:23:41:97:b3:a2:ff:4e:35:8c:59:fa:
                    3b:ba:e7:2b:fd:dc:e0:2e:45:46:d0:3c:0a:89:d2:
                    5f:d4:7f:9b:30:fa:eb:fe:c3:cb:ea:d3:fa:f4:ee:
                    ef:09:0b:25:5a:a5:08:d4:b4:f5:27:fa:6b:76:cd:
                    a8:6c:e4:6b:4e:a0:2a:35:d2:4b:e6:3a:9c:05:88:
                    4d:32:65:eb:e9:a7:1a:0c:d8:4b:d8:ec:7a:b3:52:
                    e5:8f:5f:e4:d0:23:bc:28:02:5c:9e:5a:78:13:1e:
                    7b:31
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier: 
                68:33:6F:B6:97:F5:7E:68:44:AA:DE:60:3B:A5:64:56:5D:86:67:E9
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
        3b:9d:3d:27:da:e5:a2:d3:78:ef:2d:59:2a:dc:a6:c4:89:20:
        88:5a:ca:f3:8f:3d:13:62:3b:7a:0f:8d:fd:04:c3:56:21:a9:
        21:c5:8f:18:35:70:a9:e5:27:a7:9e:c9:eb:9c:e0:5e:de:2b:
        ed:46:9c:0b:10:87:af:d8:f3:c6:bc:7e:27:db:21:9f:14:38:
        65:a1:bc:8f:c6:28:52:0d:08:c2:c7:6a:b7:c5:d7:2b:e7:79:
        b2:86:66:ef:ac:ce:06:6d:d9:47:d2:c6:7f:9c:a1:7c:80:40:
        e9:4f:4a:61:84:b1:2a:ff:e9:13:56:7e:0a:0d:20:f0:96:2a:
        be:0b:7a:8d:62:2f:f4:9e:a2:a5:63:bf:34:55:83:31:5c:23:
        01:b6:d3:9e:36:02:ee:62:ae:b1:8e:2d:8e:c4:26:77:83:c3:
        42:81:08:f6:19:a8:ce:f0:7e:45:bc:7f:be:62:4f:88:53:8c:
        3a:1a:3a:96:5f:5a:1b:48:bf:20:59:47:7f:46:d9:99:1e:d4:
        b4:d4:26:67:06:07:c1:24:36:0c:1b:7f:03:c4:dc:8a:b9:60:
        59:a3:00:4c:27:32:c8:c5:c3:15:f9:6d:59:1c:79:56:a7:44:
        50:20:e3:19:2c:3d:64:a2:a9:a3:90:28:dc:56:60:e4:6a:61:
        66:7a:3a:bc
```

