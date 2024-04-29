#### Java PSK server

Simple java bouncycastle provider which starts up a TLS PKS server.

The server just echo's back the transmitted data.

TODO: figure out how to enable tls1.3

- Start server

```bash
$ mvn clean install exec:java


		Accepted Socket[addr=/127.0.0.1,port=34580,localport=8081]
		TLS-PSK server negotiated TLS 1.2
		Server 'tls-server-end-point': (null)
		Server 'tls-unique': 1fd89d56b61db43e1733aa8f
		TLS-PSK server completed handshake for PSK identity: client1
		echo
```

- Run client

```bash
$ export PSK="b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d"
$ openssl s_client -psk $PSK -psk_identity client1 -connect 127.0.0.1:8081  -tls1_2


		Connecting to 127.0.0.1
		CONNECTED(00000003)
		Can't use SSL_get_servername
		---
		no peer certificate available
		---
		No client certificate CA names sent
		Server Temp Key: X25519, 253 bits
		---
		SSL handshake has read 167 bytes and written 340 bytes
		Verification: OK
		---
		New, TLSv1.2, Cipher is ECDHE-PSK-CHACHA20-POLY1305
		Secure Renegotiation IS supported
		Compression: NONE
		Expansion: NONE
		No ALPN negotiated
		SSL-Session:
			Protocol  : TLSv1.2
			Cipher    : ECDHE-PSK-CHACHA20-POLY1305
			Session-ID: 
			Session-ID-ctx: 
			Master-Key: 76FC367966970D607592FBC8146C350DF11CC48CAB24D86898A03BAEA9C48298934A5BE4534248E40384F12D9A8DD2DB
			PSK identity: client1
			PSK identity hint: hint
			SRP username: None
			Start Time: 1714228759
			Timeout   : 7200 (sec)
			Verify return code: 0 (ok)
			Extended master secret: yes
		---
		echo
		echo
```

---

References

* [Java Bouncy Castle TLS PSK example](https://tiebing.blogspot.com/2013/09/java-bouncy-castle-tls-psk-example.html)