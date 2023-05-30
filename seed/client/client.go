package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/salrashid123/mcbn/seed/util"
)

var (
	publicKeyHash = "" // 8csxK9BpuvU24JNkWkET_HdvyNO60ak4ygldsH4Hzew
	alice         = flag.String("alice", "b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d", "Alice's key")
	bob           = flag.String("bob", "2d362ce19a804d12b85644abf3a0e9bbfbb0e0ba3c5dd7cc4b8e335bc5154496", "bob's key")
)

const (
	bitSize    = 2048
	serverName = "server.domain.com"
)

func main() {

	flag.Parse()

	cf, e := ioutil.ReadFile("certs/root-ca.crt")
	if e != nil {
		fmt.Println("Error loading public ca cert::", e.Error())
		os.Exit(1)
	}

	kf, e := ioutil.ReadFile("certs/root-ca.key")
	if e != nil {
		fmt.Println("Error loading public ca key::", e.Error())
		os.Exit(1)
	}

	cpb, _ := pem.Decode(cf)
	kpb, _ := pem.Decode(kf)
	ca_crt, err := x509.ParseCertificate(cpb.Bytes)
	if err != nil {
		fmt.Println("Error parsing public ca cert::", e.Error())
		os.Exit(1)
	}
	ca_key, err := x509.ParsePKCS8PrivateKey(kpb.Bytes)
	if err != nil {
		fmt.Println("Error loading public ca key:", e.Error())
		os.Exit(1)
	}

	hk := sha256.New()
	hk.Write([]byte(fmt.Sprintf("%s%s", *alice, *bob)))
	combinedKey := base64.RawURLEncoding.EncodeToString(hk.Sum(nil))

	fmt.Printf("derived combined key %s\n", combinedKey)

	privkey, err := rsa.GenerateKey(util.NewDetermRand([]byte(combinedKey)), bitSize)
	if err != nil {
		fmt.Println("error generating key:", e.Error())
		os.Exit(1)
	}

	pub := privkey.Public()

	pubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(pub.(*rsa.PublicKey)),
		},
	)
	fmt.Printf("%s\n", pubPEM)

	derEncoded, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		fmt.Println("error decoding combined key:", e.Error())
		os.Exit(1)
	}

	h := sha256.New()
	h.Write(derEncoded)
	publicKeyHash = base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	fmt.Printf("derived certificate hash %s\n", publicKeyHash)

	csr, err := util.NewCSR(&util.CSR{
		PrivateKey: privkey,
		SAN:        "client.domain.com",
	})

	client_crt, err := util.NewCert(&util.Cert{
		CACert:          *ca_crt,
		CAKey:           ca_key.(*rsa.PrivateKey),
		ClientPublicKey: privkey.Public(),
		CSR:             csr,
		KeyUsages:       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		fmt.Println("Error creating new certificate:", e.Error())
		os.Exit(1)
	}

	tlsCrt := tls.Certificate{
		Certificate: [][]byte{client_crt.Raw},
		Leaf:        client_crt,
		PrivateKey:  privkey,
	}

	server_root_pool := x509.NewCertPool()
	ok := server_root_pool.AppendCertsFromPEM(cf)
	if !ok {
		fmt.Printf("could not add ca")
		return
	}
	tlsConfig := &tls.Config{
		ServerName:   serverName,
		RootCAs:      server_root_pool,
		Certificates: []tls.Certificate{tlsCrt},
		MinVersion:   tls.VersionTLS13,

		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			for _, rawCert := range rawCerts {
				c, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return err
				}
				derEncoded, err := x509.MarshalPKIXPublicKey(c.PublicKey)
				if err != nil {
					return err
				}
				ha := sha256.New()
				ha.Write(derEncoded)
				lpublicKeyHash := base64.RawURLEncoding.EncodeToString(ha.Sum(nil))
				if publicKeyHash != lpublicKeyHash {
					return fmt.Errorf("local and remote certificate hash mismatch expected %s, got %s", publicKeyHash, lpublicKeyHash)
				}
				fmt.Printf("local and remote certificate hash match %s\n", lpublicKeyHash)
				opts := x509.VerifyOptions{
					Roots: server_root_pool,
					KeyUsages: []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
					},
				}
				_, err = c.Verify(opts)
				if err != nil {
					return err
				}
			}
			return nil
		},
	}

	tr := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := tls.Dial(network, addr, tlsConfig)
			if err != nil {
				return conn, err
			}
			err = conn.Handshake()
			if err != nil {
				return conn, err
			}
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			ip := net.ParseIP(host)
			fmt.Printf("Connected to IP: %s\n", ip)
			return conn, nil
		},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Get("https://localhost:8081")
	if err != nil {
		log.Println(err)
		return
	}

	htmlData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("%v\n", resp.Status)
	fmt.Printf(string(htmlData))

}
