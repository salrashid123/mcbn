package main

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/gorilla/mux"
	"github.com/salrashid123/mcbn/seed/rand"
	"github.com/salrashid123/mcbn/seed/util"
	"golang.org/x/net/http2"
)

var (
	publicKeyHash = "" // 8csxK9BpuvU24JNkWkET_HdvyNO60ak4ygldsH4Hzew
	alice         = flag.String("alice", "b06394e28c33be5a8699759023972e9294d51b5007b3b0a51a41e9f58d406f8d", "Alice's key")
	bob           = flag.String("bob", "2d362ce19a804d12b85644abf3a0e9bbfbb0e0ba3c5dd7cc4b8e335bc5154496", "bob's key")
)

const (
	bitSize = 2048
)

type contextKey string

const contextEventKey contextKey = "event"

type event struct {
	PeerCertificates []*x509.Certificate
	KeyHash          string
}

func eventsMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		derEncoded, err := x509.MarshalPKIXPublicKey(r.TLS.PeerCertificates[0].PublicKey)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		ha := sha256.New()
		ha.Write(derEncoded)
		lpublicKeyHash := base64.RawURLEncoding.EncodeToString(ha.Sum(nil))
		if publicKeyHash != lpublicKeyHash {
			fmt.Printf("certificate hash mismatch expected %s, got %s", publicKeyHash, lpublicKeyHash)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		fmt.Printf("derived and remote certificate hash match %s\n", lpublicKeyHash)
		event := &event{
			PeerCertificates: r.TLS.PeerCertificates,
			KeyHash:          publicKeyHash,
		}
		ctx := context.WithValue(r.Context(), contextEventKey, *event)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

func gethandler(w http.ResponseWriter, r *http.Request) {
	//val := r.Context().Value(contextKey("event")).(event)
	// note val.PeerCertificates[0] is the leaf
	// for _, c := range val.PeerCertificates {
	// 	h := sha256.New()
	// 	h.Write(c.Raw)
	// 	fmt.Printf("Client Certificate hash %s\n", base64.RawURLEncoding.EncodeToString(h.Sum(nil)))
	// }
	fmt.Fprint(w, "ok")
}

func main() {

	flag.Parse()

	router := mux.NewRouter()
	router.Methods(http.MethodGet).Path("/").HandlerFunc(gethandler)

	cf, e := ioutil.ReadFile("certs/root-ca.crt")
	if e != nil {
		fmt.Println("Error loading public ca cert:", e.Error())
		os.Exit(1)
	}

	kf, e := ioutil.ReadFile("certs/root-ca.key")
	if e != nil {
		fmt.Println("Error loading public ca key:", e.Error())
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

	privkey, err := rsa.GenerateKey(rand.NewDetermRand([]byte(combinedKey)), bitSize)
	if err != nil {
		fmt.Println("Error generating key", e.Error())
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

	fmt.Printf("derived common certificate hash %s\n", publicKeyHash)

	csr, err := util.NewCSR(&util.CSR{
		PrivateKey: privkey,
		SAN:        "server.domain.com",
	})

	server_crt, err := util.NewCert(&util.Cert{
		CACert:          *ca_crt,
		CAKey:           ca_key.(*rsa.PrivateKey),
		ClientPublicKey: privkey.Public(),
		CSR:             csr,
		KeyUsages:       []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		fmt.Println("parsekey:", e.Error())
		os.Exit(1)
	}

	tlsCrt := tls.Certificate{
		Certificate: [][]byte{server_crt.Raw},
		Leaf:        server_crt,
		PrivateKey:  privkey,
	}

	client_root_pool := x509.NewCertPool()
	client_root_pool.AppendCertsFromPEM(cf)

	// *****************************************

	tlsConfig := &tls.Config{
		NextProtos:   []string{"h2", "http/1.1"},
		ClientCAs:    client_root_pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{tlsCrt},
		MinVersion:   tls.VersionTLS13,
	}

	var server *http.Server
	server = &http.Server{
		Addr:      ":8081",
		Handler:   eventsMiddleware(router),
		TLSConfig: tlsConfig,
	}

	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("", "")

	fmt.Printf("Unable to start Server %v", err)

}
