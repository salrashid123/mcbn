package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	//"net/http/httputil"

	"github.com/pion/dtls/v2"
)

var ()

const ()

func main() {

	// assume we've used workload identity for each participant and acquired their partial keys
	// since confidential space does not support inbound sockets (as of 1/2/23), the demo is moot so w'ell
	// just hardcode the keys

	alice := "2c6f63f8c0f53a565db041b91c0a95add8913fc102670589db3982228dbfed90"
	bob := "b15244faf36e5e4b178d3891701d245f2e45e881d913b6c35c0ea0ac14224cc2"
	carol := "3e2078d5cd04beabfa4a7a1486bc626d679184df2e0a2b9942d913d4b835516c"

	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%s%s%s", alice, bob, carol)))
	kb := h.Sum(nil)
	PSK_KEY := hex.EncodeToString(kb)
	//fmt.Printf("%s\n", PSK_KEY)
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w, err := os.OpenFile("dtls_keylog.log", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	config := &dtls.Config{
		KeyLogWriter: w,
		PSK: func(hint []byte) ([]byte, error) {
			fmt.Printf("Client's hint: %s \n", hint)
			return hex.DecodeString(PSK_KEY)
		},
		PSKIdentityHint:      []byte("Client1"),
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectContextMaker: func() (context.Context, func()) {
			return context.WithTimeout(ctx, 30*time.Second)
		},
	}

	l, err := dtls.Listen("udp", addr, config)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	fmt.Println("Starting dtls server")
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func(c net.Conn) {
			// Echo all incoming data.
			io.Copy(c, c)
			// Shut down the connection.
			c.Close()
		}(conn)
	}

}
