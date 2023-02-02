package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"

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

	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8081}

	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			fmt.Printf("Server's hint: %s \n", hint)
			return hex.DecodeString(PSK_KEY)
		},
		PSKIdentityHint:      []byte("Client1"),
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, config)
	if err != nil {
		fmt.Printf("Error dialing : %v\n", err.Error())
		os.Exit(1)
	}

	_, err = dtlsConn.Write([]byte("This is a UDP message"))
	if err != nil {
		fmt.Printf("Write data failed: %v\n", err.Error())
		os.Exit(1)
	}

	received := make([]byte, 1024)
	_, err = dtlsConn.Read(received)
	if err != nil {
		fmt.Printf("Read data failed: %v\n", err.Error())
		os.Exit(1)
	}

	fmt.Println(string(received))

}
