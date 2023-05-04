package util

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"crypto/x509"
	"crypto/x509/pkix"
)

const ()

type CSR struct {
	PrivateKey *rsa.PrivateKey
	SAN        string
}

var ()

func NewCSR(conf *CSR) ([]byte, error) {

	fmt.Println("Creating CSR")

	var csrtemplate = x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         conf.SAN,
		},
		DNSNames:           []string{conf.SAN},
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, conf.PrivateKey)
	if err != nil {
		fmt.Printf("Failed to create CSR: %s\n", err)
		return nil, err
	}
	return csrBytes, nil

}
