package util

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"

	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"time"
)

type Cert struct {
	CACert          x509.Certificate
	CAKey           crypto.Signer
	ClientPublicKey crypto.PublicKey
	CSR             []byte
	KeyUsages       []x509.ExtKeyUsage
}

var ()

func NewCert(conf *Cert) (*x509.Certificate, error) {

	fmt.Println("Creating Cert")

	csr, err := x509.ParseCertificateRequest(conf.CSR)
	if err != nil {
		fmt.Printf("Failed to create csr certificate: %s", err)
		return nil, err
	}

	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(time.Hour * 24 * 365)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		fmt.Printf("Failed to generate serial number: %s", err)
		return nil, err
	}

	keyBytes := x509.MarshalPKCS1PublicKey(conf.ClientPublicKey.(*rsa.PublicKey))
	keyHash := sha1.Sum(keyBytes)

	template := x509.Certificate{
		SerialNumber:       serialNumber,
		Issuer:             conf.CACert.Issuer,
		SignatureAlgorithm: x509.SHA256WithRSAPSS,
		Subject: pkix.Name{
			Organization:       []string{"Acme Co"},
			OrganizationalUnit: []string{"Enterprise"},
			Locality:           []string{"Mountain View"},
			Province:           []string{"California"},
			Country:            []string{"US"},
			CommonName:         csr.Subject.CommonName,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              []string{csr.DNSNames[0]},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		SubjectKeyId:          keyHash[:],
		AuthorityKeyId:        conf.CACert.AuthorityKeyId,
		ExtKeyUsage:           conf.KeyUsages,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &conf.CACert, conf.ClientPublicKey, conf.CAKey)
	if err != nil {
		fmt.Printf("Failed to create certificate: %s", err)
		return nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		fmt.Printf("Failed to create certificate: %s", err)
		return nil, err
	}
	fmt.Printf("Issued x509 with serial number %d\n", serialNumber)
	return cert, nil
}
