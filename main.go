package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"github.com/appscode/go/log"
	"github.com/appscode/kutil/tools/certstore"
	"k8s.io/client-go/util/cert"
	"strings"

	"github.com/spf13/afero"
)

func main() {
	s1, err := certstore.NewCertStore(afero.NewMemMapFs(), "/tmp")
	if err != nil {
		log.Fatalln(err)
	}
	err = s1.NewCA()
	if err != nil {
		log.Fatalln(err)
	}
	c1, _, err := s1.NewServerCertPair(cert.AltNames{
		DNSNames: []string{"xyz.com"},
	})
	if err != nil {
		log.Fatalln(err)
	}

	//fmt.Printf("%#v\n", c1.Issuer)
	//fmt.Printf("%#v\n", c1.RawIssuer)
	fmt.Printf("%#v\n", c1.SerialNumber)
	fmt.Printf("%#v\n", Hash(c1))

	// fmt.Printf("%#v\n", c1.RawSubjectPublicKeyInfo)
	// certificate.RawSubjectPublicKeyInfo

	fmt.Println("-------------------------------------------------------------------------------------------------")

	s2, err := certstore.NewCertStore(afero.NewMemMapFs(), "/tmp")
	if err != nil {
		log.Fatalln(err)
	}
	err = s2.NewCA()
	if err != nil {
		log.Fatalln(err)
	}
	c2, _, err := s2.NewServerCertPair(cert.AltNames{
		DNSNames: []string{"xyz.com"},
	})
	if err != nil {
		log.Fatalln(err)
	}

	//fmt.Printf("%#v\n", c2.Issuer)
	//fmt.Printf("%#v\n", c2.RawIssuer)
	fmt.Printf("%#v\n", c2.SerialNumber)
	fmt.Printf("%#v\n", Hash(c2))
}

// ref: https://github.com/kubernetes/kubernetes/blob/197fc67693c2391dcbc652fc185ba85b5ef82a8e/cmd/kubeadm/app/util/pubkeypin/pubkeypin.go#L77

const (
	// formatSHA256 is the prefix for pins that are full-length SHA-256 hashes encoded in base 16 (hex)
	formatSHA256 = "sha256"
)

// Hash calculates the SHA-256 hash of the Subject Public Key Information (SPKI)
// object in an x509 certificate (in DER encoding). It returns the full hash as a
// hex encoded string (suitable for passing to Set.Allow).
func Hash(certificate *x509.Certificate) string {
	// https://tools.ietf.org/html/rfc5280#section-4.1.2.7
	spkiHash := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return formatSHA256 + ":" + strings.ToLower(hex.EncodeToString(spkiHash[:]))
}
