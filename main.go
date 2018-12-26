package main

import (
	"fmt"
	"github.com/appscode/go/log"
	"github.com/appscode/kutil/tools/certstore"
	"k8s.io/client-go/util/cert"

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

	fmt.Printf("%#v\n", c1.Issuer)
	fmt.Printf("%#v\n", c1.RawIssuer)

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

	fmt.Printf("%#v\n", c2.Issuer)
	fmt.Printf("%#v\n", c2.RawIssuer)
}
