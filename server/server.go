package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func inputHandler(w http.ResponseWriter, r *http.Request) {

	fmt.Println("inputHandler", r.URL.Path)
	fmt.Println("inputArgs", r.URL.Query())

}

func main() {
	fmt.Println("Listening on https://data.spydar.org:443/input/")

	// Create a CA certificate pool
	caCert, err := ioutil.ReadFile("keys/rootCA.pub")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	servercert, _ := tls.LoadX509KeyPair("keys/server.pub", "keys/server.key")

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		Certificates: []tls.Certificate{servercert},
	}

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
	}

	http.HandleFunc("/input", inputHandler)

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS("keys/server.pub", "keys/server.key"))
}
