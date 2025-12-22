package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"database/sql"
	_ "github.com/go-sql-driver/mysql" // Blank import for the driver
	"os"
)

var Db *sql.DB

func init(){
	dsn := username + ":" + password + "@tcp(127.0.0.1:3306)/production"
	fmt.Println("Connecting to:", dsn)

	Db, err := sql.Open("mysql", dsn)
	if err != nil {
		log.Fatal("sql.Open failed to mysql")
	}

	_ = mysqlDb

}

func inputHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("inputHandler", r.URL.Path)
	fmt.Println("inputArgs", r.URL.Query())
}

func main() {
	fmt.Println("Listening on https://data.spydar.org:443/input/")

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	server_pub_key := home + string(os.PathSeparator) + "keys/server.pub"
	server_pri_key := home + string(os.PathSeparator) + "keys/server.key"
	rootca_pub_key := home + string(os.PathSeparator) + "keys/rootCA.pub"

	// Create a CA certificate pool
	caCert, err := ioutil.ReadFile(rootca_pub_key)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Get servercert
	servercert, err := tls.LoadX509KeyPair(server_pub_key, server_pri_key)
	if err != nil {
		log.Fatal(err)
	}

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

	// setup the database input handler
	http.HandleFunc("/input", inputHandler)

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS(server_pub_key, server_pri_key))
}

