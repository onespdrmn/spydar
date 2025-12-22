package main

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"unicode"

	_ "github.com/go-sql-driver/mysql" // Blank import for the driver
)

var mysqlDb *sql.DB
var dberr error

// initialize database connection
func init() {
	username, isFound := os.LookupEnv("MYSQL_USERNAME")
	if isFound == false || username == "" {
		log.Fatal("MYSQL_USERNAME is empty: ", isFound)
	}

	password, isFound := os.LookupEnv("MYSQL_PASSWORD")
	if isFound == false || password == "" {
		log.Fatal("MYSQL_PASSWORD is empty: ", isFound)
	}

	dsn := username + ":" + password + "@tcp(127.0.0.1:3306)/production"
	fmt.Println("Connecting to:", dsn)

	mysqlDb, dberr = sql.Open("mysql", dsn)
	if dberr != nil {
		log.Fatal("sql.Open failed to mysql")
	}

	_ = mysqlDb

}

// filter for valid input characters
func isValidInput(t, name, domaintype, dnsserver, answers, uniqueid string) bool {
	b0 := isValidChars(t)
	if b0 == false {
		return false
	}

	b1 := isValidChars(name)
	if b1 == false {
		return false
	}

	b2 := isValidChars(domaintype)
	if b2 == false {
		return false
	}

	b3 := isValidChars(dnsserver)
	if b3 == false {
		return false
	}

	b4 := isValidChars(answers)
	if b4 == false {
		return false
	}

	b5 := isValidChars(uniqueid)
	if b5 == false {
		return false
	}

	return true
}

// check each character in the string to see if it is allowed
func isValidChars(str string) bool {
	for _, char := range str {
		if isAlphaNumeric(char) == false {
			return false
		}
	}

	return true
}

// the approved chars are: a-zA-Z0-9,._-
func isAlphaNumeric(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == ',' || r == '-'
}

func inputHandler(w http.ResponseWriter, r *http.Request) {
	//fmt.Println("inputArgs", r.URL.Query())

	query := r.URL.Query()

	t := query.Get("time")
	name := query.Get("name")
	domaintype := query.Get("domaintype")
	dnsserver := query.Get("dnsserver")
	answers := query.Get("answers")
	uniqueid := query.Get("uniqueid")

	if isValidInput(t, name, domaintype, dnsserver, answers, uniqueid) == false {
		log.Println("invalid input detected")
		return
	}

	tt, err := strconv.Atoi(t)
	if err != nil {
		log.Println("strconv.Atoi:", err)
		return
	}

	insertStatement := `INSERT INTO measurements (time, name, domaintype, dnsserver, answers, uniqueId) VALUES (?, ?, ?, ?, ?, ?)`
	statement, err := mysqlDb.Prepare(insertStatement)
	if err != nil {
		log.Fatal("db.Prepare:", err)
		return
	}

	_, err = statement.Exec(tt, name, domaintype, dnsserver, answers, uniqueid)
	if err != nil {
		log.Fatal("statement.Exec", err)
		return
	}
}

func main() {

	fmt.Println("Listening on https://data.spydar.org:443/input/")

	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}

	server_pub_key := home + string(os.PathSeparator) + "keys/server.crt"
	server_pri_key := home + string(os.PathSeparator) + "keys/server.key"
	rootca_pub_key := home + string(os.PathSeparator) + "keys/rootCA.crt"

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
		RootCAs:      caCertPool,
	}

	mux := http.NewServeMux()

	//fs := http.FileServer(http.Dir("./assets"))

	// StripPrefix ensures the server looks for 'logo.png' in './assets/'
	// instead of './assets/static/logo.png'
	//mux.Handle("/static/", http.StripPrefix("/static/", fs))

	// setup the database input handler
	mux.HandleFunc("/input", inputHandler)

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      ":443",
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS(server_pub_key, server_pri_key))
}
