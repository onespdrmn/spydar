package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func viewAllHandler(w http.ResponseWriter, req *http.Request) {
	var row *sql.Rows
	var err error
	var count int = 0

	//check the nonce to make sure the request is valid
	if noncecheck(w, req) != 0 {
		fmt.Fprintln(w, "nonce mismatch in viewAllHandler, returning")
		return
	}

	db := sqliteDatabase
	row, err = db.Query("SELECT * from measurements join descriptions on measurements.name = descriptions.name")
	if err != nil {
		log.Fatal(err)
	}
	defer row.Close()

	rows := ""
	columnnames := "id,timestamp,name,domaintype,dnsserver,description,answers"
	for row.Next() { // Iterate and fetch the records from result cursor
		var id int
		var timestamp string
		var name string
		var domaintype string
		var dnsserver string
		var answers string
		var name2 string
		var description string

		err = row.Scan(&id, &timestamp, &name, &domaintype, &dnsserver, &answers, &name2, &description)
		if err != nil {
			log.Fatal("row.Scan error:", err)
		}
		_ = name2
		answers = strings.ReplaceAll(answers, ",", ";")

		timestampInt, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			log.Fatal("timestamp parse error:", err)
		}

		t := time.Unix(timestampInt, 0)
		timestamp = t.String()

		rows += fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v\n", id, timestamp, name, domaintype, dnsserver, description, answers)
		count++
	}

	makeTableFullHtml(w, columnnames, rows)

}
