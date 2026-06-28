package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func whois(name string) string {

	domain := getdomain(name)

	linkstart := "<a href=https://www.whois.com/whois/"
	linkmiddle := domain + ">" + name
	linkend := "</a>"

	link := linkstart + linkmiddle + linkend
	return link
}

// link to ip geolocation service
func geoiplookup(names string) string {

	var isIP bool
	var str string

	linkstart := "<a href=https://www.geolocation.com/?ip="

	strsep := ","
	if strings.Contains(names, ";") {
		strsep = ";"
	}

	spl := strings.Split(names, strsep)
	if len(spl) == 0 {
		return names
	} else {
		for _, entry := range spl {
			isIP = true
			ip := net.ParseIP(entry)
			if ip == nil {
				isIP = false
			}

			if isIP == true {
				str = linkstart + entry + "#ipresult>" + entry + "</a>"
				//str = linkstart + entry + "#ipresult>" + "geo" + "</a>"
			} else {
				str = whois(entry)
				//str = str + ",&nbsp;&nbsp;"
			}
		}
	}

	return str
}

func geminiLink(value string) string {
	return fmt.Sprintf("<a href=@gemini is %v a malware hosting site?>gemini query</a>", value)
}

func googleLink(value string) string {
	return fmt.Sprintf("<a href=https://www.google.com/search?q=is+%v+malware?>ai prompt</a>", value)
}

func makeLink(value string) string {
	link := ""
	if net.ParseIP(value) == nil {
		link = whois(value)
	} else {
		link = geoiplookup(value)
	}

	return link
}

func viewUniqueHandler(w http.ResponseWriter, req *http.Request) {
	var noArgs bool = false
	var row *sql.Rows
	var err error

	name := ""

	urlmap := req.URL.Query()
	name = urlmap.Get("name")

	//check the nonce to make sure the request is valid
	if noncecheck(w, req) != 0 {
		fmt.Fprintln(w, "nonce mismatch in viewUniqueHandler, returning")
		return
	}

	db := sqliteDatabase

	if name == "" {
		noArgs = true
	}

	if noArgs == true {
		row, err = db.Query("SELECT distinct measurements.name,descriptions.description from measurements join descriptions on measurements.name = descriptions.name")
	} else {
		/*
			if isInputSane1(urlargsmap) == false {
				fmt.Fprintln(w, "INPUT IS NOT SANE")
				return
			}
		*/

		//row, err = db.Query(fmt.Sprintf("SELECT distinct * from measurements join descriptions on measurements.name = descriptions.name where measurements.name='%s'", urlargsmap["name"]))
		row, err = db.Query(fmt.Sprintf("SELECT distinct * from measurements join descriptions on measurements.name = descriptions.name where measurements.name='%s'", name))
	}
	if err != nil {
		log.Fatal(err)
	}
	defer row.Close()

	rows := ""
	columnnames := ""
	if noArgs == true {
		columnnames = "name,description"
		for row.Next() { // Iterate and fetch the records from result cursor
			var name string
			var description string
			row.Scan(&name, &description)
			name = fmt.Sprintf("<a href=http://localhost:8080/viewunique?nonce=%s&name=%s>%s</a>", Webnonce, name, name)
			rows += fmt.Sprintf("%v,%v\n", name, description)
		}
	} else {
		columnnames = "id,time seen in cache,dns name,domaintype,dnsserver,answers,otherlinks"
		for row.Next() {
			var id int
			var timestamp string
			var name string
			var domaintype string
			var dnsserver string
			var answers string
			var name2 string
			var description string
			row.Scan(&id, &timestamp, &name, &domaintype, &dnsserver, &answers, &name2, &description)
			_ = name2

			///name link and answer links
			namelink := makeLink(name)
			answers = strings.ReplaceAll(answers, ",", ";")
			answerlinks := geoiplookup(answers)

			///google and gemini links
			otherlinks := googleLink(name)
			//otherlinks += "&nbsp;"
			//otherlinks += geminiLink(name)

			//time in seconds to human readable time string
			unixInt, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil {
				continue
			}
			t := time.Unix(unixInt, 0)

			if len(name) > 0 {
				rows += fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v\n", id, t.String(), namelink, domaintype, dnsserver, answerlinks, otherlinks)
			}
		}
	}

	makeTableFullHtml(w, columnnames, rows)
}
