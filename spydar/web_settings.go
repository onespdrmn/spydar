package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
)

func settingsHandler(w http.ResponseWriter, req *http.Request) {
	var dnsservers []dnsentry
	var err error

	//check the nonce to make sure the request is valid
	if noncecheck(w, req) != 0 {
		fmt.Fprintln(w, "nonce mismatch in settingsHandler, returning")
		return
	}

	if *dnsFile != "" {
		//log.Println("Reading DNS from file:", *dnsFile)
		buf, err := os.ReadFile(*dnsFile)
		if err != nil {
			fmt.Println("read error on ", *dnsFile)
			return
		}

		dnsservers, err = parseDNSFile(string(buf))
	} else {
		dnsservers, err = getDNSServers()
		if err != nil {
			fmt.Println("error getting dns server list")
			return
		}
	}

	fmt.Fprintln(w, "<!DOCTYPE html>")
	fmt.Fprintln(w, "<html lang=\"en\">")
	fmt.Fprintln(w, "<head>")
	fmt.Fprintln(w, "<title>Measurement Results</title>")
	fmt.Fprintln(w, "<meta charset=\"utf-8\">")
	fmt.Fprintln(w, "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	fmt.Fprintln(w, "<link rel=\"stylesheet\" type=\"text/css\" href=\"index.css\">")
	fmt.Fprintln(w, "<style>")
	fmt.Fprintln(w, style)
	fmt.Fprintln(w, "</style>")
	fmt.Fprintln(w, "</head>")
	fmt.Fprintln(w, "<body style=\"background-color: #71A8DE;\">")
	Sidebar := fmt.Sprintf(sidebar, Webnonce, Webnonce, Webnonce, Webnonce)
	fmt.Fprintln(w, Sidebar)

	fmt.Fprintln(w, "<h3>DNS servers being measured</h3>")
	for _, dnsserver := range dnsservers {
		fmt.Fprintln(w, dnsserver.dnsserver+"<br>")
	}

	fmt.Fprintln(w, "<h3>User Input Configuration:</h3>")
	if *urlinputFile != "" || *inputFile != "" {
		fmt.Fprintln(w, "url input: "+*urlinputFile+"<br>")
		fmt.Fprintln(w, "file input: "+*inputFile+"<br>")
	} else {
		fmt.Fprintln(w, "input file: none specified, using built-in list<br>")
	}

	fmt.Fprintln(w, "measurement enabled: "+strconv.FormatBool(measureEnabled)+"<br>")
	fmt.Fprintln(w, "client auth for remote server enabled: "+strconv.FormatBool(*clientAuth)+"<br>")
	fmt.Fprintln(w, "gui disabled (headless mode): "+strconv.FormatBool(*nogui)+"<br>")

	fmt.Fprintln(w, "<h3>Remote Server Configuration:</h3>")
	fmt.Fprintln(w, "logging to remote server: "+strconv.FormatBool(*sendRemoteServer)+"<br>")
	fmt.Fprintln(w, "logging server url: ", targetURL)

	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
}

