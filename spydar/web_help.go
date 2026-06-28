package main

import (
	"fmt"
	"net/http"
)

func helpHandler(w http.ResponseWriter, req *http.Request) {

	//check the nonce to make sure the request is valid
	if noncecheck(w, req) != 0 {
		fmt.Fprintln(w, "nonce mismatch in helpHandler, returning")
		return
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
	fmt.Println("Sidebar:", Sidebar)
	fmt.Fprintln(w, Sidebar)

	fmt.Fprintln(w, "<h3> Welcome to SPYDAR DNS Measurement Tool Help</h3>")
	fmt.Fprintln(w, "<p>This tool measures DNS caches for malware domain resolution behavior.  Use the sidebar to navigate through the results.</p>")
	fmt.Fprintln(w, "<p>More help will be coming later.</a>.</p>")

	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
}
