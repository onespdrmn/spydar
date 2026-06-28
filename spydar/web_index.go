package main

import (
	"fmt"
	"net/http"
)

func indexHandler(w http.ResponseWriter, req *http.Request) {

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

	fmt.Fprintln(w, "<h3> Welcome to SPYDAR DNS Measurement Tool</h3>")
	fmt.Fprintln(w, "<p>This tool measures DNS caches for domain resolution behavior.  Use the sidebar to navigate through the results.</p>")
	fmt.Fprintf(w, "<p>For help, click <a href=\"/help?nonce=%s\">here</a>.</p>", Webnonce)

	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
}
