package main

import (
	"fmt"
	"net/http"
	"strings"
)

/*
call this at the beginning of any web page to check the nonce

return - 0 if the nonce is correct
return -1 if the nonce is incorrect
*/
func noncecheck(w http.ResponseWriter, req *http.Request) int {
	urlmap := req.URL.Query()
	nonce := urlmap.Get("nonce")
	if nonce != Webnonce {
		return -1
	}
	return 0
}

/*
Generic write a table as output
*/
func makeTableFullHtml(w http.ResponseWriter, columnnames string, rows string) {

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

	fmt.Fprintln(w, "<br><br>")

	fmt.Fprintln(w, "<table id=table1 class=\"center\" border=1 style='font-family:\"Courier New\", Courier, monospace; font-size:100%'>")
	fmt.Fprintln(w, "<thead>")
	fmt.Fprintln(w, "<tr>")
	colnames := strings.Split(columnnames, ",")
	for _, colname := range colnames {
		fmt.Fprintf(w, "<th>%v</th>\n", colname)
	}
	fmt.Fprintln(w, "</tr>")
	fmt.Fprintln(w, "</thead>")

	rowz := strings.Split(rows, "\n")

	for _, row := range rowz {
		value := strings.Split(row, ",")
		fmt.Fprintln(w, "<tr>")
		for _, rowval := range value {
			if len(rowval) == 0 {
				continue
			}

			fmt.Fprintln(w, "<td>")
			fmt.Fprintln(w, rowval)
			fmt.Fprintln(w, "</td>")
		}
		fmt.Fprintln(w, "</tr>")
	}
	fmt.Fprintln(w, "</tbody>")
	fmt.Fprintln(w, "</table>")

	///Load the scroll buffer of what's currently happening
	//fmt.Fprintln(w, "<script src=\"scroll.js\"></script>")

	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")

}
