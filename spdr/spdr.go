package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"database/sql"

	"fyne.io/systray"
	"fyne.io/systray/example/icon"
	"github.com/beevik/ntp"
	_ "github.com/mattn/go-sqlite3" // Import the driver
	"github.com/miekg/dns"
)

var sidebar string = `
<div id="mySidebar" class="sidebar">
  <a href="javascript:void(0)" class="closebtn" onclick="closeNav()">×</a>
  <a href="viewunique">View Unique</a>
  <a href="viewall">View All</a>
  <a href="settings">Settings</a>
  <a href="help">Help</a>
</div>

<div id="main">
  <button class="openbtn" onclick="openNav()">☰</button>  
</div>

<script>
function openNav() {
  document.getElementById("mySidebar").style.width = "250px";
  document.getElementById("main").style.marginLeft = "250px";
}

function closeNav() {
  document.getElementById("mySidebar").style.width = "0";
  document.getElementById("main").style.marginLeft= "0";
}
</script>
`
var style string = `
//html table 
table {
  border-collapse: collapse;
  width: 100%;
  font-family: Arial, sans-serif;
}

th, td {
  border: 1px solid #333;
  padding: 12px;
  text-align: left;
}

th {
  background-color: #333;
  color: white;
}

tr:nth-child(odd) {
  background-color: #8A7B7B;
}

tr:nth-child(even) {
  background-color: #1a1a1a;
}

tr:nth-child(odd) td {
  color: #333;
}

tr:nth-child(even) td {
  color: white;
}

//scrolling 
:root{
  display:flex;
  flex-direction:column;
  align-content:center;
  justify-content:center;
  height:100dvh;
  background:black;
  font-family:sans-serif;
  color:white;
}

canvas{
  margin:0 auto;
  display:block;
  background-color:white;
  overflow-y: auto;
}

.author{
  position:fixed;
  bottom:1em;
  right:1em;
  font-size:clamp(16px,4dvh,32px);
  color:white;
}

.author a {
  color:#afa;
  font-weight:bold;
}

//iframe
iframe-container {
    /* The parent must have a position other than static for
       the absolute positioning of the iframe to work correctly */
    position: relative;
    width: 600px;
    height: 400px;
    border: 1px solid black;
  }

  .my-iframe1 {
    position: absolute; /* Positions the iframe relative to the container */
    top: 0px;
    left: 0px;
    width: 400px;
    height: 450px;
    border: none;
  }

  .my-iframe2 {
    position: absolute; /* Positions the iframe relative to the container */
    top: 0px;
    left: 500px;
    width: 300px;
    height: 400px;
    border: none;
  }

body {
  font-family: "Lato", sans-serif;
}

.sidebar {
  height: 100%;
  width: 0;
  position: fixed;
  z-index: 1;
  top: 0;
  left: 0;
  background-color: #111;
  overflow-x: hidden;
  transition: 0.5s;
  padding-top: 60px;
}

.sidebar a {
  padding: 8px 8px 8px 32px;
  text-decoration: none;
  font-size: 25px;
  color: #818181;
  display: block;
  transition: 0.3s;
}

.sidebar a:hover {
  color: #f1f1f1;
}

.sidebar .closebtn {
  position: absolute;
  top: 0;
  right: 25px;
  font-size: 36px;
  margin-left: 50px;
}

.openbtn {
  font-size: 20px;
  cursor: pointer;
  background-color: #111;
  color: white;
  padding: 10px 15px;
  border: none;
}

.openbtn:hover {
  background-color: #444;
}

#main {
  transition: margin-left .5s;
  padding: 16px;
}

/* On smaller screens, where height is less than 450px, change the style of the sidenav (less padding and a smaller font size) */
@media screen and (max-height: 450px) {
  .sidebar {padding-top: 15px;}
  .sidebar a {font-size: 18px;}
}

`
var measureEnabled = true
var sqliteDatabase *sql.DB
var verbose bool = false

type DNSResult struct {
	Response    *dns.Msg
	RTT         time.Duration
	Err         error
	dnsserver   string
	domainname  string
	domaintype  string
	domaindescr string
	wg          *sync.WaitGroup
}

type listentry struct {
	entry      string
	entrytype  string
	entrydescr string
}

type dnsentry struct {
	dnsserver string
	isalive   bool
}

type precision struct {
	domainname string
	unixtime   int
	uniqueid   string
}

var quitChannel1 = make(chan struct{})
var quitChannel2 = make(chan struct{})
var resultChan = make(chan DNSResult)
var result2Chan = make(chan DNSResult)

// considering use of: https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt
// right now looking for specific NS records but could also look for A records
// var measurelist []string = []string{"google.com.", "0.beer.", "0.club", "0.fashion"}
var outfd *os.File

var measurelist []listentry = []listentry{}
var validatedmeasurelist []listentry = []listentry{}
var validatedserverlist []dnsentry = []dnsentry{}
var targetURL = "https://data.spydar.org/input"

// do any initialization here
func init() {
	var err error
	var fileCreated bool = false
	databaseFile := "./sqlite-database.db"
	//outFile := "output.csv"
	//log.Println("Removing:", databaseFile)
	//os.Remove(databaseFile)
	//os.Remove(outFile)
	log.Println("Creating:", databaseFile)

	//if the file doesn't exist, create it
	_, err = os.Stat(databaseFile)
	if err != nil {
		file, err := os.Create(databaseFile) // Create SQLite file
		if err != nil {
			log.Fatal(err.Error())
		}
		file.Close()
		log.Println("Created:", databaseFile)
		fileCreated = true
	}

	/*
		outfd, err = os.Create(outFile)
		if err != nil {
			log.Fatal(err.Error())
		}
	*/

	sqliteDatabase, _ = sql.Open("sqlite3", databaseFile) // Open the created SQLite File

	if fileCreated {
		createTables(sqliteDatabase) // Create Database Tables
	}

	// Set the maximum number of open connections to 1
	sqliteDatabase.SetMaxOpenConns(1)

}

func createTables(db *sql.DB) {
	///this is the table for the measurement results
	createTableSQL := `CREATE TABLE measurements (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,		
		"time" TEXT,
		"name" TEXT,
		"domaintype" TEXT, 
		"dnsserver" TEXT,
		"answers" TEXT
	  );` // SQL Statement for Create Table

	log.Println("Create domain measurements table...")
	statement, err := db.Prepare(createTableSQL) // Prepare SQL Statement
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec() // Execute SQL Statements
	log.Println("measurements table created")

	///this is the table for the domain descriptions

	log.Println("Create domain descriptions table...")
	createTableSQL = `CREATE TABLE descriptions (
				"name" TEXT NOT NULL UNIQUE,
				"description" TEXT NO NULL
				);`

	statement, err = db.Prepare(createTableSQL)
	if err != nil {
		log.Fatal(err.Error())
	}

	statement.Exec() //Execute SQL statement
	log.Println("descriptions table created")

}

// where the measurement list comes from
var inputFile *string
var urlinputFile *string
var noMeasurement *bool
var sendRemoteServer *bool
var clientAuth *bool
var nogui *bool

// alternate way to specify dns server settings
var dnsFile *string

func main() {
	var err error

	inputFile = flag.String("fileinput", "", "specify the input measurement file")
	urlinputFile = flag.String("urlinput", "", "specify the input measurement file to download")
	dnsFile = flag.String("dnsinput", "", "specify the input dns caches to measure")
	noMeasurement = flag.Bool("nomeasurement", false, "do not perform measurements but start the web application")
	sendRemoteServer = flag.Bool("server", true, "send results to remote server")
	clientAuth = flag.Bool("clientauth", false, "use client auth for remote server")
	nogui = flag.Bool("nogui", false, "don't start the gui") //for containers and headless mode

	flag.Parse()

	//http.HandleFunc("/scrollbuffer", scrollHandler)
	http.HandleFunc("/viewall", viewAllHandler)
	http.HandleFunc("/viewunique", viewUniqueHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/help", helpHandler)
	//fileHandler := http.FileServer(http.Dir("inputs")) // Serve static files from  "inputs" directory
	//http.Handle("/in", fileHandler)
	http.HandleFunc("/", indexHandler)

	// Start the server in a goroutine
	go func() {
		port := ":8080"
		fmt.Printf("Server starting on port %s\n", port)
		log.Fatal(http.ListenAndServe(port, nil))
	}()

	//make sure the web server is up before continuing
	time.Sleep(2 * time.Second)

	if *inputFile != "" {
		fmt.Println("init - reading list from file")
		measurelist, err = readListFromFile(*inputFile)
	} else {
		//fmt.Println("init - reading list from web")
		//measurelist, err = readListFromWeb(*urlinputFile)

		//an initial list is packaged with binary to make deployment easier
		strbuf := string(malwareBytes)
		lines := strings.Split(strbuf, "\n")
		measurelist, err = processLines(lines)
	}

	if err != nil {
		fmt.Println("fatal - error reading measurement list from file|web")
		os.Exit(-1)
	}

	onExit := func() {
		now := time.Now()
		fmt.Println("Exit at", now.String())
	}

	go doUpdateProcess() //automatic code updates

	go doPreciseMeasurements()

	if *nogui == true {
		measure()
	} else {
		systray.Run(onReady, onExit)
	}
}

// default file to download for precise measurements
var precisionFileUrl string = "https://www.spydar.org/precise.txt"

func doPreciseMeasurements() {
	var preciseMeasurements []byte
	var err error

	ntpServer := "pool.ntp.org"

	dnsservers, err := getDNSServers()
	if err != nil {
		fmt.Println("error getting dns servers:", err)
		return
	}

	for {
		if measureEnabled == true {
			preciseMeasurements, err = downloadFileToMemory(precisionFileUrl)
			if err != nil {
				fmt.Println("error downloading preciseMeasurements:", err)
				time.Sleep(1 * time.Second)
				continue
			}

			mlist, err := measurement2List(string(preciseMeasurements))
			if err != nil {
				fmt.Println("error processing measurements:", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Get the current time from the NTP server
			// account for machines with wild time settings
			ntpTime, err := ntp.Time(ntpServer)
			if err != nil {
				log.Println("Failed to get time from NTP server: %v", err)
				time.Sleep(1 * time.Second)
				continue
			}

			machineUtcTime := time.Now().UTC()
			ntpUtcTime := ntpTime.UTC()
			timeDiff := ntpUtcTime.Sub(machineUtcTime) // Calculate the time difference

			processPreciseMeasurements(dnsservers, mlist, ntpUtcTime, timeDiff)

			preciseMeasurements = nil
			mlist = nil

			time.Sleep(60 * time.Second) //wait 60 seconds before next iteration
		}

		///important, don't remove.  prevents for loop from spinning too fast
		time.Sleep(1 * time.Second)
	}
}

// mlist == measurements list
func processPreciseMeasurements(dnsservers []dnsentry, mlist []precision, currentNtpTime time.Time, timeDiff time.Duration) {
	var timeResultReceived time.Time
	var answer *dns.Msg
	var err error

	//get the local machine id
	if uniqueId == "empty" {
		uniqueId = getMachineID()
	}

	if firstTime == true {
		firstTime = false
		fmt.Println("first time, setting machine id:", uniqueId)
		initCrypto()
	}

	//for all items in the measurement list
	for _, measEntry := range mlist {
		//for all configured dns caches
		for _, dnsserver := range dnsservers {
			t := time.Now()
			timeResultReceived, answer, err = do_measurement(dnsserver, uniqueId, measEntry, t, timeDiff)
			if err != nil {
				continue
			}

			timeBegin := strconv.Itoa(int(t.UTC().Unix()))
			timeEnd := strconv.Itoa(int(timeResultReceived.UTC().Unix()))
			log_remote(measEntry, answer, timeBegin, timeEnd, dnsserver.dnsserver, uniqueId)
		}
	}
}

func log_remote(measEntry precision, answer *dns.Msg, timeBegin string, timeEnd string, dnsserver string, measureid string) {

	fmt.Println("precision logging:", measEntry.domainname, "from", dnsserver, "at", timeBegin, ":", timeEnd)
	anslist := answer2String(answer)
	storeRemoteResult(timeBegin, measEntry.domainname, "A", dnsserver, anslist, measureid)
}

func do_measurement(dnsserver dnsentry, machineid string, entry precision, now time.Time, timeDiff time.Duration) (time.Time, *dns.Msg, error) {
	//add a period if it doesn't exist to make domain fully qualified
	if entry.domainname[len(entry.domainname)-1] != '.' {
		entry.domainname += "."
	}

	domainname := entry.domainname
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = false //this is important
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{domainname, dns.TypeA, dns.ClassINET}
	c := new(dns.Client)

	/*laddr := net.UDPAddr{ IP:   net.ParseIP("[::1]"), Port: 1234, Zone: "", } */

	c.Dialer = &net.Dialer{
		Timeout: 750 * time.Millisecond,
		//LocalAddr: &laddr,
	}

	in, _, err := c.Exchange(m1, dnsserver.dnsserver+":53")
	if err != nil {
		if verbose {
			fmt.Println("Exchange error 2:", err)
		}
		return time.Time{}, in, err
	}

	if len(in.Answer) > 0 {
		if verbose {
			fmt.Println("record exists:", entry.domainname, "in", dnsserver.dnsserver)
		}
		now = time.Now().UTC()
		returnTime := now.Add(timeDiff)
		return returnTime, in, nil
	} else {
		if verbose {
			fmt.Println("record does not exist:", entry.domainname, "in", dnsserver.dnsserver)
		}
		return time.Time{}, in, errors.New("no answer found")
	}
}

func measurement2List(measurements string) ([]precision, error) {
	var list []precision
	var unixtime int
	var domainname string
	var uniqueid string

	//process the lines
	lines := strings.Split(measurements, "\n")
	for _, line := range lines {
		ln := string(line)
		if len(ln) > 0 {
			if ln[0:1] == "#" {
				continue
			}

			/*
				//process the line
				//fmt.Println("DEBUG:", ln)
					parts := strings.Split(ln, ",")
						if len(parts) == 2 {
							unixtime, _ = strconv.Atoi(parts[0])
							domainname = parts[1]
							uniqueid = ""
						} else if len(parts) == 3 {
							unixtime, _ = strconv.Atoi(parts[0])
							domainname = parts[1]
							uniqueid = parts[2]
						} else {
							fmt.Println("error processing measurement line:", ln)
							return nil, errors.New("measurement line didn't have 2 or 3 elements")
						}
			*/

			unixtime = 0
			uniqueid = ""
			domainname = ln
			entry := precision{domainname, unixtime, uniqueid}

			list = append(list, entry)
		}
	}

	return list, nil

}

func doUpdateProcess() {
	var err error
	var attr os.ProcAttr
	//fileURL := "http://localhost:8000/update." + runtime.GOOS // Replace with the actual URL
	localFilePath := "update." + runtime.GOOS // Desired name for the local file.  the same on windows, mac, linux, etc

	prepend := ""
	if runtime.GOOS != "windows" {
		prepend = "./"
	}

	for {
		fmt.Println("update will happen in 24 hours")
		time.Sleep(60 * 60 * 24 * time.Second) //update once every 24 hours for the update

		os.WriteFile(localFilePath, updateBytes, 0755)
		fmt.Printf("Bytes written successfully to: %s\n", localFilePath)

		attr.Files = []*os.File{os.Stdin, os.Stdout, os.Stderr} // Inherit standard I/O from the parent process
		attr.Dir = ""                                           // Use the current working directory

		// Start the process
		fmt.Println("pre-exec:", prepend+localFilePath)
		_, err = os.StartProcess(prepend+localFilePath, os.Args[1:], &attr)
		if err != nil {
			fmt.Printf("Failed to start process: %v\n", err)
			continue
		}

		time.Sleep(3 * time.Second)

		fmt.Println("shutting down spdr")

		os.Exit(0)

	}
}

// downloadFileToMemory fetches the content from the given URL and returns it as a byte slice.
func downloadFileToMemory(url string) ([]byte, error) {
	// Perform the HTTP GET request. The default http.Client handles HTTPS automatically.
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to perform GET request: %w", err)
	}

	// Defer closing the response body. It is vital to close the body to prevent resource leaks.
	defer resp.Body.Close()

	// Check if the request was successful (HTTP status code 200 OK).
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d %s", resp.StatusCode, resp.Status)
	}

	// Read the entire response body into memory.
	// For very large files, this could cause memory issues.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

// downloadFile downloads a file from a given URL and saves it to the specified filepath.
func downloadFile(filepath string, url string) error {
	// 1. Make an HTTP GET request to the URL
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close() // Ensure the response body is closed

	// 2. Check for a successful HTTP status code
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status code: %s", resp.Status)
	}

	// 3. Create the local file to save the downloaded content
	out, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer out.Close() // Ensure the file is closed

	// 4. Copy the response body to the local file
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to copy data to file: %w", err)
	}

	return nil
}

func readListFromFile(inputFile string) ([]listentry, error) {
	fd, err := os.OpenFile(inputFile, os.O_RDONLY, 0)
	if err != nil {
		log.Println("FILE:", inputFile, err)
		return nil, err
	}
	defer fd.Close()

	buf, err := ioutil.ReadAll(fd)
	if err != nil {
		log.Println(err)
		return nil, err
	}

	strbuf := string(buf)
	lines := strings.Split(strbuf, "\n")

	return processLines(lines)
}

func readListFromWeb(url string) ([]listentry, error) {
	//some places that maintain url lists
	//fileUrl := "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt"
	//fileUrl := "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
	//fileUrl := "https://hole.cert.pl/domains/v2/domains.txt"
	fileUrl := url

	resp, err := http.Get(fileUrl)
	if err != nil {
		log.Fatalf("Error performing GET request: %v", err)
	}
	defer resp.Body.Close() // Ensure the response body is closed

	// Check if the HTTP status code indicates success
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Received non-OK HTTP status: %d %s", resp.StatusCode, resp.Status)
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("ReadAll of web site failed")
	}

	strbuf := string(buf)
	lines := strings.Split(strbuf, "\n")
	return processLines(lines)
}

func processLines(lines []string) ([]listentry, error) {
	var list []listentry

	for _, line := range lines {
		if len(line) > 0 && line[0:1] != "#" {
			split := strings.Split(line, ",")

			if len(split) < 4 {
				fmt.Println("didn't have array with 4 elements:", split, len(split))
				continue
			}

			descr := strings.Join(split[3:], "")

			list = append(list, listentry{split[1], split[0], descr})
		}
	}

	return list, nil
}

func addQuitItem() {
	mQuit := systray.AddMenuItem("Quit", "Quit the whole app")
	mQuit.Enable()
	go func() {
		<-mQuit.ClickedCh
		fmt.Println("Requesting quit")
		systray.Quit()
		fmt.Println("Finished quitting")
	}()
	systray.AddSeparator()
}

// openBrowser opens the specified URL in the default web browser.
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported operating system")
	}
	if err != nil {
		log.Printf("Error opening browser: %v", err)
	}
}

// the scroll text we hand to javascript
// show the last 10 database events
func scrollHandler(w http.ResponseWriter, req *http.Request) {
	db := sqliteDatabase

	row, err := db.Query("SELECT * FROM measurements ORDER BY id DESC LIMIT 10")
	if err != nil {
		log.Fatal(err)
	}
	defer row.Close()

	text := ""

	text = fmt.Sprintf("Recent Events;")
	for row.Next() { // Iterate and fetch the records from result cursor
		var id int
		var timestamp string
		var name string
		var domaintype string
		var dnsserver string
		var answers string

		row.Scan(&id, &timestamp, &name, &domaintype, &dnsserver, &answers)

		text += fmt.Sprintf("@%v %v;", dnsserver, name)
	}

	fmt.Fprintln(w, text)
}

func getdomain(name string) string {
	spl := strings.Split(name, ".")
	length := len(spl)
	if length < 2 {
		return "empty"
	}

	return spl[length-2] + "." + spl[length-1]
}

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

func geturlargs(url string) map[string]string {
	url = url[1:]

	parsedurl := strings.Split(url, "?")
	if len(parsedurl) == 1 {
		return nil
	}

	args := parsedurl[1]

	//fmt.Println("URLARGS:", args)

	slices := strings.Split(args, "&")

	argsmap := make(map[string]string)
	for _, slice := range slices {
		parsedurl2 := strings.Split(slice, "=")
		if len(parsedurl2) == 1 {
			return nil
		}

		if len(parsedurl2)%2 != 0 {
			return nil
		}

		for i, _ := range parsedurl {
			if i%2 == 0 {
				//fmt.Println("DEBUG:", parsedurl2[i], parsedurl2[i+1])
				argsmap[parsedurl2[i]] = parsedurl2[i+1]
			}
		}
	}

	return argsmap
}

func isAlphanumericOrPeriod(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-'
}

func isInputSane1(args map[string]string) bool {
	value, exists := args["name"]
	if exists {
		for _, char := range value {
			if isAlphanumericOrPeriod(char) == false {
				//fmt.Println(value, "char:", string(char))
				return false
			}
		}

		return true
	} else {
		return false
	}
}

func viewUniqueHandler(w http.ResponseWriter, req *http.Request) {
	var noArgs bool = false
	var row *sql.Rows
	var err error

	db := sqliteDatabase

	url := req.URL.String()
	if url == "" {
		return
	}

	urlargsmap := geturlargs(url)
	if urlargsmap == nil || len(urlargsmap) == 0 {
		noArgs = true
	}

	if noArgs == true {
		row, err = db.Query("SELECT distinct measurements.name,descriptions.description from measurements join descriptions on measurements.name = descriptions.name")
	} else {
		if isInputSane1(urlargsmap) == false {
			fmt.Fprintln(w, "INPUT IS NOT SANE")
			return
		}

		row, err = db.Query(fmt.Sprintf("SELECT distinct * from measurements join descriptions on measurements.name = descriptions.name where measurements.name='%s'", urlargsmap["name"]))
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
			name = fmt.Sprintf("<a href=http://localhost:8080/viewunique?name=%s>%s</a>", name, name)
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
	fmt.Fprintln(w, sidebar)

	fmt.Fprintln(w, "<h3> Welcome to SPYDAR DNS Measurement Tool</h3>")
	fmt.Fprintln(w, "<p>This tool measures DNS caches for domain resolution behavior.  Use the sidebar to navigate through the results.</p>")
	fmt.Fprintln(w, "<p>For help, click <a href=\"/help\">here</a>.</p>")

	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
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

	fmt.Fprintln(w, sidebar)

	/*
		//picture
		fmt.Fprintln(w, "<div class=iframe-container>")
		fmt.Fprintln(w, "<iframe class=my-iframe1 src=\"frame1.html\"></iframe>")
		fmt.Fprintln(w, "</div>")
	*/

	/*
		///javascript scroll window
		fmt.Fprintln(w, "<div class=iframe-container>")
		fmt.Fprintln(w, "<canvas class=fblogo id=myCanvas width=640 height=400></canvas>")
		fmt.Fprintln(w, "</div>")
	*/

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

/*
// where the measurement list comes from
var clientAuth *bool
var nogui *bool

// alternate way to specify dns server settings
var dnsFile *string
*/

func settingsHandler(w http.ResponseWriter, req *http.Request) {
	var dnsservers []dnsentry
	var err error
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
	fmt.Fprintln(w, sidebar)

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

func helpHandler(w http.ResponseWriter, req *http.Request) {

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
	fmt.Fprintln(w, sidebar)

	fmt.Fprintln(w, "<h3> Welcome to SPYDAR DNS Measurement Tool Help</h3>")
	fmt.Fprintln(w, "<p>This tool measures DNS caches for malware domain resolution behavior.  Use the sidebar to navigate through the results.</p>")
	fmt.Fprintln(w, "<p>More help will be coming later.</a>.</p>")

	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
}

func viewAllHandler(w http.ResponseWriter, req *http.Request) {
	var row *sql.Rows
	var err error
	var count int = 0

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
		rows += fmt.Sprintf("%v,%v,%v,%v,%v,%v,%v\n", id, timestamp, name, domaintype, dnsserver, description, answers)
		//fmt.Println(count, id, timestamp, name)
		count++
	}

	makeTableFullHtml(w, columnnames, rows)

}

//go:embed static/measure.png
var iconBytes []byte

//go:embed inputs/update.exe
var updateBytes []byte

//go:embed inputs/malphish.txt
var malwareBytes []byte

//go:embed rootCA.crt
var caCert []byte

func onReady() {
	systray.SetTemplateIcon(icon.Data, icon.Data)
	systray.SetTitle("Spydar")
	systray.SetTooltip("Spydar DNS Measurement Tool")

	addQuitItem()

	/*
		// Serve static files from a "static" directory (or adjust as needed)
		http.HandleFunc("/viewall", viewAllHandler)
		http.HandleFunc("/viewunique", viewUniqueHandler)
		http.HandleFunc("/scrollbuffer", scrollHandler)
		http.HandleFunc("/settings", settingsHandler)
		http.HandleFunc("/help", helpHandler)
		fileHandler := http.FileServer(http.Dir("./static"))
		http.Handle("/", fileHandler)

		// Start the server in a goroutine
		go func() {
			port := ":8080"
			fmt.Printf("Server starting on port %s\n", port)
			log.Fatal(http.ListenAndServe(port, nil))
		}()
	*/

	// We can manipulate the systray in other goroutines
	go func() {
		//var err error
		//systray.SetTemplateIcon(icon.Data, icon.Data)

		systray.SetTitle("Spydar")
		systray.SetTooltip("Spydar DNS Measurement Tool")
		systray.SetIcon(iconBytes)
		mEnabled := systray.AddMenuItemCheckbox("Enabled", "Enabled", true)
		systray.AddSeparator()
		mUpdate := systray.AddMenuItem("Update", "Update List")
		mStatus := systray.AddMenuItem("Status", "Get Program Status")
		mSettings := systray.AddMenuItem("Settings", "Get Program Settings")

		for {
			select {
			case <-mSettings.ClickedCh:
				fmt.Println("Settings...")
				openBrowser("http://localhost:8080/settings") // Assuming index.html is in the static directory
			case <-mStatus.ClickedCh:
				fmt.Println("Status...")
				openBrowser("http://localhost:8080/viewunique") // Assuming index.html is in the static directory
			case <-mUpdate.ClickedCh:
				fmt.Println("Doing nothing for now...")

				/*
					if *inputFile != "" {
						fmt.Println("update - reading list from file", *inputFile)
						measurelist, err = readListFromFile(*inputFile)
					} else {
						fmt.Println("update - reading list from web url", *urlinputFile)
						measurelist, err = readListFromWeb(*urlinputFile)
					}

					if err != nil {
						log.Fatalf("Update failure", err)
					}

					fmt.Println("list updated successfully")
				*/
			case <-mEnabled.ClickedCh:
				if mEnabled.Checked() {
					fmt.Println("Disabled")
					measureEnabled = false
					mEnabled.Uncheck()
					mEnabled.SetTitle("Disabled")
				} else {
					fmt.Println("Enabled")
					measureEnabled = true
					mEnabled.Check()
					mEnabled.SetTitle("Enabled")
					mEnabled.Enable()
				}
			}
		}
	}()

	if *noMeasurement == false {
		go measure()
	}
}

// make sure we can resolve www.google.com
func recursionDesired(dnsserver string) (bool, error) {
	domainname := "www.google.com."
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true //this is important
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{domainname, dns.TypeA, dns.ClassINET}
	c := new(dns.Client)

	c.Dialer = &net.Dialer{
		Timeout: 1000 * time.Millisecond,
	}

	in, _, err := c.Exchange(m1, dnsserver+":53")
	if err != nil {
		//fmt.Println("Exchange error 3:", err)
		return false, err
	}

	if len(in.Answer) > 0 {
		return true, nil
	} else {
		return false, nil
	}
}

// make sure we can't resolve www.mostexclusivewebsite.com
func recursionIgnored(dnsserver string) (bool, error) {
	domainname := "www.zsdagadsfafadfasdf.com."
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = false //this is important
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{domainname, dns.TypeA, dns.ClassINET}
	c := new(dns.Client)

	//connect to dns server and ask question
	/*laddr := net.UDPAddr{
		IP:   net.ParseIP("[::1]"),
		Port: 1234,
		Zone: "",
	}
	*/

	c.Dialer = &net.Dialer{
		Timeout: 5000 * time.Millisecond,
		//LocalAddr: &laddr,
	}

	in, _, err := c.Exchange(m1, dnsserver+":53")
	if err != nil {
		if verbose {
			fmt.Println("Exchange error 2:", err)
		}
		fmt.Printf("*")
		return false, err
	}

	if len(in.Answer) > 0 {
		return true, nil
	} else {
		return false, nil
	}
}

// asyncronous call-back for dns answers
func receiveanswers1() {

	for {
		select {
		case res := <-resultChan:
			if res.Err != nil {
				log.Printf("DNS query error: %v", res.Err)
			}
			//log.Printf("DNS response for domain: %v", res.Response)

			if len(res.Response.Answer) <= 0 {
				//fmt.Println("answering: @"+res.dnsserver, "no results on:", res.domainname)
				fmt.Printf(".")
			} else {
				//print results to html file
				//storeResults(res.dnsserver, res.domainname, res.domaintype, res.Response, time.Now())
				storeResults(res)

				//print results to console
				for x := 0; x < len(res.Response.Answer); x++ {
					answer := res.Response.Answer[x].String()
					fmt.Println("\n\t", answer)
				}
			}
		case <-quitChannel1:
			return
		}
	}
}

// asyncronous call-back for dns answers
func receiveanswers2() {
	for {
		select {
		case res2 := <-result2Chan:
			//fmt.Println("received:", result2Chan)
			alive := true
			if res2.Err != nil {
				log.Printf("error: DNS query for %v error: %v", res2.domainname, res2.Err)
				alive = false
			}

			fmt.Println("valid dns server: @", res2.dnsserver, res2.domainname)
			validatedserverlist = append(validatedserverlist, dnsentry{dnsserver: res2.dnsserver, isalive: alive})
			res2.wg.Done()

		case <-quitChannel2:
			return
		}

	}
}

func determineDnscacheHealth(dnsservers []dnsentry) {
	var wg sync.WaitGroup

	for _, dnsserver := range dnsservers {
		//connect to dns server and ask question
		domainname := "www.google.com."
		m1 := new(dns.Msg)
		m1.Id = dns.Id()
		m1.RecursionDesired = true
		m1.Question = make([]dns.Question, 1)
		m1.Question[0] = dns.Question{domainname, dns.TypeA, dns.ClassINET}
		c := new(dns.Client)
		wg.Add(1)
		go func(dnsserver string, wg *sync.WaitGroup) {
			c.Dialer = &net.Dialer{
				Timeout: 5000 * time.Millisecond,
			}

			in, rtt, err := c.Exchange(m1, dnsserver+":53")
			if err != nil {
				wg.Done()
				//fmt.Println("@"+dnsserver, "Exchange error 4:", err, "on:", domainname)
				return
			}

			fmt.Println("DNSSERVERS:", dnsserver)
			result2Chan <- DNSResult{dnsserver: dnsserver, domainname: domainname,
				domaintype: "A", Response: in, RTT: rtt, Err: err, wg: wg}
		}(dnsserver.dnsserver, &wg)
	}

	wg.Wait()
	//close(quitChannel2)
}

func checkDnscacheRecursionBit(dnslist []dnsentry) {

	///make sure the caches respect the recursion desired bit
	for i, dnsserver := range validatedserverlist { //dnsservers {
		b, err := recursionIgnored(dnsserver.dnsserver)
		if err != nil || b == true {
			fmt.Println("answering: @"+dnsserver.dnsserver, "recursion ignored or error")
			validatedserverlist[i].isalive = false
			continue
		}
		fmt.Println("answering: @"+dnsserver.dnsserver, "recursion desired was respected as expected")
	}
}

func measure() {
	var dnsservers []dnsentry
	var err error

	go receiveanswers1()
	go receiveanswers2()
	time.Sleep(2 * time.Second)

	for {

		if measureEnabled == false {
			fmt.Println("measurement currently disabled")
		} else {

			dnsservers = []dnsentry{}
			validatedserverlist = []dnsentry{}
			dnsservers, err = getDNSServers()
			if err != nil {
				fmt.Println("error getting dns server list")
				return
			}

			//determine which cache servers are alive and mark them as alive or dead
			determineDnscacheHealth(dnsservers)

			checkDnscacheRecursionBit(validatedserverlist)

			for _, entry := range measurelist {
				for _, dnsserver := range validatedserverlist { //dnsservers {
					//fmt.Println("server:", dnsserver.dnsserver)
					if dnsserver.isalive == false || strings.Contains(dnsserver.dnsserver, ":") { //if the dns server isn't alive or it's ipv6, don't query
						fmt.Println("@"+dnsserver.dnsserver, "is not alive")
						continue
					}

					domainname := entry.entry
					domaintype := entry.entrytype
					domaindescr := entry.entrydescr
					//fmt.Println("measuring:", domainname, "@", dnsserver.dnsserver)
					m1 := new(dns.Msg)
					m1.Id = dns.Id()
					m1.RecursionDesired = false
					m1.Question = make([]dns.Question, 1)

					if entry.entrytype == "A" {
						m1.Question[0] = dns.Question{domainname + ".", dns.TypeA, dns.ClassINET}
					} else if entry.entrytype == "NS" {
						m1.Question[0] = dns.Question{domainname + ".", dns.TypeNS, dns.ClassINET}
					} else {
						fmt.Println("Encountered unsupported record type of:", entry.entrytype)
						os.Exit(-1)
					}

					c := new(dns.Client)

					//connect to dns server and ask question
					go func(dnsserver string) {
						c.Dialer = &net.Dialer{
							Timeout: 5000 * time.Millisecond,
							//LocalAddr: &laddr,
						}

						in, rtt, err := c.Exchange(m1, dnsserver+":53")
						if err != nil {
							if verbose {
								fmt.Println("@"+dnsserver, "Exchange error 1:", err, "on:", domainname)
							}
							fmt.Printf("+")
							return
						}

						resultChan <- DNSResult{dnsserver: dnsserver, domainname: domainname,
							domaintype: domaintype, domaindescr: domaindescr, Response: in, RTT: rtt, Err: err}
					}(dnsserver.dnsserver)

					///check if measurement is still enabled
					if measureEnabled == false {
						break
					}

					//throttle queries a bit
					time.Sleep(10 * time.Millisecond)
				}
			}
		}

		fmt.Println("sleeping")
		time.Sleep(time.Second * 60 * 20) //wake every 20 minutes
		fmt.Println("awakening")
	}
}

/*
This function should store results in a database
*/
func storeResults(res DNSResult) {
	var dnsserver string
	var domainname string
	var domaintype string
	var domaindescr string
	var answer *dns.Msg
	var t time.Time = time.Now()

	dnsserver = res.dnsserver
	domainname = res.domainname
	domaintype = res.domaintype
	domaindescr = res.domaindescr
	answer = res.Response

	fmt.Println("@", dnsserver, " time:", t.UTC().Unix(), "domain:", domainname)

	insertRecord(sqliteDatabase, dnsserver, t, domainname, domaintype, domaindescr, answer)
}

var firstTime bool = true
var httpclient *http.Client
var transport *http.Transport
var cert tls.Certificate
var certerr error
var uniqueId string = "empty"

func initCrypto() {
	//TODO make this cmdline configurable
	client_pub_path := "keys/keys/client.crt"
	client_pri_path := "keys/keys/client.key"
	//root_pub_path := "keys/keys/rootCA.crt"
	home, _ := os.UserHomeDir()
	client_pub_key := home + string(os.PathSeparator) + client_pub_path
	client_pri_key := home + string(os.PathSeparator) + client_pri_path
	/*root_pub_key := home + string(os.PathSeparator) + root_pub_path
	caCert, err := os.ReadFile(root_pub_key)
	if err != nil {
		log.Fatalf("Error reading CA file: %v", err)
	}
	*/

	// Create a new CertPool and add the CA certificate to it
	caCertPool, _ := x509.SystemCertPool()
	if caCertPool == nil {
		caCertPool = x509.NewCertPool()
	}

	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		log.Fatal("Failed to append CA certificate")
	}

	if *clientAuth == true {
		// Load the client certificate and private key
		clientcert, certerr := tls.LoadX509KeyPair(client_pub_key, client_pri_key)
		if certerr != nil {
			log.Fatalln(certerr.Error())
		}

		// Setup TLS configuration
		tlsConfig := &tls.Config{
			RootCAs:            caCertPool,
			Certificates:       []tls.Certificate{clientcert},
			InsecureSkipVerify: false, // In production, you'd usually keep the default (false) to verify the server
		}

		// Create a custom transport and client
		transport = &http.Transport{TLSClientConfig: tlsConfig}
		httpclient = &http.Client{Transport: transport}
	} else {
		// Setup TLS server-only configuration
		tlsConfig := &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: false, // In production, you'd usually keep the default (false) to verify the server
		}
		transport = &http.Transport{TLSClientConfig: tlsConfig}
		httpclient = &http.Client{Transport: transport}
	}
}

func answer2String(answer *dns.Msg) string {
	var anslist []string
	//print results to console
	for x := 0; x < len(answer.Answer); x++ {
		answer := answer.Answer[x].String()

		//fmt.Println("\n\nANSWER:", answer, "\n\n")

		answersplit := strings.Split(answer, "\t")

		appendme := answersplit[4]
		//appendme := strings.Join(answersplit, ",")

		///remove . from end if it exists
		if strings.Contains(appendme[len(appendme)-1:], ".") {
			appendme = appendme[0 : len(appendme)-1]
		}

		anslist = append(anslist, appendme)

	}

	answers := strings.Join(anslist, ",")

	return answers

}

func insertRecord(db *sql.DB, dnsserver string, t time.Time, domainname string, domaintype string, domaindescr string, answer *dns.Msg) {
	var answers string

	answers = answer2String(answer)

	log.Println("Inserting answer measurements:", answers)

	///insert measurement record into sqlite database
	insertSQL := `INSERT INTO measurements(time, name, domaintype, dnsserver, answers) VALUES (?, ?, ?, ?, ?)`
	statement, err := db.Prepare(insertSQL) // Prepare statement.
	if err != nil {
		log.Fatalln(err.Error())
	}

	timestr := strconv.Itoa(int(t.UTC().Unix()))

	//actually insert
	_, err = statement.Exec(timestr, domainname, domaintype, dnsserver, answers)
	if err != nil {
		log.Fatalln(err.Error())
	}

	///insert domaindescr and domain name into description table, if it's already there, do nothing
	insertSQL = `INSERT INTO descriptions(name, description) VALUES (?, ?) ON CONFLICT(name) DO NOTHING`
	statement, err = db.Prepare(insertSQL)
	if err != nil {
		log.Fatalln(err.Error())
	}

	_, err = statement.Exec(domainname, domaindescr)
	if err != nil {
		log.Fatalln(err.Error())
	}

	//initialize the client certificate crypto the first time through this loop if sending messages to the remote server is enabled
	if firstTime && *sendRemoteServer {
		firstTime = false

		initCrypto()

		uniqueId = getMachineID()
		if err != nil {
			log.Fatalf("Error getting machine UUID: %v", err)
		}

		storeRemoteResult(timestr, domainname, domaintype, dnsserver, answers, uniqueId)
	} else {
		storeRemoteResult(timestr, domainname, domaintype, dnsserver, answers, uniqueId)
	}

}

// /get a unique machine id that will always be the same for the machine
func getMachineID() string {
	switch runtime.GOOS {
	case "linux":
		// Standard machine-id path for most distros
		data, err := os.ReadFile("/etc/machine-id")
		if err != nil {
			return "default-linux-id"
		}
		return strings.TrimSpace(string(data))

	case "windows":
		// Query the registry for the MachineGuid
		cmd := exec.Command("reg", "query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid")
		out, err := cmd.Output()
		if err != nil {
			return "default-windows-id"
		}
		// Extract the GUID string from the output
		parts := strings.Fields(string(out))
		return parts[len(parts)-1]

	case "darwin":
		// Query I/O Kit for the Platform UUID
		cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		out, err := cmd.Output()
		if err != nil {
			return "default-mac-id"
		}
		// Logic to find the UUID string within the output
		for _, line := range strings.Split(string(out), "\n") {
			if strings.Contains(line, "IOPlatformUUID") {
				parts := strings.Split(line, "\"")
				if len(parts) > 3 {
					return parts[3]
				}
			}
		}
	}
	return "fallback-id"
}

func storeRemoteResult(timestr string, domainname string, domaintype string, dnsserver string, answers string, measureid string) {

	if httpclient == nil {
		return
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		fmt.Println("url.Parse error:", err)
		return
	}

	q := u.Query()
	q.Set("time", timestr)
	q.Set("name", domainname)
	q.Set("domaintype", domaintype)
	q.Set("dnsserver", dnsserver)
	q.Set("answers", answers)
	q.Set("uniqueid", measureid)
	u.RawQuery = q.Encode()

	// Execute the request
	// fmt.Println("Sending data to remote server:", u.String())
	resp, err := httpclient.Get(u.String())
	if err != nil {
		fmt.Println("httpclient.Get error:", err)
		return
	}
	defer resp.Body.Close()

	// 6. Read the response
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("io.ReadAll error:", err)
		return
	}

	//return string(body), nil
}

func parseDNSFile(dnsdata string) ([]dnsentry, error) {
	lines := strings.Split(dnsdata, "\n")

	var dnslist []dnsentry = []dnsentry{}

	for _, line := range lines {
		spl := strings.Split(line, " ")
		if spl[0] != "nameserver" {
			continue
		}

		ip := spl[1]

		dnslist = append(dnslist, dnsentry{dnsserver: ip, isalive: true})
	}

	return dnslist, nil

}

func getDNSServers() ([]dnsentry, error) {
	var err error
	var list []dnsentry

	if *dnsFile != "" {
		log.Println("Reading DNS from file:", *dnsFile)
		buf, err := os.ReadFile(*dnsFile)
		if err != nil {
			fmt.Println("read error on ", *dnsFile)
			return nil, errors.New("read error on file")
		}

		list, err = parseDNSFile(string(buf))

	} else {
		log.Println("Reading DNS from OS settings:", *dnsFile)
		switch runtime.GOOS {
		case "linux":
			list, err = getUnixDNSServers()
		case "windows":
			list, err = getWindowsDNSServers()
		case "darwin":
			list, err = getUnixDNSServers()
		default:
			err := fmt.Errorf("unsupported operating system")
			return nil, err
		}

	}

	if len(list) == 0 {
		fmt.Println("fatal - parseDNSFile returned zero dns servers, expecting at least one value")
		os.Exit(-1)
	}

	return list, err
}

func getUnixDNSServers() ([]dnsentry, error) {
	//file, err := os.Open("inputs/resolv.conf")
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("could not open inputs/resolv.conf: %w", err)
	}
	defer file.Close()

	var servers []dnsentry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				servers = append(servers, dnsentry{parts[1], true})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading inputs/resolv.conf: %w", err)
	}

	return servers, nil
}

func getWindowsDNSServers() ([]dnsentry, error) {
	cmd := exec.Command("ipconfig", "/all")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("could not execute ipconfig: %w", err)
	}

	var servers []dnsentry
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "DNS Servers") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				server := strings.TrimSpace(parts[1])
				// Clean up and handle potential extra servers on subsequent lines
				if server != "" {
					servers = append(servers, dnsentry{server, true})
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning ipconfig output: %w", err)
	}

	return servers, nil
}
