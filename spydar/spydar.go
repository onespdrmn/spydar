package main

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
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
	_ "github.com/mattn/go-sqlite3" // Import the driver
	"github.com/miekg/dns"
)

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
var outfd *os.File

var measurelist []listentry = []listentry{}
var validatedmeasurelist []listentry = []listentry{}
var validatedserverlist []dnsentry = []dnsentry{}
var targetURL string = "https://data.spydar.org/input"
var databaseFile string = "./sqlite-database.db"
var Webnonce string = ""

// do any initialization here
func initdb() {
	var err error
	var fileCreated bool = false
	log.Println("Creating:", databaseFile)

	if runtime.GOOS == "windows" {
		databasePath := os.Getenv("PROGRAMDATA")
		os.MkdirAll(databasePath+"\\spydar", 0755)
		databasePath = databasePath + "\\spydar\\"
		databaseFile = databasePath + databaseFile
	}

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

	sqliteDatabase, _ = sql.Open("sqlite3", databaseFile) // Open the created SQLite File

	if fileCreated {
		createTables(sqliteDatabase) // Create Database Tables
	}

	// Set the maximum number of open connections to 1
	sqliteDatabase.SetMaxOpenConns(1)

	// read in webnonce from database
	rows, err := sqliteDatabase.Query("SELECT webnonce FROM appsecurity")
	if err != nil {
		log.Fatal(err.Error())
	}
	defer rows.Close()

	///use /etc/machine-id or equivalent to get a unique machine id for this machine

	var webnonce string
	for rows.Next() {
		err = rows.Scan(&webnonce)
		if err != nil {
			log.Fatal(err.Error())
		}

		Webnonce = webnonce
		break
	}

}

func createTable_measurements(db *sql.DB) {
	createTableSQL := `CREATE TABLE measurements (
		"id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,		
		"time" TEXT,
		"name" TEXT,
		"domaintype" TEXT, 
		"dnsserver" TEXT,
		"answers" TEXT
	  );`

	log.Println("Create domain measurements table...")
	statement, err := db.Prepare(createTableSQL) // Prepare SQL Statement
	if err != nil {
		log.Fatal(err.Error())
	}
	statement.Exec() // Execute SQL Statements
	log.Println("measurements table created")
}

func createTable_security(db *sql.DB) {
	//var webnonce [8]byte
	var webnonce string

	log.Println("Creating appsecurity table.")
	//createTableSQL := `CREATE TABLE security (
	//	"nonce" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
	//);`
	createTableSQL := `CREATE TABLE appsecurity (
				"webnonce" TEXT
    );`

	statement, err := db.Prepare(createTableSQL)
	if err != nil {
		log.Fatal(err.Error())
	}

	statement.Exec() //Execute SQL statement
	log.Println("appsecurity table created")

	///get a random nonce for security and store it in the database
	/*	_, err = rand.Read(webnonce[:])
		if err != nil {
			log.Fatal(err.Error())
		}
	*/
	webnonce = getMachineID() //get a unique machine id for this machine

	value := binary.BigEndian.Uint64([]byte(webnonce[:]))
	webnonce_str := fmt.Sprintf("%016x", value)

	statement, err = db.Prepare("INSERT INTO appsecurity (webnonce) VALUES (?)")
	if err != nil {
		log.Fatal(err.Error())
	}

	_, err = statement.Exec(webnonce_str)
	if err != nil {
		log.Fatal(err.Error())
	}

}

func createTable_descriptions(db *sql.DB) {
	log.Println("Creating domain descriptions table...")

	createTableSQL := `CREATE TABLE descriptions (
				"name" TEXT NOT NULL UNIQUE,
				"description" TEXT NOT NULL
				);`

	statement, err := db.Prepare(createTableSQL)
	if err != nil {
		log.Fatal(err.Error())
	}

	statement.Exec() //Execute SQL statement
	log.Println("Domain descriptions table created")

}

func createTables(db *sql.DB) {
	//////////////////////////////////////////////////////////////
	///this is the table for the measurement results
	createTable_measurements(db)

	//////////////////////////////////////////////////////////////
	///this is the table for spydar_security
	createTable_security(db)

	//////////////////////////////////////////////////////////////
	///this is the table for the domain descriptions
	createTable_descriptions(db)

}

// where the measurement list comes from
var inputFile *string
var urlinputFile *string
var noMeasurement *bool
var sendRemoteServer *bool
var clientAuth *bool
var nogui *bool
var serverurl *string
var dbfile *string
var update *bool

// alternate way to specify dns server settings
var dnsFile *string

func main() {
	var err error

	inputFile = flag.String("fileinput", "", "specify the input measurement file (defaults to embedded list)")
	urlinputFile = flag.String("urlinput", "", "specify the input measurement file to download (defaults to embedded list)")
	dnsFile = flag.String("dnsinput", "", "provide file name of input dns caches to measure (defaults to /etc/resolve.conf or system equivalent)")
	noMeasurement = flag.Bool("nomeasurement", false, "do not perform measurements but start the web application")
	sendRemoteServer = flag.Bool("server", true, "send results to remote server")
	clientAuth = flag.Bool("clientauth", false, "use client auth for remote server (experimental)")
	nogui = flag.Bool("nogui", false, "don't start the gui") //for containers and headless mode
	serverurl = flag.String("serverurl", "https://data.spydar.org", "remote server url")
	dbfile = flag.String("dbfile", "./sqlite-database.db", "sqlite database file location")
	update = flag.Bool("update", true, "turn on/off automatic updates")

	flag.Parse()

	if *serverurl != "" {
		targetURL = *serverurl + "/input"
	}

	if *dbfile != "" {
		databaseFile = *dbfile
	}

	initdb() //initialize the database

	if Webnonce == "" {
		panic("webnonce is empty, something went wrong with database initialization")
	}

	http.HandleFunc("/viewall", viewAllHandler)
	http.HandleFunc("/viewunique", viewUniqueHandler)
	http.HandleFunc("/settings", settingsHandler)
	http.HandleFunc("/help", helpHandler)
	http.HandleFunc("/", indexHandler)
	//fileHandler := http.FileServer(http.Dir("inputs")) // Serve static files from  "inputs" directory
	//http.Handle("/in", fileHandler)

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

	if *update == false {
		fmt.Println("automatic updates disabled")
	} else {
		//fmt.Println("automatic updates enabled")
		//go doUpdateProcess() //automatic code updates
	}

	//go doPreciseMeasurements()

	if *nogui == true {
		measure()
	} else {
		systray.Run(onReady, onExit)
	}
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

	// We can manipulate the systray in other goroutines
	go func() {
		//var err error
		//systray.SetTemplateIcon(icon.Data, icon.Data)

		systray.SetTitle("Spydar")
		systray.SetTooltip("Spydar DNS Measurement Tool")
		systray.SetIcon(iconBytes)
		mEnabled := systray.AddMenuItemCheckbox("Enabled", "Enabled", true)
		systray.AddSeparator()
		//mUpdate := systray.AddMenuItem("Update", "Update List")
		mStatus := systray.AddMenuItem("Status", "Get Program Status")
		mSettings := systray.AddMenuItem("Settings", "Get Program Settings")

		for {
			select {
			case <-mSettings.ClickedCh:
				fmt.Println("Settings...")
				openBrowser("http://localhost:8080/settings?nonce=" + Webnonce) // Assuming index.html is in the static directory
			case <-mStatus.ClickedCh:
				fmt.Println("Status...")
				openBrowser("http://localhost:8080/viewunique?nonce=" + Webnonce) // Assuming index.html is in the static directory
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

func storeRemoteResult(timestr string, domainname string, domaintype string, dnsserver string, answers string, measureid string, messagetype int) {

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
	q.Set("messagetype", strconv.Itoa(messagetype))
	u.RawQuery = q.Encode()

	// Execute the request
	// fmt.Println("Sending data to remote server:", u.String())
	resp, err := httpclient.Get(u.String())
	if err != nil {
		initCrypto()
		fmt.Println("httpclient.Get error:", err)
		return
	}
	defer resp.Body.Close()

	// 6. Read the response
	_, err = io.ReadAll(resp.Body)
	if err != nil {
		initCrypto()
		fmt.Println("io.ReadAll error:", err)
		return
	}

	//return string(body), nil
}
