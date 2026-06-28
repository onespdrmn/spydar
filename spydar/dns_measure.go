package main

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beevik/ntp"
	"github.com/miekg/dns"
)

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
	storeRemoteResult(timeBegin, measEntry.domainname, "A", dnsserver, anslist, measureid, 1)
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

		storeRemoteResult(timestr, domainname, domaintype, dnsserver, answers, uniqueId, 0)
	} else {
		storeRemoteResult(timestr, domainname, domaintype, dnsserver, answers, uniqueId, 0)
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
		//fmt.Println("fatal - parseDNSFile returned zero dns servers, expecting at least one value")
		return nil, errors.New("no dns servers found")
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
