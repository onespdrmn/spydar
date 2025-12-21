package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"unicode"
)

func usage() {
	fmt.Println(os.Args[0], "has these options:")
	fmt.Println("\tcache2input")
	fmt.Println("\tmalware2input")
	fmt.Println("\tmalphish2input")
}

func IsIPAddress(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil
}

func ContainsNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

func malphish2input(filedata string) {
	lines := strings.Split(filedata, "\n")
	count := 0

	for _, line := range lines {
		//skip the first line
		if count == 0 {
			count++
			continue
		}

		//skip empty lines
		if line == "" {
			continue
		}

		args := strings.Split(line, ",")
		//fmt.Println(len(args))
		//fmt.Println(line)
		if len(args) != 2 {
			continue
		}

		if strings.Contains(args[1], "malware") { //|| strings.Contains(args[1], "phishing") {
			spl := strings.ReplaceAll(args[0], "http://", "")
			spl = strings.ReplaceAll(spl, "https://", "")

			output := ""
			spl2 := strings.Split(spl, "/")

			if len(spl2) > 1 {
				output = spl2[0]
			} else {
				output = spl
			}

			if strings.Contains(output, ":") == true {
				continue
			}

			if IsIPAddress(output) == true || ContainsNonASCII(output) {
				continue
			}

			fmt.Println(output)
		}
	}
}

func cache2input(filedata string) {
	lines := strings.Split(filedata, "\n")
	count := 0
	for _, line := range lines {
		//skip the first line
		if count == 0 {
			count++
			continue
		}

		//skip empty lines
		if line == "" {
			continue
		}

		args := strings.Split(line, ",")
		if args[0] != "" {
			fmt.Println("nameserver", args[0])
		}
	}
}

func malware2input(filedata string) {
	lines := strings.Split(filedata, "\n")
	for _, line := range lines {
		numperiods := strings.Split(line, ".")
		if line == "" || len(numperiods) == 0 {
			continue
		}

		if len(numperiods)-1 == 1 {
			fmt.Printf("NS ")
		} else {
			fmt.Printf("A ")
		}

		printentry(numperiods)
	}
}

func printentry(numperiods []string) {
	counter := 0
	for _, entry := range numperiods {
		if counter < len(numperiods)-1 {
			fmt.Printf(entry + ".")
		} else {
			fmt.Printf(entry)
		}
		counter++
	}
	fmt.Printf("\n")
}

func main() {

	args := os.Args

	if len(args) < 2 {
		usage()
		os.Exit(-1)
	}

	filedata, err := ioutil.ReadFile(os.Args[2])
	if err != nil {
		fmt.Println("file read error:", os.Args[2])
		os.Exit(-1)
	}

	if os.Args[1] == "cache2input" {
		cache2input(string(filedata))
	} else if os.Args[1] == "malware2input" {
		malware2input(string(filedata))
	} else if os.Args[1] == "malphish2input" {
		malphish2input(string(filedata))
	} else {
		usage()
		os.Exit(-1)
	}
}
