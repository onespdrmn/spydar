package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"
)

func main() {
	url := "http://127.0.0.1:8000/spdr." + runtime.GOOS
	prepend := ""

	if runtime.GOOS != "windows" {
		prepend = "./"
	}

	var exename string = "spdr."
	exename = prepend + exename + runtime.GOOS

	time.Sleep(4 * time.Second)

	///download the new version
	err := downloadFile(exename+".new", url)
	if err != nil {
		fmt.Println("download update failed:", url)
		return
	}

	os.Remove(exename)
	fmt.Println("removed:", exename)

	os.Rename(exename+".new", exename)
	fmt.Println("renamed:", exename+".new", exename)

	if runtime.GOOS != "windows" {
		err = os.Chmod(exename, 0755)
		if err != nil {
			fmt.Printf("Error chmod file: %v\n", err)
			return
		}
	}

	//execute the program with the same args it had when it was first started
	var attr os.ProcAttr
	attr.Files = []*os.File{os.Stdin, os.Stdout, os.Stderr} // Inherit standard I/O from the parent process
	attr.Dir = ""                                           // Use the current working directory

	// Start the process
	_, err = os.StartProcess(exename, os.Args[1:], &attr)
	if err != nil {
		fmt.Printf("Failed to start process: %v\n", err)
		return
	}

	return

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
