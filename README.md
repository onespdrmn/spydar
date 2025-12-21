![Spydar](spdr/static/spydar.jpg)

# Summary
The Spydar program measures dns records in dns caches by setting the RD bit to zero. It has a web interface for viewing the results.
It is a hobby project and is currently Alpha/Beta quality. 

This program functions as a system tray application that starts a web server on localhost for viewing the program's output.
I recommend you start it in the foreground initially so you can see when it finds dns records you are looking for.  

It can also update itself to add new features later.  This feature is not currently enabled.

This program reads your platform's dns server settings from resolv.conf or ipconfig /all.  You can change the dns cache server you're measuring 
by updating /etc/resolv.conf or using the -dnsinput <file> option on spydar.  By default, it uses the DNS servers in /etc/resolv.conf or windows settings
for measurement.  This program is not IPv6 compatible at the present time (future work).  It will skip over IPv6 dns caches.

# Compile
To compile this program you need:<br>
go version go1.24.9 linux/amd64
<br><br>
If you have a modern Golang installed:<br>
`make` <br>
<br>
Then:<br>
`cd spdr/inputs` <br>
`python3 -m http.server &` <br>

If on Linux run:<br>
`./spdr.linux`<br>

If on Windows run:<br>
`./spdr.windows`<br>
<br>
# Usage
When the program starts, there will be a icon that appears in your system tray.  It has a small spider icon. Click this icon and choose 'Status'.  This will pull up
your default web browser and you will be able to click through the application to learn about the web sites in the measurement list. 

The spydar application (spdr.linux or spdr.windows) has a -help option.  You can use this option to override default dns settings and web site lists.

# Suggestions
Suggestions for improvement are welcome.

