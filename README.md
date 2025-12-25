![Spydar](spdr/static/spydar.jpg)

# Summary
The Spydar program (radar detection of spyware) measures dns records in dns caches by setting the recursion desired (RD) bit to zero in dns requests. 
This can be used to find malware domains that are found by periodically measuring caches.  It has a web interface for viewing the results of 
its measurements. This program is under heavy construction.

This program functions as a system tray application that starts a web server on localhost for viewing the program's output.
I recommend you start it in the foreground initially so you can see when it finds dns records you are looking for.  

This program reads your platform's dns server settings from resolv.conf or ipconfig /all.  You can change the dns cache server you're measuring 
by updating /etc/resolv.conf or using the -dnsinput <file> option on spydar.  By default, it uses the DNS servers in /etc/resolv.conf or windows settings
for measurement.  This program is not IPv6 compatible at the present time (future work).  It will skip over IPv6 dns caches.  All DNS names in 'malphish.txt'
that are found in the cache are logged to sqlite-database.db in the directory where you started spydar.

It can also update itself to add new features later.  This feature is not currently enabled.

# Compile
To compile this program you need a modern Linux computer with at least:<br>
go version go1.24.9 linux/amd64
<br><br>

`sudo apt install golang-go build-essentials`
<br><br>

`make` <br>
<br>
`sudo make install` <br>
<br>
If on Linux run:<br>
`spdr.linux`
<br>
<br>

# Usage
When the program starts, there will be a icon that appears in your system tray.  It has a small spider icon. Click this icon and choose 'Status'.  This will pull up
your default web browser and you will be able to click through the application to learn about the web sites in the measurement list. 

The spydar application (spdr.linux or spdr.windows) has a -help option.  You can use this option to override default dns settings and web site lists.

# Suggestions
Suggestions for improvement are welcome.

