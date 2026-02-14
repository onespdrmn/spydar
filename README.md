![Spydar](spydar/static/spydar.jpg)

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

It has support for updating itself to add new features.  This feature is currently disabled.

# Packages required to compile
To compile this program you need a modern Linux computer with at least:<br>
go version go1.24.9 linux/amd64<br><br>
`sudo apt update` <br>
`sudo apt install golang-go build-essential nsis mingw-w64` <br>
`go install github.com/akavel/rsrc@latest` <br>
`export PATH=$PATH:$HOME/go/bin/`<br>

<br>

# Compile instructions
`make` 
<br><br>
`sudo make install` 
<br><br>
If on Linux run:
<br>
`spydar.linux`
<br>
If on Windows run: <br>
`mv spydar/spydar.windows spydar.exe`<br>
`spydar.exe`
<br>
<br>

# Usage
When the program starts, there will be a icon that appears in your system tray.  It has a small spider icon. Click this icon and choose 'Status'.  This will pull up
your default web browser and you will be able to click through the application to learn about the web sites in the measurement list. 

The spydar application (spydar.linux or spydar.windows) has a -help option.  You can use this option to override default dns settings and web site lists.

For spydar.windows to work, rename spydar.windows to spydar.exe or use the nsis installer.

# Commands to clean all built objects 
sudo make debclean #clean out deb build files<br>
make clean         #clean out build files<br>
<br>

# Packages needed to build debian, rpm, and nsis packages (tested on Kali Linux)
`sudo dpkg --add-architecture i386 && sudo apt-get update` <br>
`sudo apt-get install wine32:i386 ` <br>
`sudo apt install dpkg-dev dh-make fakeroot devscripts rpm rpm-build` <br>
<br>

# Suggestions
Suggestions for improvement are welcome. <br>


