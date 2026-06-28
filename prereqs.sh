#!/bin/sh

sudo apt update
sudo apt install golang-go build-essential nsis mingw-w64
go install github.com/akavel/rsrc@latest

echo "export PATH=$PATH:$HOME/go/bin/" >> $HOME/.bash_aliases

. $HOME/.bash_aliases


