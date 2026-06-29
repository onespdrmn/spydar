#!/bin/sh

sudo apt update

#go compiler, build essentials, nsis=nullsoft installer tools, mingw-w64=compiler for windows, clang, llvm
sudo apt install golang-go build-essential nsis mingw-w64 clang llvm

#tool needed for making rsrc sections, used for embedding the spydar icon
go install github.com/akavel/rsrc@latest

#ebpf tools
sudo apt install bpftool libbpf-dev
#go get -tool github.com/cilium/ebpf/cmd/bpf2go

echo "export PATH=$PATH:$HOME/go/bin/" >> $HOME/.bash_aliases
#echo "export PATH=$PATH:$HOME/go/bin/:/home/kali/go/pkg/mod/github.com/cilium/ebpf@v0.22.0/cmd/" >> $HOME/.bash_aliases

. $HOME/.bash_aliases


