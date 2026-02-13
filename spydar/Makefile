FILELIST := spydar.windows spydar.linux 
FILELIST2 := spydar.windows spydar.linux spydar.darwin 
UNIXFLAGS := -ldflags "-s -w"
WINFLAGS  := -ldflags "-s -w -H windowsgui"
OS:=$(shell uname)

all: spydar

spydar:
	cp inputs/update.windows inputs/update.exe
	rsrc -ico windows.ico -arch=amd64
	CGO_ENABLED=1 GOARCH=amd64 CC=x86_64-w64-mingw32-gcc GOOS=windows go build $(WINFLAGS) -o spydar.windows
	cp inputs/update.linux inputs/update.exe
	GOOS=linux   go build $(UNIXFLAGS) -o spydar.linux

ifeq ($(OS), Darwin)
	echo "building on macos"
	cp inputs/update.darwin inputs/update.exe
	GOOS=darwin  go build $(UNIXFLAGS) -o spydar.darwin
	cp $(FILELIST2) inputs/
else
	cp $(FILELIST) inputs/
endif

	cp inputs/spydar.windows inputs/spydar.exe


clean:
	rm -rf spydar.windows spydar.linux spydar.darwin update.linux update.windows
	rm -rf inputs/spydar.* inputs/update.*
	rm -f *.syso
