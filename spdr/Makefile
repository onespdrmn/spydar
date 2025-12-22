FILELIST := spdr.windows spdr.linux #spdr.freebsd spdr.netbsd spdr.openbsd spdr.dragonfly
FLAGS := -ldflags "-s -w"

all: spdr

spdr:
	cp inputs/update.windows inputs/update.exe
	GOOS=windows go build $(FLAGS) -o spdr.windows

	cp inputs/update.linux inputs/update.exe
	GOOS=linux   go build $(FLAGS) -o spdr.linux

	#cp inputs/update.darwin inputs/update.exe
	#GOOS=darwin  go build -o spdr.darwin

	#cp inputs/update.freebsd inputs/update.exe
	#GOOS=freebsd go build -o spdr.freebsd

	#cp inputs/update.netbsd inputs/update.exe
	#GOOS=netbsd go build -o spdr.netbsd

	#cp inputs/update.openbsd inputs/update.exe
	#GOOS=openbsd go build -o spdr.openbsd

	#cp inputs/update.dragonfly inputs/update.exe
	#GOOS=dragonfly go build -o spdr.dragonfly

	cp $(FILELIST) inputs/

clean:
	rm -rf spdr.windows spdr.linux spdr.darwin update.linux update.windows
	rm -rf inputs/spdr.* inputs/update.*
