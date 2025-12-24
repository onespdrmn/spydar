FILELIST := spdr.windows spdr.linux 
FILELIST2 := spdr.windows spdr.linux spdr.darwin 
FLAGS := -ldflags "-s -w"
OS:=$(shell uname)

all: spdr

spdr:
	cp inputs/update.windows inputs/update.exe
	GOOS=windows go build $(FLAGS) -o spdr.windows
	cp inputs/update.linux inputs/update.exe
	GOOS=linux   go build $(FLAGS) -o spdr.linux

ifeq ($(OS), Darwin)
	echo "you are on macos"
	cp inputs/update.darwin inputs/update.exe
	GOOS=darwin  go build -o spdr.darwin
	cp $(FILELIST) inputs/
else
	cp $(FILELIST) inputs/
endif


clean:
	rm -rf spdr.windows spdr.linux spdr.darwin update.linux update.windows
	rm -rf inputs/spdr.* inputs/update.*
