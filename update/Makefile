FLAGS := -ldflags "-s -w"
OS := $(shell uname)

FILELIST := update.windows update.linux 
FILELIST2 := update.windows update.linux update.darwin 

all: update

update:
	GOOS=windows    go build $(FLAGS) -o update.windows
	GOOS=linux      go build $(FLAGS) -o update.linux
ifeq ($(OS), Darwin)
	echo "You are on macos"
	GOOS=darwin     go build $(FLAGS) -o update.darwin
	cp $(FILELIST2) ../spdr/inputs/
else
	cp $(FILELIST) ../spdr/inputs/
endif


clean:
	rm -f $(FILELIST)
