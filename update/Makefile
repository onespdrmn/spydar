FILELIST := update.windows update.linux #update.freebsd update.netbsd update.openbsd update.dragonfly update.darwin 
FLAGS := -ldflags "-s -w"

all: update

update:
	GOOS=windows    go build $(FLAGS) -o update.windows
	GOOS=linux      go build $(FLAGS) -o update.linux
	#GOOS=freebsd    go build -o update.freebsd
	#GOOS=netbsd     go build -o update.netbsd
	#GOOS=openbsd    go build -o update.openbsd
	#GOOS=dragonfly  go build -o update.dragonfly
	#GOOS=darwin     go build -o update.darwin
	cp $(FILELIST) ../spdr/inputs/

clean:
	rm -f $(FILELIST)
