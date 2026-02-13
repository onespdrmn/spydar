FLAGS := -ldflags "-s -w"

all: server

server:
	GOOS=linux go build $(FLAGS) -o spydar-server.linux

clean:
	rm -f spydar-server.linux
