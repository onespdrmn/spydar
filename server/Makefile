FLAGS := -ldflags "-s -w"

all: server

server:
	GOOS=linux go build $(FLAGS) -o server.linux

clean:
	rm -f server
