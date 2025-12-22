FLAGS := -ldflags "-s -w"

all: server

server:
	GOOS=linux go build $(FLAGS) -o server

clean:
	rm -f server
