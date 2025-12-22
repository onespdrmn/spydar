KEY:=$(HOME)/keys/data.spydar.org.pem
SERVER:=ec2-user@18.221.243.83

all: doit 

doit:
	make -C update
	make -C spdr
	make -C server

clean:
	make -C update clean
	make -C spdr clean
	make -C server clean
	rm -rf build

install:
	sudo cp build/spdr.linux /usr/bin/
	sudo cp build/server.linux /usr/bin/spdr-server

deploy: 
	mkdir -p build
	git lfs track "*.linux"
	git lfs track "*.windows"
	cp server/server.linux build
	cp spdr/spdr.linux build
	cp spdr/spdr.windows build
	cp update/update.linux build
	cp update/update.windows build
