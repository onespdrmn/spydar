KEY:=$(HOME)/keys/data.spydar.org.pem
SERVER:=ec2-user@18.221.243.83
VERSION:=$(shell cat VERSION)

all: doit #deploy

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
	sudo cp spdr/spdr.linux /usr/bin/
	sudo cp server/server.linux /usr/bin/spdr-server

buildrelease: 
	git checkout main
	mkdir -p build
	make clean all 
	git lfs track "*.linux"
	git lfs track "*.windows"
	cp server/server.linux build
	cp spdr/spdr.linux build
	cp spdr/spdr.windows build
	cp update/update.linux build
	cp update/update.windows build
	git add build/*
	git commit -m $(VERSION)
	git tag -a $(VERSION)

pushrelease:
	git push --tags

