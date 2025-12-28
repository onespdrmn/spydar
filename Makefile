VERSION:=$(shell cat VERSION)

#git push --delete origin latest

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
	sudo cp spdr/spdr.linux /usr/bin/
	sudo cp server/server.linux /usr/bin/spdr-server

buildrelease: 
	git checkout main
	make clean all 
	mkdir -p build
	git lfs track "*.linux"
	git lfs track "*.windows"
	cp server/server.linux build/
	cp spdr/spdr.linux build/
	cp spdr/spdr.windows build/
	cp update/update.linux build/
	cp update/update.windows build/
	git add build/*
	git commit -m $(VERSION)
	git tag -a $(VERSION)

pushrelease:
	git push --tags

