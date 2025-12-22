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

deploy: doit
	mkdir -p build
	cp server/server build
	cp spdr/spdr.linux build
	cp spdr/spdr.windows build
	cp update/update.linux build
	cp update/update.windows build
	scp -i $(KEY) -r build $(SERVER):~/
