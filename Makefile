all: doit

doit:
	make -C update
	make -C spdr

clean:
	make -C update clean
	make -C spdr clean
