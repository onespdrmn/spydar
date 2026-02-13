VERSION:=$(shell cat VERSION)
SPYDARVERSION=$(shell cat VERSION | awk -F - {'print $$2'})


all: doit

doit:
	make -C update
	make -C spydar
	make -C server

clean:
	make -C update clean
	make -C spydar clean
	make -C server clean
	rm -rf build
	rm -f spydar_setup.exe
	rm -rf rpmbuild

packages: doit nsis deb rpm #podman docker kubernetes 

nsis:
	echo "building windows installer"
	makensis spydar.nsis

rpm:
	echo "building rpm"
	mkdir -p rpmbuild/BUILD
	mkdir -p rpmbuild/RPMS
	mkdir -p rpmbuild/SOURCES
	mkdir -p rpmbuild/SPECS
	mkdir -p rpmbuild/SRPMS
	tar --exclude='debian' --exclude='.git' --exclude='rpmbuild' -cvzf rpmbuild/SOURCES/$(VERSION).tar.gz ../$(VERSION)/
	cat spydar.spec | sed s/SPYDARVERSION/$(SPYDARVERSION)/g > rpmbuild/SPECS/spydar.spec
	rpmbuild -v -D "_topdir /home/kali/spydar/$(VERSION)/rpmbuild" -ba $(PWD)/rpmbuild/SPECS/spydar.spec

tarball:
	tar --exclude='debian' --exclude='.git' --exclude='rpmbuild' --exclude='server/keys' -cvzf ../$(VERSION).tar.gz ../$(VERSION)/

make_debian_dir:
	echo "building deb"
	dh_make --createorig

deb:
	dpkg-buildpackage -rfakeroot -b -uc 

debclean:
	dpkg-buildpackage -Tclean

podman:
	echo "building podman"

docker:
	echo "building docker"

kubernetes:
	echo "building kubernetes"

install:
	sudo cp spydar/spydar.linux /usr/bin/
	sudo cp server/spydar-server.linux /usr/bin/spydar-server

buildrelease: 
	#git tag -d latest
	#git push --delete origin latest
	git checkout main
	make clean all 
	mkdir -p build
	git lfs track "*.linux"
	git lfs track "*.windows"
	cp server/spydar-server.linux build/
	cp spydar/spydar.linux build/
	cp spydar/spydar.windows build/
	cp update/update.linux build/
	cp update/update.windows build/
	git add build/*
	git commit -m $(VERSION)
	git tag -a $(VERSION)

pushrelease:
	git push --tags

