#!/bin/sh
#
#
# simple build script for dhcpy6d
#
#

if [ -f /etc/debian_version ] 
	then
		echo "Building .deb package"
		
		cd installer
		ln -s ../etc
		ln -s ../dhcpy6d
		ln -s ../dhcpy6
		ln -s ../doc
		ln -s ../var
		ln -s ../setup.py

		cp etc/default/dhcpy6d debian/dhcpy6d.default
		cp etc/logrotate.d/dhcpy6d debian/dhcpy6d.logrotate
		cp etc/init.d/dhcpy6d debian/dhcpy6d.init

		chmod 755 debian/rules
		dh clean --with python2
		debuild binary-indep

elif [ -f /etc/redhat-release ]
	then
		echo "Building .rpm package"

		# setup.py checks if this file exists
		touch /tmp/DHCPY6D_BUILDING_RPM

		# create source folder for rpmbuild
		mkdir -p ~/rpmbuild/SOURCES
	
		# build spec only because it needs to be modified
		python setup.py bdist_rpm --dist-dir . --spec-only

		# modify spec file to keep custom configuration when updating
		echo "%config(noreplace) /etc/dhcpy6d.conf" >> ./dhcpy6d.spec
		echo "%config(noreplace) /var/lib/dhcpy6d/volatile.sqlite" >> ./dhcpy6d.spec

		# use setup.py sdist build output to get package name
		FILE=`python setup.py sdist --dist-dir ~/rpmbuild/SOURCES | grep "creating dhcpy6d-" | head -n1 | cut -d" " -f2`
		echo Source file: $FILE.tar.gz

		# finally build binary rpm
		rpmbuild -bb dhcpy6d.spec

		# get rpm file
		cp ~/rpmbuild/RPMS/noarch/$FILE-1.noarch.rpm .

else
	echo "Package creation is only supported on Debian and RedHat derivatives."
fi
