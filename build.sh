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
	
		python setup.py bdist_rpm --dist-dir . --binary-only

else
	echo "Package creation is only supported on Debian and RedHat derivatives."
fi
