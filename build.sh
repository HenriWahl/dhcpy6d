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

        TOPDIR=$HOME/dhcpy6d.$$
        SPEC=installer/redhat/dhcpy6d.spec

		# create source folder for rpmbuild
		mkdir -p $TOPDIR/SOURCES
	
        # init needed in TOPDIR/SOURCES
        cp -pf installer/redhat/init.d/dhcpy6d $TOPDIR/SOURCES

		# use setup.py sdist build output to get package name
		FILE=`python setup.py sdist --dist-dir $TOPDIR/SOURCES | grep "creating dhcpy6d-" | head -n1 | cut -d" " -f2`
		echo Source file: $FILE.tar.gz

        # version
        VERSION=`echo $FILE | cut -d"-" -f 2`

        # replace version in the spec file
        sed -i "s|Version:.*|Version: $VERSION|" $SPEC

		# finally build binary rpm
		rpmbuild -bb --define "_topdir $TOPDIR" $SPEC

		# get rpm file
		cp -f `find $TOPDIR/RPMS -name "$FILE-1.*noarch.rpm"` .

        # clean
        rm -rf $TOPDIR
else
	echo "Package creation is only supported on Debian and RedHat derivatives."
fi
