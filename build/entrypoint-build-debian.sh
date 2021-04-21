#!/bin/bash
#
# flexible entrypoint, mounted as volume
#

set -e

# got to working directory
cd /dhcpy6d
# run build script
./build.sh
# copy resulting Debian package back into working directory
cp /*.deb /dhcpy6d