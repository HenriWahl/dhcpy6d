#!/bin/bash
#
# flexible entrypoint, mounted as volume
#

set -e

# got to working directory
cd /dhcpy6d

ls -lR

# run build script
./build.sh
