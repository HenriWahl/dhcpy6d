#!/bin/bash
#
# flexible entrypoint, mounted as volume
#

set -e

# got to working directory
cd /dhcpy6d
# run build script
./build.sh
