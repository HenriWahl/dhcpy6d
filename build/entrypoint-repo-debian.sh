#!/bin/bash
#
# create repo package files and sign them
#

set -e

# go to working directory volume
cd /dhcpy6d

# import signing key, stored from GitHub secrets in workflow
gpg --import signing_key.asc

# temporary directory, will come from jekyll repo checkout in the future
mkdir -p dhcpy6d-jekyll/docs/repo/${RELEASE}/debian

# put package to its later place
cp -r artifact/*.deb dhcpy6d-jekyll/docs/repo/${RELEASE}/debian

# RELEASE is a runtime --env argument to make it easier to provide stable and latest reo
cd dhcpy6d-jekyll/docs/repo/${RELEASE}/debian

# create repo files
dpkg-scanpackages . > Packages
gzip -k -f Packages
apt-ftparchive release . > Release

# sign package
gpg -abs -o Release.gpg Release
gpg --clearsign -o InRelease Release
gpg --output key.gpg --armor --export
