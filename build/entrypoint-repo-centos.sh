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
mkdir -p dhcpy6d-jekyll/docs/repo/${RELEASE}/centos

# put package to its later place
cp -r artifact/*.rpm dhcpy6d-jekyll/docs/repo/${RELEASE}/centos

# RELEASE is a runtime --env argument to make it easier to provide stable and latest reo
cd dhcpy6d-jekyll/docs/repo/${RELEASE}/centos

# create repo files + sign package
gpg --output RPM-GPG-KEY-dhcpy6d --armor --export
cp RPM-GPG-KEY-dhcpy6d /etc/pki/rpm-gpg
rpm --import RPM-GPG-KEY-dhcpy6d
echo "%_signature gpg" > ~/.rpmmacros
echo "%_gpg_name dhcpy6d" >> ~/.rpmmacros
rpm --resign *.rpm
createrepo --update .
rm -rf .rpmmacros
