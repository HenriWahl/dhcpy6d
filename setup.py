#!/usr/bin/env python3

# dhcpy6d - DHCPv6 server
# Copyright (C) 2012-2024 Henri Wahl <h.wahl@dhcpy6d.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the
#
# Free Software Foundation
# 51 Franklin Street, Fifth Floor
# Boston, MA 02110-1301
# USA

import os
import os.path
from setuptools import setup, find_packages
import shutil

# workaround to get dhcpy6d-startscript created
try:
    if not os.path.exists('sbin'):
        os.mkdir('sbin')
    shutil.copyfile('main.py', 'sbin/dhcpy6d')
    os.chmod('sbin/dhcpy6d', 0o554)
except:
    print('could not copy main.py to sbin/dhcpy6d')

classifiers = [
    'Intended Audience :: System Administrators',
    'Development Status :: 5 - Production/Stable',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: POSIX :: Linux',
    'Operating System :: POSIX',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Topic :: System :: Networking'
]

data_files = [('/var/lib/dhcpy6d', ['var/lib/volatile.sqlite']),
              ('/var/log', ['var/log/dhcpy6d.log']),
              ('/usr/share/doc/dhcpy6d', ['doc/clients-example.conf',
                                          'doc/config.sql',
                                          'doc/dhcpy6d-example.conf',
                                          'doc/dhcpy6d-minimal.conf',
                                          'doc/LICENSE',
                                          'doc/volatile.sql',
                                          'doc/volatile.postgresql']),
              ('/usr/share/man/man5', ['man/man5/dhcpy6d.conf.5',
                                       'man/man5/dhcpy6d-clients.conf.5']),
              ('/usr/share/man/man8', ['man/man8/dhcpy6d.8']),
              ('/etc', ['etc/dhcpy6d.conf']),
              ('/usr/sbin', ['sbin/dhcpy6d']),
              ]

setup(name='dhcpy6d',
      version='1.6.0',
      license='GNU GPL v2',
      description='DHCPv6 server daemon',
      long_description='Dhcpy6d delivers IPv6 addresses for DHCPv6 clients, which can be identified by DUID, hostname or MAC address as in the good old IPv4 days. It allows easy dualstack transition, addresses may be generated randomly, by range, by DNS, by arbitrary ID or MAC address. Clients can get more than one address, leases and client configuration can be stored in databases and DNS can be updated dynamically.',
      author='Henri Wahl',
      author_email='henri@dhcpy6d.de',
      url='https://dhcpy6d.de/',
      download_url='https://dhcpy6d.de/download',
      requires=['distro', 'dnspython'],
      packages=find_packages(),
      classifiers=classifiers,
      data_files=data_files
      )
