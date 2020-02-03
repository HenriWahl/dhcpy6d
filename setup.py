#!/usr/bin/env python3
# encoding: utf-8

# dhcpy6d - DHCPv6 server 
# Copyright (C) 2012-2020 Henri Wahl <h.wahl@ifw-dresden.de>
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


from distutils.core import setup
import os.path

CLASSIFIERS = [
    'Intended Audience :: System Administrators',
    'Development Status :: 5 - Production/Stable',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: POSIX :: Linux',
    'Operating System :: POSIX', 
    'Natural Language :: English',
    'Programming Language :: Python',
    'Topic :: System :: Networking'
]

data_files_custom = [('/var/lib/dhcpy6d', ['var/lib/volatile.sqlite']),
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
              ('/etc', ['etc/dhcpy6d.conf']),]

# RPM creation uses more files as data_files which on Debian are 
# installed via debhelpers
# /tmp/DHCPY6D_BUILDING_RPM has been touched by build.sh
if os.path.exists('/tmp/DHCPY6D_BUILDING_RPM'):
    scripts_custom = ''
    data_files_custom.append(('/usr/sbin', ['dhcpy6d']))
    data_files_custom.append(('/etc/logrotate.d', ['etc/logrotate.d/dhcpy6d']))	
else:
    #scripts_custom = ['main.py']
    scripts_custom = ''
    entry_points = {'console_scripts': ['dhcpy6d = main']}

setup(name = 'dhcpy6d',
      version = '0.7.99',
      license = 'GNU GPL v2',
      description = 'DHCPv6 server daemon',
      long_description = 'Dhcpy6d delivers IPv6 addresses for DHCPv6 clients, which can be identified by DUID, hostname or MAC address as in the good old IPv4 days. It allows easy dualstack transition, addresses may be generated randomly, by range, by DNS, by arbitrary ID or MAC address. Clients can get more than one address, leases and client configuration can be stored in databases and DNS can be updated dynamically.',
      classifiers = CLASSIFIERS,
      author = 'Henri Wahl',
      author_email = 'h.wahl@ifw-dresden.de',
      url = 'https://dhcpy6d.ifw-dresden.de/',
      download_url = 'https://dhcpy6d.ifw-dresden.de/download',
      py_modules = ['dhcpy6d.client.default',
                    'dhcpy6d.client.from_config',
                    'dhcpy6d.client.parse_pattern',
                    'dhcpy6d.client.reuse_lease',
                    'dhcpy6d.config',
                    'dhcpy6d.constants',
                    'dhcpy6d.domain',
                    'dhcpy6d.globals',
                    'dhcpy6d.handler',
                    'dhcpy6d.helpers',
                    'dhcpy6d.log',
                    'dhcpy6d.route',
                    'dhcpy6d.storage.mysql',
                    'dhcpy6d.storage.postgresql',
                    'dhcpy6d.storage.sqlite',
                    'dhcpy6d.storage.store',
                    'dhcpy6d.storage.textfile',
                    'dhcpy6d.threads',
                    'dhcpy6d.transaction'],
      data_files = data_files_custom,
      scripts = scripts_custom, requires=['distro', 'dns']
      )

