#!/usr/bin/env python3

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

import os
import os.path
from setuptools import setup, find_packages
import shutil
import sys

package_data = {'dhcpy6d': ['var/lib/volatile.sqlite',
                            'var/log/dhcpy6d.log',
                            'doc/LICENSE', 'doc/*.conf', 'doc/*.sql', 'doc/*.postgresql',
                            'man/man5/*.conf.5',
                            'man/man8/*.8',
                            'etc/*.conf']}
extra_args = {}

if __name__ == "__main__" and "sdist" in sys.argv:
    # Workaround to get dhcpy6d-startscript created
    try:
        script_name = 'sbin/dhcpy6d'
        if not os.path.exists('sbin'):
            os.mkdir('sbin')
        shutil.copyfile('main.py', script_name)
        os.chmod(script_name, 0o554)
        package_data['dhcpy6d'].append(script_name)
    except:
        print('could not copy main.py to sbin/dhcpy6d')
else:
    extra_args = {
        "entry_points": {
            'console_scripts': [
                'dhcpy6d=main:run'
            ]
        },
    }

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

setup(name='dhcpy6d',
      version='1.0.3',
      license='GNU GPL v2',
      description='DHCPv6 server daemon',
      long_description='Dhcpy6d delivers IPv6 addresses for DHCPv6 clients, which can be identified by DUID, hostname or MAC address as in the good old IPv4 days. It allows easy dualstack transition, addresses may be generated randomly, by range, by DNS, by arbitrary ID or MAC address. Clients can get more than one address, leases and client configuration can be stored in databases and DNS can be updated dynamically.',
      author='Henri Wahl',
      author_email='h.wahl@ifw-dresden.de',
      url='https://dhcpy6d.ifw-dresden.de/',
      download_url='https://dhcpy6d.ifw-dresden.de/download',
      install_requires=['distro', 'dnspython'],
      packages=find_packages(),
      py_modules=["main"],
      classifiers=classifiers,
      package_data=package_data,
      **extra_args
      )
