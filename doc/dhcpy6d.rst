=======
dhcpy6d
=======

----------------------------------------------------------------
MAC address aware DHCPv6 server
----------------------------------------------------------------

:Author: Copyright (C) 2012-2020 Henri Wahl <h.wahl@ifw-dresden.de>
:Date:   2018-04-30
:Version: 0.7
:Manual section: 8
:Copyright: This manual page is licensed under the GPL-2 license.


Synopsis
========

**dhcpy6d** [**-c** *file*] [**-u** *user*] [**-g** *group*] [**-p** *prefix*] [**-r** *yes|no*] [**-d** *duid*] [**-m** *message*] [**-G**]


Description
===========
**dhcpy6d** is an open source server for DHCPv6, the DHCP protocol for IPv6.

Its development is driven by the need to be able to use the existing
IPv4 infrastructure in coexistence with IPv6.  In a dualstack
scenario, the existing DHCPv4 most probably uses MAC addresses of
clients to identify them.  This is not intended by RFC 3315 for
DHCPv6, but also not forbidden.  Dhcpy6d is able to do so in local
network segments and therefore offers a pragmatical method for
parallel use of DHCPv4 and DHCPv6, because existing client management
solutions could be used further.

**dhcpy6d** comes with the following features:

* identifies clients by MAC address, DUID or hostname
* generates addresses randomly, by MAC address, by range or by given ID
* filters clients by MAC, DUID or hostname
* assigns multiple addresses per client
* allows one to organize clients in different classes
* stores leases in MySQL, PostgreSQL or SQLite database
* client information can be retrieved from MySQL or PostgreSQL database or textfile
* dynamically updates DNS (Bind)
* supports rapid commit
* listens on multiple interfaces

Options
=======

Most configuration is done via the configuration file.

**-c, --config=<configfile>**
    Set the configuration file to use. Default is /etc/dhcpy6d.conf.

**-u, --user=<user>**
    Set the unprivileged user to be used.

**-g, --group=<group>**
    Set the unprivileged group to be used.

**-r, --really-do-it=<yes|no>**
    Really activate the DHCPv6 server. This is a precaution to prevent larger network trouble.

**-d, --duid=<duid>**
    Set the DUID for the server. This argument is used by /etc/init.d/dhcpy6d and /lib/systemd/system/dhcpy6d.service repectively.

**-p, --prefix=<prefix>**
    Set the prefix which will be substituted for the $prefix$ variable in address definitions. Useful for setups where the ISP uses a changing prefix.

**-G, --generate-duid**
    Generate DUID to be used in config file. This argument is used to generate a DUID for /etc/default/dhcpy6d. After generation dhcpy6d exits.

**-m, --message "<message>"**
    Send message to running dhcpy6d server. At the moment the only valid message is *"prefix <prefix>"*. The value of *<prefix>* will be used instantly where *$prefix$* is to be replaced as placeholder in address definitions. This might be of use for dynamic prefixes by ISPs, for example: *dhcpy6d -m "prefix 2001:db8"*.

Files
=====

* /etc/dhcpy6d.conf
* /etc/dhcpy6d-clients.conf
* /var/lib/dhcpy6d/
* /var/log/dhcpy6d.log


License
=======

This program is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation; either
version 2 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be
useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public
License along with this package; if not, write to the Free
Software Foundation, Inc., 51 Franklin St, Fifth Floor,
Boston, MA  02110-1301 USA

On Debian systems, the full text of the GNU General Public
License version 2 can be found in the file
*/usr/share/common-licenses/GPL-2*.

See also
========
* dhcpy6d.conf(5)
* dhcpy6d-clients.conf(5)
* `<https://dhcpy6d.ifw-dresden.de>`_
* `<https://github.com/HenriWahl/dhcpy6d>`_


