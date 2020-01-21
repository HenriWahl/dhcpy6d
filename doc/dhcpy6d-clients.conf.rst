====================
dhcpy6d-clients.conf
====================

----------------------------------------------------
Clients configuration file for DHCPv6 server dhcpy6d
----------------------------------------------------

:Author: Copyright (C) 2012-2020 Henri Wahl <h.wahl@ifw-dresden.de>
:Date:   2018-04-30
:Version: 0.7
:Manual section: 5
:Copyright: This manual page is licensed under the GPL-2 license.

Description
===========

This file contains all client configuration data if these options are set in
**dhcpy6d.conf**:

**store_config = file**

and

**store_file_config = /path/to/dhcpy6d-clients.conf**

An alternative method to store client configuration is using database storage with SQLite or MySQLor PostgreSQL databases.
Further details are available at `<https://dhcpy6d.ifw-dresden.de/documentation/config>`_.

This file follows RFC 822 style parsed by Python ConfigParser module.

Some options allow multiple values. These have to be separated by spaces.


Client sections
===============

**[host_name]**
    Every client is configured in one section. It might have multiple attributes which are necessary depending on the configured **identification** and general address settings from *dhcpy6d.conf*.

Client attributes
=================
Every client section contains several attributes. **hostname** and **class** are mandatory. A third one should match at least one of the **identification** attributes configured in *dhcpy6d.conf*.

Both of the following 2 attributes are necessary - the **class** and at least one of the others.

Mandatory client attribute  'class'
-------------------------------------

**class = <class>**
    Every client needs a class. If a client is identified, it depends from its class, which addresses it will get.
    This relation is configured in *dhcpy6d.conf*.

Semi-mandatory client attributes
--------------------------------

Depending on **identification** in *dhcpy6d.conf* clients need to have the corresponding attributes. At least one of them is needed.

**mac = <mac-address>**
    The MAC address of the Link Local Address of the client DHCPv6 request, formatted like the most usual 01:02:03:04:05:06.

**duid = <duid>**
    The DUID of the client which comes with the DHCPv6 request message. No hex and \\ needed, just like  for example 000100011234567890abcdef1234 .

**hostname = <hostname>**
    The client non-FQDN hostname. It will be used for dynamic DNS updates.

Extra attributes
----------------

These attributes do not serve for identification of a client but for appropriate address generation.

**id = <id>** **id**
    has to be a hex number in the range 0-FFFF. The client ID from this directive will be inserted in the *address pattern* of category **id** instead of the **$id$** placeholder.

**address = <address> [<address> ...]**
    Addresses configured here will be sent to a client in addition to the ones it gets due to its class. Might be useful for some extra static address definitions.


Examples
========

The next lines contain some example client definitions:

| [client1]
| hostname = client1
| mac = 01:01:01:01:01:01
| class = valid_client

| [client2]
| hostname = client2
| mac = 02:02:02:02:02:02
| class = invalid_client

| [client3]
| hostname = client3
| duid = 000100011234567890abcdef1234
| class = valid_client
| address = 2001:cb8::babe:1

| [client4]
| hostname = client4
| mac = 04:04:04:04:04:04
| id = 1234
| class = valid_client

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

* dhcpy6d(8)
* dhcpy6d.conf(5)
* `<https://dhcpy6d.ifw-dresden.de>`_
* `<https://github.com/HenriWahl/dhcpy6d>`_

