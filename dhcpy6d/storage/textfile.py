# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2024 Henri Wahl <henri@dhcpy6d.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

import configparser

from ..config import cfg, BOOLPOOL
from ..helpers import (decompress_ip6,
                       error_exit,
                       listify_option, convert_prefix_inline)

from .store import (ClientConfig,
                    Store)


class Textfile(Store):
    """
        client config in text files
    """
    def __init__(self, query_queue, answer_queue):
        Store.__init__(self, query_queue, answer_queue)
        self.connection = None

        # store config information of hosts
        self.hosts = {}
        self.index_mac = {}
        self.index_duid = {}

        # store IDs for ID-based hosts to check if there are duplicates
        self.ids = {}

        # instantiate a Configparser
        config = configparser.ConfigParser()
        config.read(cfg.STORE_FILE_CONFIG)

        # read all sections of config file
        # a section here is a host
        for section in config.sections():
            hostname = config[section]['hostname'].lower()
            # only if section matches hostname the following steps are of any use
            if section.lower() == hostname:
                self.hosts[hostname] = ClientConfig()
                for item in config.items(hostname):
                    # lowercase all MAC addresses, DUIDs, IPv6 addresses and prefixes
                    if item[0].upper() in ['ADDRESS', 'DUID', 'HOSTNAME', 'MAC', 'PREFIX', 'PREFIX_ROUTE_LINK_LOCAL']:
                        self.hosts[hostname].__setattr__(item[0].upper(), str(item[1]).lower())
                    else:
                        self.hosts[hostname].__setattr__(item[0].upper(), str(item[1]))

                # Test if host has ID
                if self.hosts[hostname].CLASS in cfg.CLASSES:
                    for a in cfg.CLASSES[self.hosts[hostname].CLASS].ADDRESSES:
                        if cfg.ADDRESSES[a].CATEGORY == 'id' and self.hosts[hostname].ID == '':
                            error_exit(f"Textfile client configuration: No ID given "
                                       f"for client '{self.hosts[hostname].HOSTNAME}'")
                else:
                    error_exit(f"Textfile client configuration: Class '{self.hosts[hostname].CLASS}' "
                               f"of host '{self.hosts[hostname].HOSTNAME}' is not defined")

                if self.hosts[hostname].ID != '':
                    if self.hosts[hostname].ID in list(self.ids.keys()):
                        error_exit(f"Textfile client configuration: ID '{self.hosts[hostname].ID}' "
                                   f"of client '{self.hosts[hostname].HOSTNAME}' is already used "
                                   f"by '{self.ids[self.hosts[hostname].ID]}'.")
                    else:
                        self.ids[self.hosts[hostname].ID] = self.hosts[hostname].HOSTNAME

                # in case of various MAC addresses split them...
                self.hosts[hostname].MAC = listify_option(self.hosts[hostname].MAC)

                # in case of various fixed addresses split them and avoid decompressing of ':'...
                self.hosts[hostname].ADDRESS = listify_option(self.hosts[hostname].ADDRESS)

                # Decompress IPv6-Addresses
                if self.hosts[hostname].ADDRESS is not None:
                    self.hosts[hostname].ADDRESS = [decompress_ip6(x) for x in self.hosts[hostname].ADDRESS]

                # in case of multiple supplied prefixes convert them to list
                self.hosts[hostname].PREFIX = listify_option(self.hosts[hostname].PREFIX)

                # split prefix into address and length, verify address
                if self.hosts[hostname].PREFIX is not None:
                    self.hosts[hostname].PREFIX = [convert_prefix_inline(x) for x in self.hosts[hostname].PREFIX]

                # boolify prefix route link local setting
                if self.hosts[hostname].PREFIX_ROUTE_LINK_LOCAL:
                    self.hosts[hostname].PREFIX_ROUTE_LINK_LOCAL = BOOLPOOL[self.hosts[hostname].PREFIX_ROUTE_LINK_LOCAL]

                # and put the host objects into index
                if self.hosts[hostname].MAC:
                    for m in self.hosts[hostname].MAC:
                        if m not in self.index_mac:
                            self.index_mac[m] = [self.hosts[hostname]]
                        else:
                            self.index_mac[m].append(self.hosts[hostname])

                # add DUIDs to IndexDUID
                if not self.hosts[hostname].DUID == '':
                    if not self.hosts[hostname].DUID in self.index_duid:
                        self.index_duid[self.hosts[hostname].DUID] = [self.hosts[hostname]]
                    else:
                        self.index_duid[self.hosts[hostname].DUID].append(self.hosts[hostname])
            else:
                error_exit(f"Textfile client configuration: section [{section.lower()}] "
                           f"does not match hostname '{hostname}'")
        # not very meaningful in case of databaseless textfile config but for completeness
        self.connected = True

    def get_client_config_by_mac(self, transaction):
        """
            get host(s?) and its information belonging to that mac
        """
        hosts = list()
        mac = transaction.mac
        if mac in self.index_mac:
            hosts.extend(self.index_mac[mac])
            return hosts
        else:
            return None

    def get_client_config_by_duid(self, transaction):
        """
            get host and its information belonging to that DUID
        """
        hosts = list()
        duid = transaction.duid
        if duid in self.index_duid:
            hosts.extend(self.index_duid[duid])
            return hosts
        else:
            return None

    def get_client_config_by_hostname(self, transaction):
        """
            get host and its information by hostname
        """
        hostname = transaction.hostname
        if hostname in self.hosts:
            return [self.hosts[hostname]]
        else:
            return None

    def get_client_config(self, hostname='', client_class='', duid='', address=[], mac=[], host_id=''):
        """
            give back ClientConfig object
        """
        return ClientConfig(hostname=hostname, client_class=client_class, duid=duid, address=address, mac=mac, host_id=host_id)
