# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2020 Henri Wahl <h.wahl@ifw-dresden.de>
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

from ..config import cfg
from ..helpers import (decompress_ip6,
                       error_exit,
                       listify_option)

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
            self.hosts[section] = ClientConfig()
            for item in config.items(section):
                # lowercase all MAC addresses, DUIDs and IPv6 addresses
                if item[0].upper() in ['MAC', 'DUID', 'ADDRESS']:
                    self.hosts[section].__setattr__(item[0].upper(), str(item[1]).lower())
                else:
                    self.hosts[section].__setattr__(item[0].upper(), str(item[1]))

            # Test if host has ID
            if self.hosts[section].CLASS in cfg.CLASSES:
                for a in cfg.CLASSES[self.hosts[section].CLASS].ADDRESSES:
                    if cfg.ADDRESSES[a].CATEGORY == 'id' and self.hosts[section].ID == '':
                        error_exit(f"Textfile client configuration: No ID given "
                                   f"for client '{self.hosts[section].HOSTNAME}'")
            else:
                error_exit(f"Textfile client configuration: Class '{self.hosts[section].CLASS}' "
                           f"of host '{self.hosts[section].HOSTNAME}' is not defined")

            if self.hosts[section].ID != '':
                if self.hosts[section].ID in list(self.ids.keys()):
                    error_exit(f"Textfile client configuration: ID '{self.hosts[section].ID}' "
                               f"of client '{self.hosts[section].HOSTNAME}' is already used "
                               f"by '{self.ids[self.hosts[section].ID]}'.")
                else:
                    self.ids[self.hosts[section].ID] = self.hosts[section].HOSTNAME

            # in case of various MAC addresses split them...
            self.hosts[section].MAC = listify_option(self.hosts[section].MAC)

            # in case of various fixed addresses split them and avoid decompressing of ':'...
            self.hosts[section].ADDRESS = listify_option(self.hosts[section].ADDRESS)

            # Decompress IPv6-Addresses
            if self.hosts[section].ADDRESS is not None:
                self.hosts[section].ADDRESS = [decompress_ip6(x) for x in self.hosts[section].ADDRESS]

            # and put the host objects into index
            if self.hosts[section].MAC:
                for m in self.hosts[section].MAC:
                    if m not in self.index_mac:
                        self.index_mac[m] = [self.hosts[section]]
                    else:
                        self.index_mac[m].append(self.hosts[section])

            # add DUIDs to IndexDUID
            if not self.hosts[section].DUID == '':
                if not self.hosts[section].DUID in self.index_duid:
                    self.index_duid[self.hosts[section].DUID] = [self.hosts[section]]
                else:
                    self.index_duid[self.hosts[section].DUID].append(self.hosts[section])

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
