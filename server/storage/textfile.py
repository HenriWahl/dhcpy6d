# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2019 Henri Wahl <h.wahl@ifw-dresden.de>
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

from ..globals import transactions
from ..helpers import (decompress_ip6,
                       error_exit,
                       listify_option)
from .store import (ClientConfig,
                    Store)


class Textfile(Store):
    """
        client config in text files
    """
    def __init__(self, cfg, query_queue, answer_queue, transactions, collected_macs):
        Store.__init__(self, cfg, query_queue, answer_queue, transactions, collected_macs)
        self.connection = None

        # store config information of hosts
        self.Hosts = dict()
        self.IndexMAC = dict()
        self.IndexDUID = dict()

        # store IDs for ID-based hosts to check if there are duplicates
        self.IDs = dict()

        # instantiate a Configparser
        config = configparser.ConfigParser()
        config.read(cfg.STORE_FILE_CONFIG)

        # read all sections of config file
        # a section here is a host
        for section in config.sections():
            self.Hosts[section] = ClientConfig()
            for item in config.items(section):
                # lowercase all MAC addresses, DUIDs and IPv6 addresses
                if item[0].upper() in ['MAC', 'DUID', 'ADDRESS']:
                    self.Hosts[section].__setattr__(item[0].upper(), str(item[1]).lower())
                else:
                    self.Hosts[section].__setattr__(item[0].upper(), str(item[1]))

            # Test if host has ID
            if self.Hosts[section].CLASS in cfg.CLASSES:
                for a in cfg.CLASSES[self.Hosts[section].CLASS].ADDRESSES:
                    if cfg.ADDRESSES[a].CATEGORY == 'id' and self.Hosts[section].ID == '':
                        error_exit("Textfile client configuration: No ID given for client '%s'" % (self.Hosts[section].HOSTNAME))
            else:
                error_exit("Textfile client configuration: Class '%s' of host '%s' is not defined" % (self.Hosts[section].CLASS, self.Hosts[section].HOSTNAME))

            if self.Hosts[section].ID != '':
                if self.Hosts[section].ID in list(self.IDs.keys()):
                    error_exit("Textfile client configuration: ID '%s' of client '%s' is already used by '%s'." % (self.Hosts[section].ID, self.Hosts[section].HOSTNAME, self.IDs[self.Hosts[section].ID]))
                else:
                    self.IDs[self.Hosts[section].ID] = self.Hosts[section].HOSTNAME

            # in case of various MAC addresses split them...
            self.Hosts[section].MAC = listify_option(self.Hosts[section].MAC)

            # in case of various fixed addresses split them and avoid decompressing of ':'...
            self.Hosts[section].ADDRESS = listify_option(self.Hosts[section].ADDRESS)

            # Decompress IPv6-Addresses
            if self.Hosts[section].ADDRESS != None:
                self.Hosts[section].ADDRESS =  [decompress_ip6(x) for x in self.Hosts[section].ADDRESS]

            # and put the host objects into index
            if self.Hosts[section].MAC:
                for m in self.Hosts[section].MAC:
                    if not m in self.IndexMAC:
                        self.IndexMAC[m] = [self.Hosts[section]]
                    else:
                        self.IndexMAC[m].append(self.Hosts[section])

            # add DUIDs to IndexDUID
            if not self.Hosts[section].DUID == '':
                if not self.Hosts[section].DUID in self.IndexDUID:
                    self.IndexDUID[self.Hosts[section].DUID] = [self.Hosts[section]]
                else:
                    self.IndexDUID[self.Hosts[section].DUID].append(self.Hosts[section])

        # not very meaningful in case of databaseless textfile config but for completeness
        self.connected = True


    def get_client_config_by_mac(self, transaction_id):
        """
            get host(s?) and its information belonging to that mac
        """
        hosts = list()
        mac = transactions[transaction_id].MAC
        if mac in self.IndexMAC:
            hosts.extend(self.IndexMAC[mac])
            return hosts
        else:
            return None


    def get_client_config_by_duid(self, transaction_id):
        """
            get host and its information belonging to that DUID
        """
        hosts = list()
        duid = transactions[transaction_id].DUID
        if duid in self.IndexDUID:
            hosts.extend(self.IndexDUID[duid])
            return hosts
        else:
            return None


    def get_client_config_by_hostname(self, transaction_id):
        """
            get host and its information by hostname
        """
        hostname = transactions[transaction_id].Hostname
        if hostname in self.Hosts:
            return [self.Hosts[hostname]]
        else:
            return None


    def get_client_config(self, hostname='', aclass='', duid='', address=[], mac=[], id=''):
        """
            give back ClientConfig object
        """
        return ClientConfig(hostname=hostname, aclass=aclass, duid=duid, address=address, mac=mac, id=id)
