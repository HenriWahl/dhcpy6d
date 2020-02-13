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

import re
import sys
import traceback

from ..config import cfg
from ..constants import CONST
from ..globals import (DUMMY_MAC,
                       EMPTY_OPTIONS,
                       IGNORED_LOG_OPTIONS)
from ..helpers import colonify_ip6
from ..log import log
from ..storage import config_store

from .default import default
from .from_config import from_config
from .parse_pattern import (parse_pattern_address,
                            parse_pattern_prefix)
from .reuse_lease import reuse_lease


class Client:
    """
        client object, generated from configuration database or on the fly
    """
    def __init__(self, transaction=None):
        # Addresses, depending on class or fixed addresses
        self.addresses = list()
        # Bootfiles, depending on class and architecture
        self.bootfiles = list()
        # Last chosen Bootfile
        self.chosen_boot_file = ''
        # Prefixes, depending on class or fixed prefixes
        self.prefixes = list()
        # DUID
        self.duid = ''
        # Hostname
        self.hostname = ''
        # Class/role of client - sadly "class" is a keyword and "class_" is more error prone
        self.client_class = ''
        # MAC
        self.mac = ''
        # timestamp of last update
        self.last_update = ''

        # when an transaction is given build the client
        if transaction is not None:
            self.build(transaction)

    def get_options_string(self):
        """
            all attributes in a string for logging
        """
        options_string = ''
        # put own attributes into a string
        options = sorted(self.__dict__.keys())
        # options.sort()
        for option in options:
            # ignore some attributes
            if option not in IGNORED_LOG_OPTIONS and self.__dict__[option] not in EMPTY_OPTIONS:
                if option == 'addresses':
                    if 'addresses' in cfg.CLASSES[self.client_class].ADVERTISE:
                        option_string = f'{option}:'
                        for address in self.__dict__[option]:
                            option_string += f' {colonify_ip6(address.ADDRESS)}'
                        options_string = f'{options_string} | {option_string}'
                elif option == 'bootfiles':
                    option_string = f'{option}:'
                    for bootfile in self.__dict__[option]:
                        option_string += f' {bootfile.BOOTFILE_URL}'
                    options_string = f'{options_string} | {option_string}'
                elif option == 'prefixes':
                    if 'prefixes' in cfg.CLASSES[self.client_class].ADVERTISE:
                        option_string = f'{option}:'
                        for p in self.__dict__[option]:
                            option_string += f' {colonify_ip6(p.PREFIX)}/{p.LENGTH}'
                        options_string = f'{options_string} | {option_string}'
                elif option == 'mac':
                    if self.__dict__[option] != DUMMY_MAC:
                        option_string = f'{option}: {self.__dict__[option]}'
                        options_string = f'{options_string} | {option_string}'
                else:
                    option_string = f'{option}: {self.__dict__[option]}'
                    options_string = f'{options_string} | {option_string}'
        return options_string

    def build(self, transaction):
        """
            builds client object of client config and transaction data
            checks if filters apply
            check if lease is still valid for RENEW and REBIND answers
            check if invalid addresses need to get deleted with lifetime 0
        """
        try:
            # configuration from client deriving from general config or filters - defaults to none
            client_config = None

            # list to collect filtered client information
            # if there are more than one entries that do not match the class is not uniquely identified
            filtered_class = {}

            # check if there are identification attributes of any class - classes are sorted by filter types
            for f in cfg.FILTERS:
                # look into all classes and their filters
                for c in cfg.FILTERS[f]:
                    # check further only if class applies to interface
                    if transaction.interface in c.INTERFACE:
                        # MACs
                        if c.FILTER_MAC != '':
                            pattern = re.compile(c.FILTER_MAC)
                            # if mac filter fits client mac address add client config
                            if len(pattern.findall(transaction.mac)) > 0:
                                client_config = config_store.get_client_config(hostname=transaction.hostname,
                                                                               mac=[transaction.mac],
                                                                               duid=transaction.duid,
                                                                               client_class=c.NAME)
                                # add classname to dictionary - if there are more than one entry classes do not match
                                # and thus are invalid
                                filtered_class[c.NAME] = c
                        # DUIDs
                        if c.FILTER_DUID != '':
                            pattern = re.compile(c.FILTER_DUID)
                            # if duid filter fits client duid address add client config
                            if len(pattern.findall(transaction.duid)) > 0:
                                client_config = config_store.get_client_config(hostname=transaction.hostname,
                                                                               mac=[transaction.mac],
                                                                               duid=transaction.duid,
                                                                               client_class=c.NAME)
                                # see above
                                filtered_class[c.NAME] = c
                        # HOSTNAMEs
                        if c.FILTER_HOSTNAME != '':
                            pattern = re.compile(c.FILTER_HOSTNAME)
                            # if hostname filter fits client hostname address add client config
                            if len(pattern.findall(transaction.hostname)) > 0:
                                client_config = config_store.get_client_config(hostname=transaction.hostname,
                                                                               mac=[transaction.mac],
                                                                               duid=transaction.duid,
                                                                               client_class=c.NAME)
                                # see above
                                filtered_class[c.NAME] = c

            # if there are more than 1 different classes matching for the client they are not valid
            if len(filtered_class) != 1:
                client_config = None

            # if filters did not get a result try it the hard way
            if client_config is None:
                # check all given identification criteria - if they all match each other the client is identified
                id_attributes = []

                # get client config that most probably seems to fit
                config_store.build_config_from_db(transaction)

                # check every attribute which is required
                # depending on identificaton mode empty results are ignored or considered
                # finally all attributes are grouped in sets and for a correctly identified host
                # only one entry should appear at the end
                for identification in cfg.IDENTIFICATION:
                    if identification == 'mac':
                        # get all MACs for client from config
                        macs = config_store.get_client_config_by_mac(transaction)
                        if macs:
                            macs = set(macs)
                            id_attributes.append(macs)
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            macs = set()
                            id_attributes.append(macs)

                    if identification == 'duid':
                        duids = config_store.get_client_config_by_duid(transaction)
                        if duids:
                            duids = set(duids)
                            id_attributes.append(duids)
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            duids = set()
                            id_attributes.append(duids)

                    if identification == 'hostname':
                        hostnames = config_store.get_client_config_by_hostname(transaction)
                        if hostnames:
                            hostnames = set(hostnames)
                            id_attributes.append(hostnames)
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            hostnames = set()
                            id_attributes.append(hostnames)

                # get intersection of all sets of identifying attributes - even the empty ones
                if len(id_attributes) > 0:
                    client_config = set.intersection(*id_attributes)

                    # if exactly one client has been identified use that config
                    if len(client_config) == 1:
                        # reuse client_config, grab it out of the set
                        client_config = client_config.pop()
                    else:
                        # in case there is no client config we should maybe log this?
                        client_config = None
                else:
                    client_config = None

            # If client gave some addresses for RENEW or REBIND consider them
            if transaction.last_message_received_type is not CONST.MESSAGE.RENEW and \
               transaction.last_message_received_type is not CONST.MESSAGE.REBIND and \
               not (len(transaction.addresses) == 0 and
                    len(transaction.prefixes) == 0):
                # use already existing lease
                reuse_lease(client=self, client_config=client_config, transaction=transaction)
            # build IA addresses from config - fixed ones and dynamic
            elif client_config is not None:
                # build client from config
                from_config(client=self, client_config=client_config, transaction=transaction)
            else:
                # use default class if host is unknown
                default(client=self, client_config=client_config, transaction=transaction)

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error('build(): ' + str(err))
            return None
