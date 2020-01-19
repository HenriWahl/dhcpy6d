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
from ..globals import (DUMMY_MAC,
                       EMPTY_OPTIONS,
                       IGNORED_LOG_OPTIONS,
                       transactions)
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
    def __init__(self, transaction_id=None):
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

        # when an transaction_id is given build the client
        if transaction_id is not None:
            self.build(transaction_id)

    def get_options_string(self):
        """
            all attributes in a string for logging
        """
        options_string = ''
        # put own attributes into a string
        options = sorted(list(self.__dict__.keys()))
        # options.sort()
        for o in options:
            # ignore some attributes
            if o not in IGNORED_LOG_OPTIONS and self.__dict__[o] not in EMPTY_OPTIONS:
                if o == 'addresses':
                    if 'addresses' in cfg.CLASSES[self.client_class].ADVERTISE:
                        option = o + ':'
                        for a in self.__dict__[o]:
                            option += ' ' + colonify_ip6(a.ADDRESS)
                        options_string = options_string + ' | '  + option
                elif o == 'bootfiles':
                    option = o + ':'
                    for a in self.__dict__[o]:
                        option += ' ' + a.BOOTFILE_URL
                    options_string = options_string + ' | '  + option
                elif o == 'prefixes':
                    if 'prefixes' in cfg.CLASSES[self.client_class].ADVERTISE:
                        option = o + ':'
                        for p in self.__dict__[o]:
                            option += ' {0}/{1}'.format(colonify_ip6(p.PREFIX), p.LENGTH)
                        options_string = options_string + ' | '  + option
                elif o == 'mac':
                    if self.__dict__[o] != DUMMY_MAC:
                        option = o + ': ' + str(self.__dict__[o])
                        options_string = options_string + ' | ' + option
                else:
                    option = o + ': ' + str(self.__dict__[o])
                    options_string = options_string + ' | '  + option
        return options_string

    def build(self, transaction_id):
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
                    if transactions[transaction_id].interface in c.INTERFACE:
                        # MACs
                        if c.FILTER_MAC != '':
                            pattern = re.compile(c.FILTER_MAC)
                            # if mac filter fits client mac address add client config
                            if len(pattern.findall(transactions[transaction_id].mac)) > 0:
                                client_config = config_store.get_client_config(hostname=transactions[transaction_id].hostname,
                                                                               mac=[transactions[transaction_id].mac],
                                                                               duid=transactions[transaction_id].duid,
                                                                               aclass=c.NAME)
                                # add classname to dictionary - if there are more than one entry classes do not match
                                # and thus are invalid
                                filtered_class[c.NAME] = c
                        # DUIDs
                        if c.FILTER_DUID != '':
                            pattern = re.compile(c.FILTER_DUID)
                            # if duid filter fits client duid address add client config
                            if len(pattern.findall(transactions[transaction_id].duid)) > 0:
                                client_config = config_store.get_client_config(hostname=transactions[transaction_id].hostname,
                                                                               mac=[transactions[transaction_id].mac],
                                                                               duid=transactions[transaction_id].duid,
                                                                               aclass=c.NAME)
                                # see above
                                filtered_class[c.NAME] = c
                        # HOSTNAMEs
                        if c.FILTER_HOSTNAME != '':
                            pattern = re.compile(c.FILTER_HOSTNAME)
                            # if hostname filter fits client hostname address add client config
                            if len(pattern.findall(transactions[transaction_id].hostname)) > 0:
                                client_config = config_store.get_client_config(hostname=transactions[transaction_id].hostname,
                                                                               mac=[transactions[transaction_id].mac],
                                                                               duid=transactions[transaction_id].duid,
                                                                               aclass=c.NAME)
                                # see above
                                filtered_class[c.NAME] = c

            # if there are more than 1 different classes matching for the client they are not valid
            if len(filtered_class) != 1:
                client_config = None

            # if filters did not get a result try it the hard way
            if client_config is None:
                # check all given identification criteria - if they all match each other the client is identified
                id_attributes = list()

                # get client config that most probably seems to fit
                config_store.build_config_from_db(transaction_id)

                # check every attribute which is required
                # depending on identificaton mode empty results are ignored or considered
                # finally all attributes are grouped in sets and for a correctly identified host
                # only one entry should appear at the end
                for identification in cfg.IDENTIFICATION:
                    if identification == 'mac':
                        # get all MACs for client from config
                        macs = config_store.get_client_config_by_mac(transaction_id)
                        if macs:
                            macs = set(macs)
                            id_attributes.append('macs')
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            macs = set()
                            id_attributes.append('macs')

                    if identification == 'duid':
                        duids = config_store.get_client_config_by_duid(transaction_id)
                        if duids:
                            duids = set(duids)
                            id_attributes.append('duids')
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            duids = set()
                            id_attributes.append('duids')

                    if identification == 'hostname':
                        hostnames = config_store.get_client_config_by_hostname(transaction_id)
                        if hostnames:
                            hostnames = set(hostnames)
                            id_attributes.append('hostnames')
                        elif cfg.IDENTIFICATION_MODE == 'match_all':
                            hostnames = set()
                            id_attributes.append('hostnames')

                # get intersection of all sets of identifying attributes - even the empty ones
                if len(id_attributes) > 0:
                    client_config = set.intersection(eval('&'.join(id_attributes)))

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
            if transactions[transaction_id].last_message_received_type in (5, 6) and \
                not (len(transactions[transaction_id].addresses) == 0 and
                     len(transactions[transaction_id].prefixes) == 0):
                # use already existing lease
                reuse_lease(client=self, client_config=client_config, transaction_id=transaction_id)
            # build IA addresses from config - fixed ones and dynamic
            elif client_config is not None:
                # build client from config
                from_config(client=self, client_config=client_config, transaction_id=transaction_id)
            else:
                # use default class if host is unknown
                default(client=self, client_config=client_config, transaction_id=transaction_id)

        except Exception as err:
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            log.error('build_client(): ' + str(err))
            return None
