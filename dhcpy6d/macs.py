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

"""Module dhcpy6d"""

from binascii import hexlify
from random import randint
import select
import shlex
import socket
import struct
import subprocess
import sys
import traceback

from .config import cfg
from .constants import (RTM_DELNEIGH,
                        RTM_GETNEIGH,
                        RTM_NEWNEIGH,
                        NLMSG_DONE,
                        NLMSG_ERROR,
                        MSG_HEADER_FLAGS,
                        MSG_HEADER_LENGTH,
                        MSG_HEADER_TYPE,
                        NUD_FAILED,
                        NUD_INCOMPLETE,
                        NUD_NOARP,
                        NDA,
                        NLA_ALIGNTO,
                        NLMSG_ALIGNTO)
from .globals import (collected_macs,
                      IF_NUMBER,
                      NC,
                      OS,
                      timer)
from .helpers import (colonify_ip6,
                      colonify_mac,
                      correct_mac,
                      decompress_ip6,
                      NeighborCacheRecord)
from .log import log
from .storage import volatile_store


def get_neighbor_cache_linux(if_number, now):
    """
    imported version of https://github.com/vokac/dhcpy6d
    https://github.com/vokac/dhcpy6d/commit/bd34d3efb18ba6016a2b3afea0b6a3fcdfb524a4
    Thanks for donating!
    """
    # open raw NETLINK socket
    # NETLINK_ROUTE has neighbor cache information too
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    # PID 0 means AUTOPID, let socket choose
    s.bind((0, 0))
    pid, groups = s.getsockname()

    # random sequence for NETLINK access
    seq = randint(0, pow(2, 31))

    # netlink message header (struct nlmsghdr)
    msg_header = struct.pack('IHHII',
                             MSG_HEADER_LENGTH,
                             MSG_HEADER_TYPE,
                             MSG_HEADER_FLAGS,
                             seq,
                             pid)

    # NETLINK message is always the same except header seq (struct ndmsg)
    msg = struct.pack('B', socket.AF_INET6)

    # send message with header
    s.send(msg_header + msg)

    # read all data from socket
    answer = b''
    while True:
        r, w, e = select.select([s], [], [], 0.)
        if s not in r:
            break  # no more data
        answer += s.recv(16384)

    result = {}
    curr_pos = 0
    answer_pos = 0
    answer_len = len(answer)

    nlmsghdr_fmt = 'IHHII'  # struct nlmsghdr
    nlattr_fmt = 'HH'  # struct nlattr
    ndmsg_fmt = 'BBHiHBB'  # struct ndmsg

    nlmsg_header_len = (struct.calcsize(nlmsghdr_fmt) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)  # alignment to 4
    nla_header_len = (struct.calcsize(nlattr_fmt) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)  # alignment to 4

    # parse netlink answer to RTM_GETNEIGH
    try:
        while answer_pos < answer_len:
            curr_pos = answer_pos

            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from(f'<{nlmsghdr_fmt}',
                                                                                          answer,
                                                                                          answer_pos)
            # basic safety checks for received data (imitates NLMSG_OK)
            if nlmsg_len < struct.calcsize(f'<{nlmsghdr_fmt}'):
                log.warn('broken data from netlink (position {0}, nlmsg_len {1}): '
                         'nlmsg_len is smaller than structure size'.format(answer_pos, nlmsg_len))
                break
            if answer_len - answer_pos < struct.calcsize(f'<{nlmsghdr_fmt}'):
                log.warn(f'broken data from netlink (position {answer_pos}, length avail {answer_len - answer_pos}): '
                         'received data size is smaller than structure size')
                break
            if answer_len - answer_pos < nlmsg_len:
                log.warn(f'broken data from netlink (position {answer_pos}, length avail {answer_len - answer_pos}): '
                         'received dcolonify_ata size is smaller than nlmsg_len')
                break
            if pid != nlmsg_pid or seq != nlmsg_seq:
                log.warn(f'broken data from netlink (position {answer_pos}, length avail {answer_len - answer_pos}): '
                         f'invalid seq ({seq} x {nlmsg_seq}) or pid ({pid} x {nlmsg_pid})')
                break

            # data for this Routing/device hook record
            nlmsg_data = answer[answer_pos + nlmsg_header_len:answer_pos + nlmsg_len]

            if nlmsg_type == NLMSG_DONE:
                break
            if nlmsg_type == NLMSG_ERROR:
                nlmsgerr_error, nlmsgerr_len, nlmsgerr_type, nlmsgerr_flags, nlmsgerr_seq, nlmsgerr_pid = \
                    struct.unpack_from('<sIHHII', nlmsg_data)
                log.warn(f'broken data from netlink (position {answer_pos}, length avail {answer_len - answer_pos}): '
                         f'invalid message (errno {nlmsgerr_error})')
                break
            if nlmsg_type not in [RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH]:
                log.warn(f'broken data from netlink (position {answer_pos}, length avail {answer_len - answer_pos}): '
                         f'this is really weird, wrong message type {nlmsg_type}')
                break

            curr_pos = answer_pos + nlmsg_header_len
            ndm_family, ndm_pad1, ndm_pad2, ndm_ifindex, ndm_state, ndm_flags, ndm_type = \
                struct.unpack_from(f'<{ndmsg_fmt}', nlmsg_data, 0)
            nda = {'NDM_FAMILY': ndm_family, 'NDM_IFINDEX': ndm_ifindex,
                   'NDM_STATE': ndm_state, 'NDM_FLAGS': ndm_flags,
                   'NDM_TYPE': ndm_type}
            nlmsg_data_pos = 0
            nlmsg_data_len = nlmsg_len - nlmsg_header_len
            while nlmsg_data_pos < nlmsg_data_len:
                curr_pos = answer_pos + nlmsg_header_len + nlmsg_data_pos

                nla_len, nla_type = \
                    struct.unpack_from(f'<{nlattr_fmt}', nlmsg_data, nlmsg_data_pos)

                # basic safety checks for received data (imitates RTA_OK)
                if nla_len < struct.calcsize(f'<{nlattr_fmt}'):
                    log.debug('This is normal for last record, but we should not get here (because of NLMSG_DONE); '
                              f'data size: {answer_len}, data[{answer_pos + nlmsg_header_len}:'
                              f'{answer_pos + nlmsg_len}] =  {hexlify(nlmsg_data)}')
                    break

                # data for this Routing/device hook record attribute
                nla_data = nlmsg_data[nlmsg_data_pos + nla_header_len:nlmsg_data_pos + nla_len]

                nda_type_key = NDA.get(nla_type, str(nla_type))
                if nda_type_key == 'NDA_DST':
                    nda[nda_type_key] = colonify_ip6(hexlify(nla_data))
                elif nda_type_key == 'NDA_LLADDR':
                    nda[nda_type_key] = colonify_mac(hexlify(nla_data))
                elif nda_type_key == 'NDA_CACHEINFO':
                    nda[nda_type_key] = struct.unpack_from('<IIII', nla_data)
                elif nda_type_key == 'NDA_VLAN':
                    nda[nda_type_key] = hexlify(nla_data)
                else:
                    nda[nda_type_key] = nla_data

                nlmsg_data_pos += nla_header_len
                nlmsg_data_pos += (nla_len - nla_header_len + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)  # alignment to 4

            # prepare all required data to be returned to callee
            # * only care about configured devices
            # * no need for multicast address cache entries (MAC 33:33:...)
            if nda['NDM_STATE'] & ~(NUD_INCOMPLETE | NUD_FAILED | NUD_NOARP):
                if nda['NDM_IFINDEX'] not in if_number:
                    log.debug(f"can't find device for interface index {nda['NDM_IFINDEX']}")
                elif 'NDA_DST' not in nda:
                    log.warn(f"can't find destination address (wrong entry state: {nda['NDM_STATE']}?!)")
                elif 'NDA_LLADDR' not in nda:
                    log.warn(f"can't find local hardware address (wrong entry state: {nda['NDM_STATE']}?!)")
                else:
                    if if_number[nda['NDM_IFINDEX']] in cfg.INTERFACE and not nda['NDA_LLADDR'].startswith('33:33:'):
                        # store neighbor caches entries
                        record = NeighborCacheRecord(llip=decompress_ip6(nda['NDA_DST']),
                                                     mac=nda['NDA_LLADDR'],
                                                     interface=if_number[nda['NDM_IFINDEX']],
                                                     now=now)
                        result[record.llip] = record

            # move to next record
            answer_pos += nlmsg_len

    except struct.error as e:
        log.warn(f'broken data from netlink (position {answer_pos}, '
                 f'data[{curr_pos}:{answer_len}] = {hexlify(answer[curr_pos:curr_pos + 8])}...): {str(e)}')

    # clean up
    s.close()

    return result


def collect_macs(now):
    """
    collect MAC address from clients to link local addresses with MACs
    if a client has a new MAC the LLIP changes - with privacy extension enabled anyway
    calls local ip command to get neighbor cache - any more sophisticated idea is welcome!

    The Linux netlink method is considered stable now.
    """
    try:
        # Linux can use kernel neighbor cache
        if OS == 'Linux':
            for host in list(get_neighbor_cache_linux(IF_NUMBER, timer.time).values()):
                if host.llip not in collected_macs:
                    if host.llip.startswith('fe80'):
                        collected_macs[host.llip] = host
                        if cfg.LOG_MAC_LLIP:
                            log.info(f'collected mac {host.mac} for llip {colonify_ip6(host.llip)}')
                        if cfg.CACHE_MAC_LLIP:
                            volatile_store.store_mac_llip(host.mac, host.llip, timer.time)
        else:
            # subject to change - other distros might have other paths - might become a task
            # for a setup routine to find appropriate paths
            for host in subprocess.getoutput(NC[OS]['call']).splitlines():
                # get fragments of output line
                frags = shlex.split(host)
                if frags[NC[OS]['dev']] in cfg.INTERFACE and len(frags) >= NC[OS]['len']:
                    # get rid of %interface
                    frags[NC[OS]['llip']] = decompress_ip6(frags[NC[OS]['llip']].split('%')[0])
                    if frags[NC[OS]['mac']] == '(incomplete)':
                        continue
                    # correct maybe shortened MAC
                    frags[NC[OS]['mac']] = correct_mac(frags[NC[OS]['mac']])
                    # put non yet existing LLIPs into dictionary - if they have MACs
                    if not frags[NC[OS]['llip']] in collected_macs and \
                       frags[NC[OS]['llip']].lower().startswith('fe80') and \
                       ':' in frags[NC[OS]['mac']]:
                        collected_macs[frags[NC[OS]['llip']]] = NeighborCacheRecord(llip=frags[NC[OS]['llip']],
                                                                                    mac=frags[NC[OS]['mac']],
                                                                                    interface=frags[NC[OS]['dev']],
                                                                                    now=now)
                        if cfg.LOG_MAC_LLIP:
                            log.info(f"collected mac {frags[NC[OS]['mac']]} for "
                                     f"llip {colonify_ip6(frags[NC[OS]['llip']])}")
                        volatile_store.store_mac_llip(frags[NC[OS]['mac']], frags[NC[OS]['llip']], timer.time)
    except Exception as err:
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        log.error('collect_macs(): ' + str(err))
