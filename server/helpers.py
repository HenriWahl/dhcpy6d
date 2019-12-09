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

import binascii
import shlex
import socket
import sys

# whitespace for options with more than one value
WHITESPACE = ' ,'

# needed for NTP server option 56 and its suboptions
NTP_SERVER_TYPES = {'SRV': 1, 'MC': 2, 'FQDN': 3}

# define address characters once - for decompress_ipv6
ADDRESS_CHARS_STRICT = ':0123456789abcdef'
ADDRESS_CHARS_NON_STRICT = ':0123456789abcdefx'

# localhost
LOCALHOST = '::1'
LOCALHOST_LLIP = '00000000000000000000000000000001'
LOCALHOST_INTERFACES = ['', 'lo', 'lo0']


class Interface:
    """
    hold interface information
    interface information comes in tuple from socket.if_nameindex()
    """

    def __init__(self, interface_tuple):
        self.index, self.name = interface_tuple


class NeighborCacheRecord:
    """
    object for neighbor cache entries to be returned by get_neighbor_cache_linux() and in CollectedMACs
    .interface is only interesting for real neighbor cache records, to be ignored for collected MACs stored in DB
    """

    def __init__(self, llip='', mac='', interface='', now=0):
        self.llip = llip
        self.mac = mac
        self.interface = interface
        self.timestamp = now


def convert_dns_to_binary(name):
    """
    convert domain name as described in RFC 1035, 3.1
    """
    binary = ''
    domain_parts = name.split('.')
    for p in domain_parts:
        binary += '%02x' % (len(p))  # length of Domain Name Segments
        binary += binascii.b2a_hex(p.encode()).decode()
    # final zero size octet following RFC 1035
    binary += '00'
    return binary


def convert_binary_to_dns(binary):
    """
    convert domain name from hex like in RFC 1035, 3.1
    """
    name = ''
    binary_parts = binary
    while len(binary_parts) > 0:
        # RFC 1035 - domain names are sequences of labels separated by length octets
        length = int(binary_parts[0:2], 16)
        # lenght*2 because 2 charse represent a byte
        label = binascii.a2b_hex(binary_parts[2:2 + length * 2])
        binary_parts = binary_parts[2 + length * 2:]
        name += label
        # insert '.' if this is not the last label of FQDN
        # >2 because last byte is the zero byte terminator
        if len(binary_parts) > 2:
            name += '.'
    return str(name)


def build_option(number, payload):
    """
    glue option with payload
    """
    # option number and length take 2 byte each so the string has to be 4 chars long
    option = '{:04x}'.format(number)  # option number
    option += '{:04x}'.format(len(payload) // 2)  # payload length, /2 because 2 chars are 1 byte
    option += payload
    return option


def correct_mac(mac):
    """
    OpenBSD shortens MAC addresses in ndp output - here they grow again
    """
    decompressed = ['%02x' % (int(m, 16)) for m in mac.split(':')]
    return ':'.join(decompressed)


def colonify_mac(mac):
    """
    return complete MAC address with colons
    """
    if type(mac) == bytes:
        mac = mac.decode()
    return ':'.join((mac[0:2], mac[2:4], mac[4:6], mac[6:8], mac[8:10], mac[10:12]))


def decompress_ip6(ip6, strict=True):
    """
    decompresses shortened IPv6 address and returns it as ':'-less 32 character string
    additionally allows testing for prototype address with less strict set of allowed characters
    """

    ip6 = ip6.lower()
    # cache some repeated calls
    colon_count1 = ip6.count(':')
    colon_count2 = ip6.count('::')
    colon_count3 = ip6.count(':::')

    # if in strict mode there are no hex numbers and ':' something is wrong
    if strict:
        for c in ip6:
            if c not in ADDRESS_CHARS_STRICT:
                raise Exception('{} should consist only of : 0 1 2 3 4 5 6 7 8 9 a b c d e f'.format(ip6))
    else:
        # used for comparison of leases with address pattern - X replace the dynamic part of the address
        for c in ip6:
            if c not in ADDRESS_CHARS_NON_STRICT:
                raise Exception('{} should consist only of : 0 1 2 3 4 5 6 7 8 9 a b c d e f x'.format(ip6))
    # nothing to do
    if len(ip6) == 32 and colon_count1 == 0:
        return ip6

    # larger heaps of :: smell like something wrong
    if colon_count2 > 1 or colon_count3 >= 1:
        raise Exception("{} has too many accumulated ':'".format(ip6))

    # less than 7 ':' but no '::' also make a bad impression
    if colon_count1 < 7 and colon_count2 != 1:
        raise Exception("{} is missing some ':'".format(ip6))

    # replace :: with :0000:: - the last ':' will be cut of finally
    while ip6.count(':') < 8 and ip6.count('::') == 1:
        ip6 = ip6.replace('::', ':0000::')

    # remaining ':' will be cut off
    ip6 = ip6.replace('::', ':')

    # ':' at the beginning have to be filled up with 0000 too
    if ip6.startswith(':'):
        ip6 = '0000' + ip6

    # if a segment is shorter than 4 chars the gaps get filled with zeros
    ip6_segments_source = ip6.split(':')
    ip6_segments_target = list()
    for s in ip6_segments_source:
        if len(s) > 4:
            raise Exception("{} has segment with more than 4 digits".format(ip6))
        else:
            ip6_segments_target.append(s.zfill(4))

    # return with separator (mostly '')
    return ''.join(ip6_segments_target)


def colonify_ip6(address):
    """
    return complete IPv6 address with colons
    """
    if address:
        if type(address) == bytes:
            address = address.decode()
        return ':'.join((address[0:4], address[4:8], address[8:12], address[12:16],
                         address[16:20], address[20:24], address[24:28], address[28:32]))
    else:
        return 'N/A'


def combine_prefix_length(prefix, length):
    """
    add prefix and length to 'prefix/length' string
    """
    return '{0}/{1}'.format(prefix, length)


def split_prefix(prefix):
    """
    split prefix and length from 'prefix/length' notation
    """
    return prefix.split('/')


def decompress_prefix(prefix, length):
    """
    return prefix with decompressed address part
    """
    return combine_prefix_length(decompress_ip6(prefix), length)


def error_exit(message='An error occured.', status=1):
    """
    exit with given error message
    allow prefix, especially for spitting out section of configuration errors
    """
    sys.stderr.write('\n{}\n\n'.format(message))
    sys.exit(status)


def listify_option(option):
    """
    return any comma or space separated option as list
    """
    if option:
        lex = shlex.shlex(option)
        lex.whitespace = WHITESPACE
        lex.wordchars += ':.-'
        return list(lex)
    else:
        return None


# def get_neighbor_cache_linux(if_number, now):
#     """
#     imported version of https://github.com/vokac/dhcpy6d
#     https://github.com/vokac/dhcpy6d/commit/bd34d3efb18ba6016a2b3afea0b6a3fcdfb524a4
#     Thanks for donating!
#     """
#     # open raw NETLINK socket
#     # NETLINK_ROUTE has neighbor cache information too
#     s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
#     # PID 0 means AUTOPID, let socket choose
#     s.bind((0, 0))
#     pid, groups = s.getsockname()
#
#     # random sequence for NETLINK access
#     seq = random.randint(0, pow(2, 31))
#
#     # netlink message header (struct nlmsghdr)
#     MSG_HEADER = struct.pack('IHHII', MSG_HEADER_LENGTH,
#                              MSG_HEADER_TYPE, MSG_HEADER_FLAGS, seq, pid)
#
#     # NETLINK message is always the same except header seq (struct ndmsg)
#     MSG = struct.pack('B', socket.AF_INET6)
#
#     # send message with header
#     s.send(MSG_HEADER + MSG)
#
#     # read all data from socket
#     answer = b''
#     while True:
#         r, w, e = select.select([s], [], [], 0.)
#         if s not in r:
#             break  # no more data
#         answer += s.recv(16384)
#
#     result = {}
#     curr_pos = 0
#     answer_pos = 0
#     answer_len = len(answer)
#
#     nlmsghdr_fmt = 'IHHII'  # struct nlmsghdr
#     nlattr_fmt = 'HH'  # struct nlattr
#     ndmsg_fmt = 'BBHiHBB'  # struct ndmsg
#
#     nlmsg_header_len = (struct.calcsize(nlmsghdr_fmt) + NLMSG_ALIGNTO - 1) & ~(NLMSG_ALIGNTO - 1)  # alignment to 4
#     nla_header_len = (struct.calcsize(nlattr_fmt) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)  # alignment to 4
#
#     # parse netlink answer to RTM_GETNEIGH
#     try:
#         while answer_pos < answer_len:
#             curr_pos = answer_pos
#             # if log.getEffectiveLevel() <= logging.DEBUG:
#             #    log.debug('nlm[%i:]: parsing up to %i...' % (answer_pos, answer_len))
#
#             nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = struct.unpack_from('<{}'.format(nlmsghdr_fmt),
#                                                                                           answer,
#                                                                                           answer_pos)
#
#             # basic safety checks for received data (imitates NLMSG_OK)
#             if nlmsg_len < struct.calcsize('<{}'.format(nlmsghdr_fmt)):
#                 log.warn('broken data from netlink (position {0}, nlmsg_len {1}): '
#                          'nlmsg_len is smaller than structure size'.format(answer_pos, nlmsg_len))
#                 break
#             if answer_len - answer_pos < struct.calcsize('<%s' % nlmsghdr_fmt):
#                 log.warn('broken data from netlink (position {0}, length avail %{1}): '
#                          'received data size is smaller than structure size'.format(answer_pos,
#                                                                                     answer_len - answer_pos))
#                 break
#             if answer_len - answer_pos < nlmsg_len:
#                 log.warn('broken data from netlink (position {0}, length avail {1}): '
#                          'received dcolonify_ata size is smaller than nlmsg_len'.format(answer_pos,
#                                                                                         answer_len - answer_pos))
#                 break
#             if pid != nlmsg_pid or seq != nlmsg_seq:
#                 log.warn('broken data from netlink (position {0}, length avail {1}): '
#                          'invalid seq ({2} x {3}) or pid ({4} x {5})'.format(answer_pos,
#                                                                              answer_len - answer_pos,
#                                                                              seq,
#                                                                              nlmsg_seq,
#                                                                              pid,
#                                                                              nlmsg_pid))
#                 break
#
#             # data for this Routing/device hook record
#             nlmsg_data = answer[answer_pos + nlmsg_header_len:answer_pos + nlmsg_len]
#             # if log.getEffectiveLevel() <= logging.DEBUG:
#             #    log.debug('nlm[%i:%i]%s: %s' % (answer_pos, answer_pos+nlmsg_len, \
#             #              str(struct.unpack_from('<%s' % nlmsghdr_fmt, answer, answer_pos)), \
#             #              binascii.b2a_hex(nlmsg_data)))
#
#             if nlmsg_type == NLMSG_DONE:
#                 break
#             if nlmsg_type == NLMSG_ERROR:
#                 nlmsgerr_error, nlmsgerr_len, nlmsgerr_type, nlmsgerr_flags, nlmsgerr_seq, nlmsgerr_pid = \
#                     struct.unpack_from('<sIHHII', nlmsg_data)
#                 log.warn('broken data from netlink (position {0}, length avail {1}): '
#                          'invalid message (errno {2})'.format(answer_pos,
#                                                               answer_len - answer_pos,
#                                                               nlmsgerr_error))
#                 break
#             if nlmsg_type not in [RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH]:
#                 log.warn('broken data from netlink (position {0}, length avail {1}): '
#                          'this is really weird, wrong message type {2}'.format(answer_pos,
#                                                                                answer_len - answer_pos,
#                                                                                nlmsg_type))
#                 break
#
#             curr_pos = answer_pos + nlmsg_header_len
#             ndm_family, ndm_pad1, ndm_pad2, ndm_ifindex, ndm_state, ndm_flags, ndm_type = \
#                 struct.unpack_from('<{}'.format(ndmsg_fmt), nlmsg_data, 0)
#             # if log.getEffectiveLevel() <= logging.DEBUG:
#             #    log.debug('nlm[%i:%i]: family %s, pad1 %s, pad2 %s, ifindex %s, state %s, flags %s, type %s' % \
#             #              (answer_pos, answer_pos+nlmsg_len, ndm_family, ndm_pad1, ndm_pad2, ndm_ifindex, ndm_state, ndm_flags, ndm_type))
#
#             nda = {
#                 'NDM_FAMILY': ndm_family, 'NDM_IFINDEX': ndm_ifindex,
#                 'NDM_STATE': ndm_state, 'NDM_FLAGS': ndm_flags,
#                 'NDM_TYPE': ndm_type}
#             nlmsg_data_pos = 0
#             nlmsg_data_len = nlmsg_len - nlmsg_header_len
#             while nlmsg_data_pos < nlmsg_data_len:
#                 curr_pos = answer_pos + nlmsg_header_len + nlmsg_data_pos
#                 # if log.getEffectiveLevel() <= logging.DEBUG:
#                 #    log.debug('nla[%i:]: parsing up to %i...' % (nlmsg_data_pos, nlmsg_data_len))
#
#                 nla_len, nla_type = \
#                     struct.unpack_from('<%s' % nlattr_fmt, nlmsg_data, nlmsg_data_pos)
#
#                 # basic safety checks for received data (imitates RTA_OK)
#                 if nla_len < struct.calcsize('<{}'.format(nlattr_fmt)):
#                     log.debug('This is normal for last record, but we should not get here (because of NLMSG_DONE); '
#                               'data size: {0}, data[{1}:{2}] =  {3}'.format(answer_len,
#                                                                             answer_pos + nlmsg_header_len,
#                                                                             answer_pos + nlmsg_len,
#                                                                             binascii.b2a_hex(nlmsg_data)))
#                     break
#
#                 # data for this Routing/device hook record attribute
#                 nla_data = nlmsg_data[nlmsg_data_pos + nla_header_len:nlmsg_data_pos + nla_len]
#                 # if log.getEffectiveLevel() <= logging.DEBUG:
#                 #    log.debug('nla[%i:]%s: %s' % (nlmsg_data_pos, \
#                 #              str(struct.unpack_from('<%s' % nlattr_fmt, nlmsg_data, nlmsg_data_pos)), \
#                 #              binascii.b2a_hex(nla_data)))
#
#                 nda_type_key = NDA.get(nla_type, str(nla_type))
#                 if nda_type_key == 'NDA_DST':
#                     nda[nda_type_key] = colonify_ip6(binascii.b2a_hex(nla_data))
#                 elif nda_type_key == 'NDA_LLADDR':
#                     nda[nda_type_key] = colonify_mac(binascii.b2a_hex(nla_data))
#                 elif nda_type_key == 'NDA_CACHEINFO':
#                     nda[nda_type_key] = struct.unpack_from('<IIII', nla_data)
#                 elif nda_type_key == 'NDA_VLAN':
#                     nda[nda_type_key] = binascii.b2a_hex(nla_data)
#                 else:
#                     nda[nda_type_key] = nla_data
#
#                 nlmsg_data_pos += nla_header_len
#                 nlmsg_data_pos += (nla_len - nla_header_len + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1)  # alignment to 4
#
#             # if log.getEffectiveLevel() <= logging.DEBUG:
#             #    log.debug('nlm[%i:%i]: %s' % (answer_pos, answer_pos+nlmsg_len, str(nda)))
#
#             # prepare all required data to be returned to callee
#             # * only care about configured devices
#             # * no need for multicast address cache entries (MAC 33:33:...)
#             if nda['NDM_STATE'] & ~(NUD_INCOMPLETE | NUD_FAILED | NUD_NOARP):
#                 if not nda['NDM_IFINDEX'] in if_number:
#                     log.debug("can't find device for interface index {}}".format(nda['NDM_IFINDEX']))
#                 elif not 'NDA_DST' in nda:
#                     log.warn("can't find destination address (wrong entry state: {}?!)".format(nda['NDM_STATE']))
#                 elif not 'NDA_LLADDR' in nda:
#                     log.warn("can't find local hardware address (wrong entry state: {}?!)".format(nda['NDM_STATE']))
#                 else:
#                     if if_number[nda['NDM_IFINDEX']] in cfg.INTERFACE and not nda['NDA_LLADDR'].startswith('33:33:'):
#                         # store neighbor caches entries
#                         record = NeighborCacheRecord(llip=decompress_ip6(nda['NDA_DST']),
#                                                      mac=nda['NDA_LLADDR'],
#                                                      interface=if_number[nda['NDM_IFINDEX']],
#                                                      now=now)
#                         result[record.llip] = record
#
#             # move to next record
#             answer_pos += nlmsg_len
#
#     except struct.error as e:
#         log.warn('broken data from netlink (position {0}, '
#                  'data[{1}:{2}] = {3}...): {4}'.format(answer_pos,
#                                                        curr_pos,
#                                                        answer_len,
#                                                        binascii.b2a_hex(answer[curr_pos:curr_pos + 8]),
#                                                        str(e)))
#
#     # clean up
#     s.close()
#
#     return result


def send_control_message(message):
    """
    Send a control message to the locally running dhcpy6d daemon
    """
    # clean message of quotations marks
    message = message.strip('"').encode('utf8')
    socket_control = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    socket_control.sendto(message, ('::1', 547))


def convert_mac_to_eui64(mac):
    """
    Convert a MAC address to a EUI64 address
    """
    # http://tools.ietf.org/html/rfc4291#section-2.5.1
    # only ':' come in MACs from get_neighbor_cache_linux()
    eui64 = mac.replace(':', '')
    eui64 = eui64[0:6] + 'fffe' + eui64[6:]
    eui64 = hex(int(eui64[0:2], 16) ^ 2)[2:].zfill(2) + eui64[2:]

    split_string = lambda x, n: [x[i:i + n] for i in range(0, len(x), n)]

    return ':'.join(split_string(eui64, 4))


def get_interfaces():
    """
    return dict full of Interface objects
    :return:
    """
    interfaces = {}
    for interface_tuple in socket.if_nameindex():
        interface = Interface(interface_tuple)
        interfaces[interface.name] = interface
    return interfaces


# def collect_macs(now):
#     """
#     collect MAC address from clients to link local addresses with MACs
#     if a client has a new MAC the LLIP changes - with privacy extension enabled anyway
#     calls local ip command to get neighbor cache - any more sophisticated idea is welcome!
#
#     The Linux netlink method is considered stable now.
#     """
#     try:
#         # Linux can use kernel neighbor cache
#         if OS == 'Linux':
#             for host in list(get_neighbor_cache_linux(IF_NUMBER, timer).values()):
#                 if not host.llip in collected_macs:
#                     if host.llip.startswith('fe80'):
#                         collected_macs[host.llip] = host
#                         if cfg.LOG_MAC_LLIP:
#                             log.info('Collected MAC %s for LinkLocalIP %s' % (host.mac, colonify_ip6(host.llip)))
#                         if cfg.CACHE_MAC_LLIP:
#                             volatile_store.store_mac_llip(host.mac, host.llip, timer)
#         else:
#             # subject to change - other distros might have other paths - might become a task
#             # for a setup routine to find appropriate paths
#             for host in subprocess.getoutput(NC[OS]['call']).splitlines():
#                 # get fragments of output line
#                 f = shlex.split(host)
#                 if f[NC[OS]['dev']] in cfg.INTERFACE and len(f) >= NC[OS]['len']:
#                     # get rid of %interface
#                     f[NC[OS]['llip']] = decompress_ip6(f[NC[OS]['llip']].split('%')[0])
#                     if f[NC[OS]['mac']] == '(incomplete)':
#                         continue
#                     # correct maybe shortened MAC
#                     f[NC[OS]['mac']] = correct_mac(f[NC[OS]['mac']])
#                     # put non yet existing LLIPs into dictionary - if they have MACs
#                     if not f[NC[OS]['llip']] in collected_macs and f[NC[OS]['llip']].lower().startswith('fe80') \
#                             and ':' in f[NC[OS]['mac']]:
#                         collected_macs[f[NC[OS]['llip']]] = NeighborCacheRecord(llip=f[NC[OS]['llip']],
#                                                                                 mac=f[NC[OS]['mac']],
#                                                                                 interface=f[NC[OS]['dev']],
#                                                                                 now=now)
#                         if cfg.LOG_MAC_LLIP:
#                             log.info('Collected MAC %s for LinkLocalIP %s' % (
#                                 f[NC[OS]['mac']], colonify_ip6(f[NC[OS]['llip']])))
#                         volatile_store.store_mac_llip(f[NC[OS]['mac']], f[NC[OS]['llip']], timer)
#     except Exception as err:
#         traceback.print_exc(file=sys.stdout)
#         sys.stdout.flush()
#         log.error('collect_macs(): ' + str(err))
