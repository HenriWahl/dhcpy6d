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

from binascii import (hexlify,
                      unhexlify)
import shlex
import socket
import sys

# whitespace for options with more than one value
WHITESPACE = ' ,'

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
    for domain_part in domain_parts:
        binary += f'{len(domain_part):02x}'  # length of Domain Name Segments
        binary += hexlify(domain_part.encode()).decode()
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
        label = unhexlify(binary_parts[2:2 + length * 2]).decode()
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
    option = f'{number:04x}'  # option number
    option += f'{len(payload) // 2:04x}'  # payload length, /2 because 2 chars are 1 byte
    option += payload
    return option


def correct_mac(mac):
    """
    OpenBSD shortens MAC addresses in ndp output - here they grow again
    """
    decompressed = [f'{(int(m, 16)):02x}' for m in mac.split(':')]
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
                raise Exception(f'{ip6} should consist only of : 0 1 2 3 4 5 6 7 8 9 a b c d e f')
    else:
        # used for comparison of leases with address pattern - X replace the dynamic part of the address
        for c in ip6:
            if c not in ADDRESS_CHARS_NON_STRICT:
                raise Exception(f'{ip6} should consist only of : 0 1 2 3 4 5 6 7 8 9 a b c d e f x')
    # nothing to do
    if len(ip6) == 32 and colon_count1 == 0:
        return ip6

    # larger heaps of :: smell like something wrong
    if colon_count2 > 1 or colon_count3 >= 1:
        raise Exception(f"{ip6} has too many accumulated ':'")

    # less than 7 ':' but no '::' also make a bad impression
    if colon_count1 < 7 and colon_count2 != 1:
        raise Exception(f"{ip6} is missing some ':'")

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
            raise Exception(f"{ip6} has segment with more than 4 digits")
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
        # return 'n/a'
        # provoke crash to see what happens with un-addresses
        return False


def combine_prefix_length(prefix, length):
    """
    add prefix and length to 'prefix/length' string
    """
    return f'{prefix}/{length}'


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
    sys.stderr.write(f'\n{message}\n\n')
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
