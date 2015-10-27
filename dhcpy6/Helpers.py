# encoding: utf8
#
# DHCPy6d DHCPv6 Daemon
#
# Copyright (C) 2009-2015 Henri Wahl <h.wahl@ifw-dresden.de>
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
import random
import sys
import shlex
import logging


# needed for neighbor cache access
import select
import socket
import struct
import binascii
import ctypes
import platform
import time

# used for NETLINK in GetNeighborCacheLinux() access by Github/vokac
RTM_NEWNEIGH = 28
RTM_DELNEIGH = 29
RTM_GETNEIGH = 30
NLM_F_REQUEST = 1
# Modifiers to GET request
NLM_F_ROOT = 0x100
NLM_F_MATCH = 0x200
NLM_F_DUMP = (NLM_F_ROOT | NLM_F_MATCH)
# NETLINK message is alsways the same except header seq
MSG = struct.pack("B", socket.AF_INET6)
# always the same length...
MSG_HEADER_LENGTH = 17
# ...type...
MSG_HEADER_TYPE = RTM_GETNEIGH
# ...flags.
MSG_HEADER_FLAGS = (NLM_F_REQUEST | NLM_F_DUMP)
# state of peer
NUD_REACHABLE = 2
NLMSG_NOOP             = 0x1     #/* Nothing.             */
NLMSG_ERROR            = 0x2     #/* Error                */
NLMSG_DONE             = 0x3     #/* End of a dump        */
NLMSG_OVERRUN          = 0x4     #/* Data lost            */

NUD_INCOMPLETE  = 0x01
NUD_REACHABLE   = 0x02
NUD_STALE       = 0x04
NUD_DELAY       = 0x08
NUD_PROBE       = 0x10
NUD_FAILED      = 0x20
NUD_NOARP       = 0x40
NUD_PERMANENT   = 0x80
NUD_NONE        = 0x00

NDA = {
  0: 'NDA_UNSPEC',
  1: 'NDA_DST',
  2: 'NDA_LLADDR',
  3: 'NDA_CACHEINFO',
  4: 'NDA_PROBES',
  5: 'NDA_VLAN',
  6: 'NDA_PORT',
  7: 'NDA_VNI',
  8: 'NDA_IFINDEX',
}
NLMSG_ALIGNTO = 4
NLA_ALIGNTO = 4

# whitespace for options with more than one value
WHITESPACE = " ,"


def ConvertDNS2Binary(name):
    """
        convert domain name as described in RFC 1035, 3.1
    """
    binary = ""
    domain_parts = name.split(".")
    for p in domain_parts:
        binary += "%02x" % (len(p))     # length of Domain Name Segements
        binary += binascii.b2a_hex(p)
    # final zero size octet following RFC 1035
    binary += "00"
    return binary


def ConvertBinary2DNS(binary):
    """
        convert domain name from hex like in RFC 1035, 3.1
    """
    name = ""
    binary_parts = binary
    while len(binary_parts) > 0:
        # RFC 1035 - domain names are sequences of labels separated by length octets
        length = int(binary_parts[0:2], 16)
        # lenght*2 because 2 charse represent a byte
        label = binascii.a2b_hex(binary_parts[2:2+length*2])
        binary_parts = binary_parts[2+length*2:]
        name += label
        # insert "." if this is not the last label of FQDN
        # >2 because last byte is the zero byte terminator
        if len(binary_parts) > 2:
            name += "."
    return str(name)


def BuildOption(number, payload):
    """
        glue option with payload
    """
    # option number and length take 2 byte each so the string has to be 4 chars long
    option = "%04x" % (number)          # option number
    option += "%04x" % (len(payload)/2) # payload length, /2 because 2 chars are 1 byte
    option += payload  
    return option
    
    
def CorrectMAC(mac):
    """
        OpenBSD shortens MAC addresses in ndp output - here they grow again
    """
    decompressed = map(lambda m: "%02x" % (int(m, 16)), mac.split(":")) 
    return ":".join(decompressed)


def ColonifyMAC(mac):
    """
        return complete MAC address with colons
    """
    return ":".join((mac[0:2], mac[2:4], mac[4:6],\
                     mac[6:8], mac[8:10], mac[10:12]))


def DecompressIP6(ip6, strict=True):
    """
        decompresses shortened IPv6 address and returns it as ":"-less 32 character string
        additionally allows testing for prototype address with less strict set of allowed characters
    """
    # if in strict mode there are no hex numbers and ":" something is wrong
    if strict == True:
        for c in ip6.lower():
            #if not c in [":", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"]:
            if not c in ":0123456789abcdef":
                raise Exception('%s should consist only of : 0 1 2 3 4 5 6 7 8 9 a b c d e f' % (ip6))
                #return None
    else:
        # used for comparison of leases with address pattern - X replace the dynamic part of the address
        for c in ip6.lower():
            #if not c in [":", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f", "x"]:
            if not c in ":0123456789abcdefx":
                raise Exception('%s should consist only of : 0 1 2 3 4 5 6 7 8 9 a b c d e f x' % (ip6))
                #return None          
    # nothing to do
    if len(ip6) == 32 and ip6.count(":") == 0:
        return ip6

    # larger heaps of :: smell like something wrong
    if ip6.count("::") > 1 or ip6.count(":::") >= 1:
        raise Exception('%s has too many accumulated ":"' % (ip6))      
    
    # less than 7 ":" but no "::" also make a bad impression 
    if ip6.count(":") < 7 and ip6.count("::") <> 1:
        raise Exception('%s is missing some ":"' % (ip6))       
    
    # replace :: with :0000:: - the last ":" will be cut of finally 
    while ip6.count(":") < 8 and ip6.count("::") == 1:
        ip6 = ip6.replace("::", ":0000::")
    # remaining ":" will be cut off
    ip6 = ip6.replace("::", ":")

    # ":" at the beginning have to be filled up with 0000 too
    if ip6.startswith(":"):
        ip6 = "0000" + ip6

    # if a segment is shorter than 4 chars the gaps get filled with zeros
    ip6_segments_source = ip6.split(":")
    ip6_segments_target = list()
    for s in ip6_segments_source:
        while len(s) < 4:
            s = "0" + s
        if len(s) > 4:
            raise Exception
        ip6_segments_target.append(s)

    # return with separator (mostly "")
    return "".join(ip6_segments_target)
               

def ColonifyIP6(address):
    """
        return complete IPv6 address with colons
    """
    if address:
        return ":".join((address[0:4], address[4:8], address[8:12], address[12:16],\
                        address[16:20], address[20:24], address[24:28], address[28:32]))
    else:
        return "N/A"


def ErrorExit(message="An error occured.", status=1):
    """
        exit with given error message
        allow prefix, especially for spitting out section of configuration errors
    """
    sys.stderr.write("\n%s\n\n" % (message))
    sys.exit(status)
    
    
def ListifyOption(option):
    """
        return any comma or space separated option as list
    """
    if option:
        lex = shlex.shlex(option)
        lex.whitespace = WHITESPACE
        lex.wordchars += ":.-"
        return list(lex)
    else:
        return None


class NeighborCacheRecord(object):
    """
        object for neighbor cache entries to be returned by GetNeighborCacheLinux() and in CollectedMACs
        .interface is only interesting for real neighbor cache records, to be ignored for collected MACs stored in DB
    """
    def __init__(self, llip="", mac="", interface=""):
        self.llip = llip
        self.mac = mac
        self.interface = interface
        self.timestamp = time.time()


def GetNeighborCacheLinux(cfg, IF_NUMBER, log):
    """
        imported version of https://github.com/vokac/dhcpy6d
        https://github.com/vokac/dhcpy6d/commit/bd34d3efb18ba6016a2b3afea0b6a3fcdfb524a4
        Thanks for donating!
    """
    # result
    result = dict()

    # open raw NETLINK socket
    # NETLINK_ROUTE has neighbor cache information too
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    # PID 0 means AUTOPID, let socket choose
    s.bind((0, 0))
    pid, groups = s.getsockname()

    # random sequence for NETLINK access
    seq = random.randint(0, pow(2,31))

    # netlink message header (struct nlmsghdr)
    MSG_HEADER = struct.pack("IHHII", MSG_HEADER_LENGTH,
            MSG_HEADER_TYPE, MSG_HEADER_FLAGS, seq, pid)

    # NETLINK message is always the same except header seq (struct ndmsg)
    MSG = struct.pack("B", socket.AF_INET6)

    # send message with header
    s.send(MSG_HEADER + MSG)

    # read all data from socket
    answer = ''
    while True:
        r,w,e = select.select([s], [], [], 0.)
        if s not in r: break # no more data
        answer += s.recv(16384)

    result = {}
    curr_pos = 0
    answer_pos = 0
    answer_len = len(answer)

    nlmsghdr_fmt = 'IHHII' # struct nlmsghdr
    nlattr_fmt = 'HH' # struct nlattr
    ndmsg_fmt = 'BBHiHBB' # struct ndmsg

    nlmsg_header_len = (struct.calcsize(nlmsghdr_fmt)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) # alignment to 4
    nla_header_len = (struct.calcsize(nlattr_fmt)+NLA_ALIGNTO-1) & ~(NLA_ALIGNTO-1) # alignment to 4

    # parse netlink answer to RTM_GETNEIGH
    try:
        while answer_pos < answer_len:
            curr_pos = answer_pos
            if log.getEffectiveLevel() <= logging.DEBUG:
                log.debug("nlm[%i:]: parsing up to %i..." % (answer_pos, answer_len))

            nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid = \
                    struct.unpack_from("<%s" % nlmsghdr_fmt, answer, answer_pos)

            # basic safety checks for received data (imitates NLMSG_OK)
            if nlmsg_len < struct.calcsize("<%s" % nlmsghdr_fmt):
                log.warn("broken data from netlink (position %i, nlmsg_len %i): "\
                         "nlmsg_len is smaler then structure size" % (answer_pos, nlmsg_len))
                break
            if answer_len-answer_pos < struct.calcsize("<%s" % nlmsghdr_fmt):
                log.warn("broken data from netlink (position %i, length avail %i): "\
                         "received data size is smaler then structure size" % \
                         (answer_pos, answer_len-answer_pos))
                break
            if answer_len-answer_pos < nlmsg_len:
                log.warn("broken data from netlink (position %i, length avail %i): "\
                         "received data size is smaller then nlmsg_len" % \
                         (answer_pos, answer_len-answer_pos))
                break
            if (pid != nlmsg_pid or seq != nlmsg_seq):
                log.warn("broken data from netlink (position %i, length avail %i): "\
                         "invalid seq (%s x %s) or pid (%s x %s)" % \
                         (answer_pos, answer_len-answer_pos, seq, nlmsg_seq, pid, nlmsg_pid))
                break

            # data for this Routing/device hook record
            nlmsg_data = answer[answer_pos+nlmsg_header_len:answer_pos+nlmsg_len]
            if log.getEffectiveLevel() <= logging.DEBUG:
                log.debug("nlm[%i:%i]%s: %s" % (answer_pos, answer_pos+nlmsg_len, \
                          str(struct.unpack_from("<%s" % nlmsghdr_fmt, answer, answer_pos)), \
                          binascii.b2a_hex(nlmsg_data)))

            if nlmsg_type == NLMSG_DONE:
                break
            if nlmsg_type == NLMSG_ERROR:
                nlmsgerr_error, nlmsgerr_len, nlmsgerr_type, nlmsgerr_flags, nlmsgerr_seq, nlmsgerr_pid = \
                        struct.unpack_from("<sIHHII", nlmsg_data)
                log.warn("broken data from netlink (position %i, length avail %i): "\
                         "invalid message (errno %i)" % (answer_pos, \
                         answer_len-answer_pos, nlmsgerr_error))
                break
            if nlmsg_type not in [ RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH ]:
                log.warn("broken data from netlink (position %i, length avail %i): "\
                         "this is realy wierd, wrong message type %i" % \
                         (answer_pos, answer_len-answer_pos, nlmsg_type))
                break

            curr_pos = answer_pos+nlmsg_header_len
            ndm_family, ndm_pad1, ndm_pad2, ndm_ifindex, ndm_state, ndm_flags, ndm_type = \
                    struct.unpack_from("<%s" % ndmsg_fmt, nlmsg_data, 0)
            if log.getEffectiveLevel() <= logging.DEBUG:
                log.debug("nlm[%i:%i]: family %s, pad1 %s, pad2 %s, ifindex %s, state %s, flags %s, type %s" % \
                          (answer_pos, answer_pos+nlmsg_len, ndm_family, ndm_pad1, ndm_pad2, ndm_ifindex, ndm_state, ndm_flags, ndm_type))

            nda = {
                'NDM_FAMILY' : ndm_family, 'NDM_IFINDEX': ndm_ifindex,
                'NDM_STATE': ndm_state, 'NDM_FLAGS': ndm_flags,
                'NDM_TYPE': ndm_type }
            nlmsg_data_pos = 0
            nlmsg_data_len = nlmsg_len-nlmsg_header_len
            while nlmsg_data_pos < nlmsg_data_len:
                curr_pos = answer_pos+nlmsg_header_len+nlmsg_data_pos
                if log.getEffectiveLevel() <= logging.DEBUG:
                    log.debug("nla[%i:]: parsing up to %i..." % (nlmsg_data_pos, nlmsg_data_len))

                nla_len, nla_type = \
                        struct.unpack_from("<%s" % nlattr_fmt, nlmsg_data, nlmsg_data_pos)

                # basic safety checks for received data (imitates RTA_OK)
                if nla_len < struct.calcsize("<%s" % nlattr_fmt):
                    log.debug("This is normal for last record, but we should not get here "\
                              "(because of NLMSG_DONE); data size: %i, data[%i:%i] = %s" % \
                              (answer_len, answer_pos+nlmsg_header_len, \
                               answer_pos+nlmsg_len, binascii.b2a_hex(nlmsg_data)))
                    break

                # data for this Routing/device hook record attribute
                nla_data = nlmsg_data[nlmsg_data_pos+nla_header_len:nlmsg_data_pos+nla_len]
                if log.getEffectiveLevel() <= logging.DEBUG:
                    log.debug("nla[%i:]%s: %s" % (nlmsg_data_pos, \
                              str(struct.unpack_from("<%s" % nlattr_fmt, nlmsg_data, nlmsg_data_pos)), \
                              binascii.b2a_hex(nla_data)))

                nda_type_key = NDA.get(nla_type, str(nla_type))
                if nda_type_key == 'NDA_DST':
                    nda[nda_type_key] = ColonifyIP6(binascii.b2a_hex(nla_data))
                elif nda_type_key == 'NDA_LLADDR':
                    nda[nda_type_key] = ColonifyMAC(binascii.b2a_hex(nla_data))
                elif nda_type_key == 'NDA_CACHEINFO':
                    nda[nda_type_key] = struct.unpack_from("<IIII", nla_data)
                elif nda_type_key == 'NDA_VLAN':
                    nda[nda_type_key] = binascii.b2a_hex(nla_data)
                else:
                    nda[nda_type_key] = nla_data

                nlmsg_data_pos += nla_header_len
                nlmsg_data_pos += (nla_len-nla_header_len+NLA_ALIGNTO-1) & ~(NLA_ALIGNTO-1) # alginment to 4

            if log.getEffectiveLevel() <= logging.DEBUG:
                log.debug("nlm[%i:%i]: %s" % (answer_pos, answer_pos+nlmsg_len, str(nda)))

            # prepare all required data to be returned to callee
            # * only care about configured devices
            # * no need for multicast address cache entries (MAC 33:33:...)
            #log.debug("TEST %s -> %s, state = %s, %s %s" % (nda.get('NDM_IFINDEX'), IF_NUMBER.get(nda.get('NDM_IFINDEX', '')), ndm_state, nda.get('NDA_DST'), nda.get('NDA_LLADDR')))
            if nda['NDM_STATE'] & ~(NUD_INCOMPLETE|NUD_FAILED|NUD_NOARP):
                if not IF_NUMBER.has_key(nda['NDM_IFINDEX']):
                    log.debug("can't find device for interface index %i" % nda['NDM_IFINDEX'])
                elif not nda.has_key('NDA_DST'):
                    log.warn("can't find destination address (wrong entry state: %i?!)" % nda['NDM_STATE'])
                elif not nda.has_key('NDA_LLADDR'):
                    log.warn("can't find local hardware address (wrong entry state: %i?!)" % nda['NDM_STATE'])
                else:
                    if IF_NUMBER[nda['NDM_IFINDEX']] in cfg.INTERFACE and not nda['NDA_LLADDR'].startswith('33:33:'):
                        # store neighbor caches entries
                        record = NeighborCacheRecord(llip=DecompressIP6(nda['NDA_DST']),
                                                     mac=nda['NDA_LLADDR'],
                                                     interface=IF_NUMBER[nda['NDM_IFINDEX']])
                        result[str(record.llip)] = record

            # move to next record
            answer_pos += nlmsg_len

    except struct.error, e:
        log.warn("broken data from netlink (position %i, data[%i:%i] = %s...): %s" % \
                 (answer_pos, curr_pos, answer_len, \
                  binascii.b2a_hex(answer[curr_pos:curr_pos+8]), str(e)))

    # clean up
    s.close()

    return result


def GetLibC():
    """
        return libC-object to be used for NIC handling in dhcpy6d and Config.py
        first get the library to connect to - OS-dependent
    """
    OS = platform.system()
    if OS == "Linux":
        libc_name = "libc.so.6"
    elif "BSD" in OS:
        # libc_ver() returns version number of libc that is hardcoded in
        # libc file name
        libc_name = "libc.so." + platform.libc_ver()[1]
    elif OS == "Darwin":
        libc_name = "libc.dylib"
    else:
        print "\n OS not yet supported. :-( \n"
        sys.exit(1)
    # use ctypes for libc access
    return ctypes.cdll.LoadLibrary(libc_name)
