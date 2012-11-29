# encoding: utf8
#
# some little helping helpers
#

import binascii
import random
import sys
import shlex

# needed for neighor cache access
import socket
import struct
import binascii
import ctypes

# constants for GetNeighborCacheLinux()
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
                raise Exception('%s should consist only of : 0 1 2 3 4 5 6 7 8 9 a b c d e f' %s (ip6))
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
    return ":".join((address[0:4], address[4:8], address[8:12], address[12:16],\
                     address[16:20], address[20:24], address[24:28], address[28:32]))


def ErrorExit(message="An error occured.", status=1):
    """
    exit with given error message
    allow prefix, especially for spitting out section of configuration errors
    """
    print "\n", message, "\n"
    sys.exit(status)
    
    
def ListifyOption(option):
    """
    return any comma or space separated option as list
    """
    if option:
        lex = shlex.shlex(option)
        lex.whitespace = WHITESPACE
        lex.wordchars += ":."
        return list(lex)
    else:
        return None

    
def GetNeighborCacheLinux(cfg, IF_NAME, IF_NUMBER, LIBC):
    """
    get neighbor cache on Linux via NETLINK interface
    Pymnl available at http://pypi.python.org/pypi/pymnl/ helped a lot to
    find out how to get neighbor cache
    
    # DOES NOT WQORK RELIABLY :-(
    
    """
    # result
    #result = list()
    result = dict()
    
    # open raw NETLINK socket
    # NETLINK_ROUTE has neighbor cache information too
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    # PID 0 means AUTOPID, let socket choose
    s.bind((0, 0))
    pid, groups = s.getsockname()

    # random sequence for NETLINK access
    MSG_HEADER_SEQ = random.randint(0, pow(2,31))

    MSG_HEADER = struct.pack("IHHII",\
                             MSG_HEADER_LENGTH,
                             MSG_HEADER_TYPE,\
                             MSG_HEADER_FLAGS,\
                             MSG_HEADER_SEQ, pid)
    
    # send message with header
    s.send(MSG_HEADER + MSG)

    # use a large buffer for answer message
    answer = s.recv(65536) 
    
    # convert answer to ascii
    # might be more efficient with some struct.unpack()
    # but still faster than external call
    answer = binascii.b2a_hex(answer)
    
    # split answer without header by "0a000000" because it
    # separates different cache entries
    for l in answer[32:].split("0a000000")[1:]:
        # because we need at least the first 76 bytes the answer has to be
        # at least that long - it varies 
        if len(l) >= 76:
            interface = int(l[0:2])
            # only care about configured devices
            for i in cfg.INTERFACE:
                if IF_NAME[i] == interface:  
                    # /include/linux/neighbour.h defines NTF_ROUTER as 0x80
                    # but routers etc. not needed here
                    if l[12:14] == "00":
                        mac = l[64:76]
                        # no need for multicast address cache entries
                        if not mac.startswith("3333"):
                            # get Link Local IP
                            llip = l[24:56]
                            # only care about configured device
                            if IF_NAME[i] == interface:                   
                                #result.append({"interface": IF_NUMBER[interface],\
                                #               "llip" : ColonifyIP6(llip),\
                                #               "mac" : ColonifyMAC(mac)})
                                result["|".join((IF_NUMBER[interface],\
                                                 ColonifyIP6(llip),\
                                                 ColonifyMAC(mac)))] = [IF_NUMBER[interface],\
                                                                       ColonifyIP6(llip),\
                                                                       ColonifyMAC(mac)]
    # clean up 
    s.close()                    

    return result
