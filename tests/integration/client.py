"""A real UDP DHCPv6 client with deterministic transaction and interface scope."""
import ipaddress
import json
import socket
import struct
import sys


def option(code, value):
    return struct.pack('!HH', code, len(value)) + value


def options(data):
    while data:
        code, length = struct.unpack('!HH', data[:4])
        yield code, data[4:4 + length]
        data = data[4 + length:]


index = socket.if_nametoindex('eth0')
sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
sock.settimeout(3)
sock.bind(('fe80::2', 546, 0, index))
duid = bytes.fromhex('00030001' + sys.argv[1].replace(':', ''))
# Identical address AND transaction ID deliberately collide on different links.
packet = b'\x01\x12\x34\x56' + option(1, duid) + option(3, struct.pack('!III', 1, 0, 0)) + option(14, b'')
for attempt in range(8):
    sock.sendto(packet, ('ff02::1:2', 547, 0, index))
    try:
        response, sender = sock.recvfrom(65535)
    except socket.timeout:
        continue
    if response[:4] != b'\x07\x12\x34\x56':
        continue
    opts = dict(options(response[4:]))
    if opts.get(1) != duid:
        raise AssertionError('Reply contains the other interface client identity')
    addresses = [str(ipaddress.IPv6Address(value[:16]))
                 for code, value in options(opts.get(3, b'')[12:]) if code == 5]
    if addresses:
        print(json.dumps({'duid': duid.hex(), 'addresses': addresses, 'sender': sender[0]}))
        break
else:
    raise AssertionError('No successful address Reply after repeated solicitations')
