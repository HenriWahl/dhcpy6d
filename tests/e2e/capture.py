"""Capture wire evidence independently of DHCPy6d's packet parser."""
import json
from pathlib import Path
import sys
import time
from scapy.all import IPv6, UDP, PcapWriter, sniff

root = Path(sys.argv[1])
writer = PcapWriter(str(root / 'packets.pcap'), sync=True)
stream = (root / 'packets.jsonl').open('a', buffering=1)

def record(packet):
    if IPv6 not in packet or UDP not in packet:
        return
    if packet[UDP].sport not in (546, 547) and packet[UDP].dport not in (546, 547):
        return
    payload = bytes(packet[UDP].payload)
    if not payload:
        return
    writer.write(packet)
    stream.write(json.dumps({'time': time.monotonic(), 'src': packet[IPv6].src,
        'dst': packet[IPv6].dst, 'sport': packet[UDP].sport,
        'dport': packet[UDP].dport, 'hex': payload.hex(), 'type': payload[0]}) + '\n')

sniff(iface='srv', prn=record, store=False, started_callback=lambda: (root / 'capture.ready').touch())
