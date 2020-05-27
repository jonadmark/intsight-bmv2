#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import string
import math
import os

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.utils import wrpcap
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, UDP


def main():
    print('Building random string', end='...', flush=True)
    letters = string.ascii_letters + string.digits
    lorem = ''.join(random.choice(letters) for i in range(int(1e6)))
    print('done', flush=True)

    seconds = 10
    msglen = 1430
    hdslen = 42

    os.makedirs('../../../resources/workloads/bandwidth', exist_ok=True)

    print('Generating traffic for RED flow (h1-h14)')
    rate = int(math.ceil(50e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.1.1', dst='10.0.7.14') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/red.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for BLUE flow (h7-h11)')
    rate = int(math.ceil(50e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.4.7', dst='10.0.6.11') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/blue.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for TEAL flow (h2-h9)')
    rate = int(math.ceil(50e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.1.2', dst='10.0.5.9') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/teal.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for GREEN flow (h5-h9)')
    rate = int(math.ceil(50e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.3.5', dst='10.0.5.9') / \
            UDP(sport=1235, dport=1235) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/green.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for ORANGE flow (h5-h13)')
    rate = int(math.ceil(50e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.3.5', dst='10.0.7.13') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/orange.pcp', pkts)
    print('done', flush=True)


if __name__ == '__main__':
    main()
