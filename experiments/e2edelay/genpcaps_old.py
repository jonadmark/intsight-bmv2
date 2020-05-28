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
from scapy.all import Ether, IP, UDP, TCP


def main():
    print('Building random string', end='...', flush=True)
    letters = string.ascii_letters + string.digits
    lorem = ''.join(random.choice(letters) for i in range(int(1e6)))
    print('done', flush=True)

    seconds = 10
    msglen = 1430
    hdslen = 42

    os.makedirs('../../../resources/workloads/e2edelay', exist_ok=True)

    print('Generating traffic for RED flow (h1-h10)')
    rate = int(math.ceil(15e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.1.1', dst='10.0.5.10') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/e2edelay/red.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for BLUE flow (h2-h3)')
    rate = int(math.ceil(15e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.1.2', dst='10.0.2.3') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/e2edelay/blue.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for TEAL flow (h4-h7)')
    rate = int(math.ceil(15e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.2.4', dst='10.0.4.7') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/e2edelay/teal.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for GREEN flow (h6-h7)')
    rate = int(math.ceil(15e6/8.0/(msglen)))
    pkts = []
    for i in range(rate*seconds):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.3.6', dst='10.0.4.7') / \
            UDP(sport=1235, dport=1235) / lorem[beg:beg+msglen]
        pkt.time = (1.0/rate)*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/e2edelay/green.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for ORANGE flow (h6-h9)')
    pkts = []
    burstsize = 10000
    for i in range(burstsize):
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src='10.0.3.6', dst='10.0.5.9') / \
            UDP(sport=1234, dport=1234) / lorem[beg:beg+msglen]
        pkt.time = 5.0 + 0.0001*i
        pkts.append(pkt)
        if i%100 == 0:
            print(i, end='', flush=True)
        elif i%10 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/e2edelay/orange.pcp', pkts)
    print('done', flush=True)


if __name__ == '__main__':
    main()
