#!/usr/bin/env python3
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


def Yred(x):
    return 30

def Yblue(x):
    return 30

def Yteal(x):
    if x < 10 or x > 50:
        return 20
    return -5*math.cos((x - 10)*math.pi*2/40) + 20 + 5

def Ygreen(x):
    if x < 15 or x > 45:
        return 15
    return -7.5*math.cos((x - 15)*math.pi*2/30) + 15 + 7.5

def Yorange(x):
    if x < 20 or x > 40:
        return 10
    return -10*math.cos((x - 20)*math.pi*2/20) + 10 + 10


def gen_pkts(src_addr, dst_addr, src_port, dst_port, yfunc, lorem, seconds, msglen, hdslen, add_noise=True):
    random.seed(42)
    x = 0
    i = 0
    pkts = []
    while (x < 60.0):
        # build packet
        beg = random.randint(0, 1e6 - msglen - 1)
        pkt = Ether() / IP(src=src_addr, dst=dst_addr) / \
            UDP(sport=src_port, dport=dst_port) / lorem[beg:beg+msglen]
        pkt.time = x
        pkts.append(pkt)
        # calculate arrival time for next packet
        delay = 1.0/((yfunc(x)*1e6)/(8*(hdslen + msglen)))
        if add_noise is True:
            noise = random.gauss(1, 0.1)
        else:
            noise = 1.0
        x = x + noise*delay
        # count pkts
        i = i + 1
        if i%1000 == 0:
            print(i, end='', flush=True)
        elif i%100 == 0:
            print(end='.', flush=True)
    print('done', flush=True)
    return pkts

def main():
    print('Building random string', end='...', flush=True)
    letters = string.ascii_letters + string.digits
    lorem = ''.join(random.choice(letters) for i in range(int(1e6)))
    print('done', flush=True)

    seconds = 60.0
    maxframesize = 1518 - 4  # Frame Check Sequence
    hdslen = 14 + 20 + 8  # Eth + IPv4 + UDP
    tellen = 33  # IntSight
    msglen = maxframesize - hdslen - tellen

    os.makedirs('../../../resources/workloads/bandwidth', exist_ok=True)

    print('Generating traffic for RED flow (h1-h14)')
    pkts = gen_pkts('10.0.1.1', '10.0.7.14', 1234, 1234, Yred, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/red.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for BLUE flow (h7-h11)')
    pkts = gen_pkts('10.0.4.7', '10.0.6.11', 1234, 1234, Yblue, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/blue.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for TEAL flow (h2-h9)')
    pkts = gen_pkts('10.0.1.2', '10.0.5.9', 1234, 1234, Yteal, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/teal.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for GREEN flow (h5-h9)')
    pkts = gen_pkts('10.0.3.5', '10.0.5.9', 1235, 1235, Ygreen, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/green.pcp', pkts)
    print('done', flush=True)

    print('Generating traffic for ORANGE flow (h6-h13)')
    pkts = gen_pkts('10.0.3.6', '10.0.7.13', 1234, 1234, Yorange, lorem, seconds, msglen, hdslen)
    print('Writting traffic to pcap file', end='...', flush=True)
    wrpcap('../../../resources/workloads/bandwidth/orange.pcp', pkts)
    print('done', flush=True)


if __name__ == '__main__':
    main()
