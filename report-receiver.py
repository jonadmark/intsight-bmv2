#!/usr/bin/env python
from __future__ import print_function

import os
import sys
import struct
import threading
import time
from datetime import datetime

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import ShortField, IntField, BitField
from scapy.all import IP, TCP, UDP, Raw
from scapy.all import bind_layers


class IntSight_Report(Packet):
    name = "IntSight_Report"
    fields_desc = [
        IntField("epoch", 0),
        IntField("flow_ID", 0),
        BitField("path_src", 0,  10),
        BitField("path_length", 0,  6),
        ShortField("path_code", 0),
        BitField("contention_points", 0, 48),
        ShortField("path_dst", 0),
        IntField("high_delays", 0),
        IntField("drops", 0),
        IntField("ingress_packets", 0),
        IntField("ingress_bytes", 0),
        IntField("egress_packets", 0),
        IntField("egress_bytes", 0)
    ]

    def __repr__(self):
        out = ''
        out += '[{:2d}:{:2d}] '.format(self.epoch, self.flow_ID)
        fmt = '{{:0{}b}}'.format(self.path_length)
        cps = fmt.format(self.contention_points)[::-1]
        cps = cps.replace('0', '-')
        cps = cps.replace('1', '^')
        out += '({:1d} => {:1d}, p={:d}, len={:d}, cps={:>5}) '.format(
            self.path_src, self.path_dst, self.path_code, self.path_length, cps
        )
        out += 'hd={:03d} '.format(self.high_delays)
        out += 'pkts={:04d}=>{:04d}({:03d}) bits={:08d}=>{:08d}' \
            .format(
                self.ingress_packets,
                self.egress_packets,
                self.drops,
                self.ingress_bytes*8,
                self.egress_bytes*8,
            )
        return out
    
    def csv(self):
        out = ''
        out += '{:d},{:d},'.format(self.epoch, self.flow_ID)
        fmt = '{{:0{}b}}'.format(self.path_length)
        cps = fmt.format(self.contention_points)[::-1]
        cps = cps.replace('0', '-')
        cps = cps.replace('1', '^')
        out += '{:d},{:d},{:d},{:d},{},'.format(
            self.path_src, self.path_dst, self.path_code, self.path_length, cps
        )
        out += '{:03d},'.format(self.high_delays)
        out += '{:d},{:d},{:d},{:d},{:d}' \
            .format(
                self.ingress_packets,
                self.egress_packets,
                self.drops,
                self.ingress_bytes,
                self.egress_bytes,
            )
        return out


class PacketSniffer(threading.Thread):
    def __init__(self, interface):
        threading.Thread.__init__(self)
        self.interface = interface
        self.log_filename = 'logs/{}-reports'.format(interface.split('-')[0])
        with open(self.log_filename + '.txt', 'w') as f:
            f.write('# IntSight report packet log for interface {}.\n' \
                    .format(self.interface))
        with open(self.log_filename + '.csv', 'w') as f:
            f.write('epoch,flow,psrc,pdst,path,plen,cps,hds,' \
                    'ipkts,epkts,drops,ibytes,ebytes\n')
    
    def log_packet(self, pkt):
        if IntSight_Report in pkt:
            with open(self.log_filename + '.txt', 'a') as f:
                f.write('{}\n'.format(repr(pkt[IntSight_Report])))
            with open(self.log_filename + '.csv', 'a') as f:
                f.write('{}\n'.format(pkt[IntSight_Report].csv()))

    def run(self):
        sys.stdout.flush()
        print('Sniffing interface {}'.format(self.interface))
        sniff(iface=self.interface, prn=lambda x: self.log_packet(x))


def main(n_nodes=5, username=None):
    bind_layers(IP, IntSight_Report, proto=224)
    
    print('Creating sniffer threads.')
    sniffers = []
    for i in range(n_nodes):
        sniffers.append(PacketSniffer('s{}-eth3'.format(i + 1)))
    print('Starting the sniffer threads.')
    for s in sniffers:
        s.start()
    
    # print('Waiting to finish.', end='')
    stop_flag = 0
    while stop_flag == 0:
        with open('/tmp/intsight_flag') as f:
            stop_flag = int(f.read())
        if stop_flag == 0:
            # print('.', end='')
            # sys.stdout.flush()
            time.sleep(2)
    # print('IntSight Receiver: Bye')

    if username is not None:
        os.system('chown -R {}: .'.format(username))

    os._exit(0)

    # print("sniffing on {}".format(iface))
    # sys.stdout.flush()
    # with open(log_filename, 'w') as lf:
    #     sniff(iface = iface, prn = lambda x: handle_pkt(x, lf))


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: report-receiver.py <n_nodes> <username>')
    main(n_nodes=int(sys.argv[1]), username=sys.argv[2])
