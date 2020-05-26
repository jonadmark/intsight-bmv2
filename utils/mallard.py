from __future__ import print_function

import json
import os
import sys
# import subprocess
import time


def run_workload(mn, wf):

    mn.pingAll()

    with open(wf) as f:
        workload = json.load(f)

    # start servers
    print('Starting iperf3 servers')
    if 'iperf3' in workload:
        for t in workload['iperf3']:
            sidx = int(t['server'][1:]) - 1
            cmd = 'iperf3 {opt} > logs/{log} &'.format(
                opt=t['server_opt'],
                log=t['server_log']
            )
            print('{}$ {}'.format(t['server'], cmd))
            mn.hosts[sidx].cmd(cmd)
            t['server_pid'] = int(mn.hosts[sidx].cmd('echo $!'))
    
    print('Starting tcpreplay receivers')
    if 'tcpreplay' in workload:
        for t in workload['tcpreplay']:
            ridx = int(t['receiver'][1:]) - 1
            cmd = '(sleep {delay}) && timeout {dur} python tcpreplay-receiver.py {opt} &> logs/{log} &'.format(
                delay=t['start_delay'],
                dur=t['duration'] + 10,
                opt=t['receiver_opt'],
                log=t['receiver_log']
            )
            print('{}$ {}'.format(t['receiver'], cmd))
            mn.hosts[ridx].cmd(cmd)
            t['receiver_pid'] = int(mn.hosts[ridx].cmd('echo $!'))

    # give a little bit of time for the servers to start
    time.sleep(4.5)

    # start ping hosts and iperf3 clients
    print('Starting ping hosts')
    if 'ping' in workload:
        for t in workload['ping']:
            hidx = int(t['host'][1:]) - 1
            cmd = '(sleep {delay}) && ping {opt} > logs/{log} &'.format(
                delay=t['start_delay'],
                opt=t['opt'],
                log=t['log']
            )
            print('{}$ {}'.format(t['host'], cmd))
            mn.hosts[hidx].cmd(cmd)
            t['pid'] = int(mn.hosts[hidx].cmd('echo $!'))

    print('Starting iperf3 clients')
    if 'iperf3' in workload:
        for t in workload['iperf3']:
            cidx = int(t['client'][1:]) - 1
            cmd = '(sleep {delay}) && (timeout {dur} iperf3 {opt} > logs/{log}) &'.format(
                dur=t['duration'] + 5,
                delay=t['start_delay'],
                opt=t['client_opt'],
                log=t['client_log']
            )
            print('{}$ {}'.format(t['client'], cmd))
            mn.hosts[cidx].cmd(cmd)
            t['client_pid'] = int(mn.hosts[cidx].cmd('echo $!'))
    
    print('Starting tcpreplay senders')
    if 'tcpreplay' in workload:
        for t in workload['tcpreplay']:
            sidx = int(t['sender'][1:]) - 1
            cmd = '(sleep {delay}) && (timeout {dur} tcpreplay {opt} > logs/{log}) &'.format(
                dur=t['duration'] + 5,
                delay=t['start_delay'],
                opt="--intf1={}-eth0 ".format(t['sender']) + t['sender_opt'],
                log=t['sender_log']
            )
            print('{}$ {}'.format(t['sender'], cmd))
            mn.hosts[sidx].cmd(cmd)
            t['sender_pid'] = int(mn.hosts[sidx].cmd('echo $!'))
    
    # wait for clients to finish
    print('Waiting for iperf3 clients to finish')
    if 'iperf3' in workload:
        for t in workload['iperf3']:
            print('Client in {}'.format(t['client']), end='')
            finished = 0
            while finished == 0:
                cidx = int(t['client'][1:]) - 1
                mn.hosts[cidx].cmd('ps -p {}'.format(t['client_pid']))
                finished = int(mn.hosts[cidx].cmd('echo $?'))
                if finished == 0:
                    print('.', end='')
                    sys.stdout.flush()
                    time.sleep(1)
            print()
    
    # wait for tcpreplay senders to finish
    print('Waiting for tcpreplay senders to finish')
    if 'tcpreplay' in workload:
        for t in workload['tcpreplay']:
            print('Sender in {}'.format(t['sender']), end='')
            finished = 0
            while finished == 0:
                sidx = int(t['sender'][1:]) - 1
                mn.hosts[sidx].cmd('ps -p {}'.format(t['sender_pid']))
                finished = int(mn.hosts[sidx].cmd('echo $?'))
                if finished == 0:
                    print('.', end='')
                    sys.stdout.flush()
                    time.sleep(1)
            print()

    # wait for pings to finish
    print('Waiting for ping hosts to finish')
    if 'ping' in workload:
        for t in workload['ping']:
            print('Ping in {}'.format(t['host']), end='')
            finished = 0
            while finished == 0:
                hidx = int(t['host'][1:]) - 1
                mn.hosts[hidx].cmd('ps -p {}'.format(t['pid']))
                finished = int(mn.hosts[hidx].cmd('echo $?'))
                if finished == 0:
                    print('.', end='')
                    sys.stdout.flush()
                    time.sleep(1)
            print()
    


    # wait for servers to finish
    print('Waiting for iperf3 servers to finish')
    if 'iperf3' in workload:
        for t in workload['iperf3']:
            print('Server in {}'.format(t['server']), end='')
            finished = 0
            while finished == 0:
                sidx = int(t['server'][1:]) - 1
                mn.hosts[sidx].cmd('ps -p {}'.format(t['server_pid']))
                finished = int(mn.hosts[sidx].cmd('echo $?'))
                if finished == 0:
                    print('.', end='')
                    sys.stdout.flush()
                    time.sleep(1)
            print()
    
    # wait for tcpreplay receivers to  finish
    print('Waiting for tcpreplay receivers to finish')
    if 'tcpreplay' in workload:
        for t in workload['tcpreplay']:
            print('Receiver in {}'.format(t['receiver']), end='')
            finished = 0
            while finished == 0:
                ridx = int(t['receiver'][1:]) - 1
                mn.hosts[ridx].cmd('ps -p {}'.format(t['receiver_pid']))
                finished = int(mn.hosts[ridx].cmd('echo $?'))
                if finished == 0:
                    print('.', end='')
                    sys.stdout.flush()
                    time.sleep(1)
            print()

    time.sleep(5)

    mn.pingAll()

    print('Byebye')
