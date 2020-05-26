from __future__ import print_function

import socket
import sys

from datetime import datetime

def main(UDP_IP, UDP_PORT):
    sock = socket.socket(socket.AF_INET,  # Internet
                        socket.SOCK_DGRAM)  # UDP
    sock.bind((UDP_IP, UDP_PORT))

    cnt = 0
    try:
        print('Waiting for packets')
        sys.stdout.flush()
        while True:
            data, addr = sock.recvfrom(1500)  # buffer size is 1500 bytes
            cnt = cnt + 1
            # print('{}'.format(cnt))
            if cnt % 100 == 0:
                print('{} {}'.format(datetime.now(), cnt))
                sys.stdout.flush()
    except KeyboardInterrupt:
        print('\n{}'.format(cnt))
        sys.stdout.flush()
    
    return


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print('Usage: tcpreplay-receiver.py <host_IP> <UDP_port>')
        exit(1)
    main(sys.argv[1], int(sys.argv[2]))