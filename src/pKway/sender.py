#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, XShortField, BitField
from scapy.all import bind_layers
import readline

class P4kway(Packet):
    name = "p4kway"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    StrFixedLenField("type", "F", length=1),
                    BitField("k", 0, 8),
                    XShortField("v", 0),
                    BitField("cache", 0, 8),
                    ]


bind_layers(Ether, P4kway, type=0x1234)


def main():
    s = ''
    iface = 'eth0'

    while s not in ['LFU', 'LRU']:
        s = str(raw_input('Type LFU or LRU> '))
    if s == 'LFU':
        t = 'F'
    elif s == 'LRU':
        t = 'R'

    while True:
        s = int(str(raw_input('> ')))
        if s == "quit":
            break
        print s
        try:
            pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4kway(type=t,
                                                                       k=s)
            pkt = pkt/' '

#            pkt.show()
            resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
            if resp:
                p4kway=resp[P4kway]
                if p4kway:
                    print('key={}, value={}, from_cache={}'.format(p4kway.k, p4kway.v, p4kway.cache))
                else:
                    print "cannot find P4aggregate header in the packet"
            else:
                print "Didn't receive response"
        except Exception as error:
            print 'error --> ' + error.message


if __name__ == '__main__':
    main()
