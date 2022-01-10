#!/usr/bin/env python

""" This tool performs a (very silly) attempt at ARP cache poisoning. Although
    the poisoning attempt is not strictly valid (what with deadbeefcafe not
    being a real place) it does generate suspicious ARP packets for us. """

from scapy.all import * 

operation = 2        # 2 specifies ARP Reply
victim = '127.0.0.1' # We're poisoning our own cache for this demonstration
spoof = '192.168.222.222' # We are trying to poison the entry for this IP
mac = 'de:ad:be:ef:ca:fe' # Silly mac address


arp=ARP(op=operation, psrc=spoof, pdst=victim, hwdst=mac)
send(arp)

