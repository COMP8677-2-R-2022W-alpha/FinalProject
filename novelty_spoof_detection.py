#!/usr/bin/env python3
from scapy.all import *
from datetime import datetime

dns_packets = dict()
dns_mapping = dict()


def spoof_dns(pkt):
    if (DNS in pkt):
        id_packet = pkt[DNS].id
        dns_packets.setdefault(id_packet, 0)
        dns_mapping[id_packet] = pkt[DNS].qd.qname
        dns_packets[id_packet] += 1
        message = 'SPOOF DETECTED! @"{}" duplicate DNS {} replies in packet ID: {}'
        for dns_id, count in dns_packets.items():
            duplicate = count > 2 and dns_id == id_packet
        if duplicate: print(message.format(datetime.now(), dns_mapping[dns_id], dns_id))
        # print('dns packet history: ', dns_packets)


f = 'udp'
pkt = sniff(iface='br-c3497a9f082b', filter=f, prn=spoof_dns)
