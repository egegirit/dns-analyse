#!usr/bin/env python3
from scapy.all import *

destination_addr = "192.168.1.100"
source_port = RandShort()
destination_port = 53
dns_query_name = "nameserver2.intranet.local"

# rd: recursion desired
# qr: 0 = Query, 1 = Respose
dns_request = IP(dst=destination_addr)/UDP(sport=source_port, dport=destination_port)/DNS(rd=1, qr=0, qd=DNSQR(qname=dns_query_name, qtype="A"))

dns_response = sr1(dns_request, verbose=0)

print(dns_response[DNS].summary())
