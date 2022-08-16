import time
from datetime import datetime
import dns.resolver
import dns.reversename

###############################################################
### Run packet capture program before executing this script ###
###############################################################

# Time to wait between the queries (Caching should be considered here)
sleep_time = 5

# Determines how many times the program sends the query
execute_count = 10

# Domain names to query (TEST)
#dns_request_qnames = [
#    "google.com", 
#    "amazon.com", 
#    "securitycharms.com",
#    "twitch.tv", 
#    "udemy.com"
#]

# Queries to send to resolvers
dns_request_qnames = [
    "nameserver1.packetloss.syssec-research.mmci.uni-saarland.de", 
    "nameserver2.packetloss.syssec-research.mmci.uni-saarland.de", 
    "nameserver3.packetloss.syssec-research.mmci.uni-saarland.de",
    "nameserver4.packetloss.syssec-research.mmci.uni-saarland.de", 
    "nameserver5.packetloss.syssec-research.mmci.uni-saarland.de", 
    "nameserver6.packetloss.syssec-research.mmci.uni-saarland.de",
    "nameserver7.packetloss.syssec-research.mmci.uni-saarland.de", 
    "nameserver8.packetloss.syssec-research.mmci.uni-saarland.de", 
    "nameserver9.packetloss.syssec-research.mmci.uni-saarland.de",
    "nameserver10.packetloss.syssec-research.mmci.uni-saarland.de"
]

# DNS Resolver IP Addresses
resolver_ip_addresses = [
  "94.140.14.14",     # AdGuard 1  (dns.adguard.com)
  "94.140.14.15",     # AdGuard 2  (dns-family.adguard.com )
  "185.228.168.168",  # CleanBrowsing 1  (family-filter-dns.cleanbrowsing.org )
  "185.228.168.9",    # CleanBrowsing 2  (security-filter-dns.cleanbrowsing.org )
  "1.1.1.1",          # Cloudflare 1     (one.one.one.one)
  "1.0.0.1",          # Cloudflare 2     (1dot1dot1dot1.cloudflare-dns.com)
  "216.146.35.35",    # Dyn 1  (resolver1.dyndnsinternetguide.com)
  "216.146.36.36",    # Dyn 2  (resolver2.dyndnsinternetguide.com )
  "8.8.8.8",          # Google 1  (dns.google )
  "8.8.4.4",          # Google 2  (dns.google )
  "64.6.64.6",        # Neustar 1  (?)  ERROR
  "156.154.70.1",     # Neustar 2  (?)  ERROR
  "208.67.222.222",   # OpenDNS 1  (dns.opendns.com )
  "208.67.222.2",     # OpenDNS 2  (sandbox.opendns.com )
  "9.9.9.9",          # Quad9 1    (dns9.quad9.net )
  "9.9.9.11",         # Quad9 2    (dns11.quad9.net)
  "77.88.8.1",        # Yandex 1   (dns.yandex.ru)
  "77.88.8.8"         # Yandex 2   (secondary.dns.yandex.ru )
]

def send_queries(sleep_time, execute_count, resolver_ip_addresses):
    if sleep_time < 0:
        print("Invalid sleep time")
        return
    if execute_count < 0:
        print("Invalid execution count")
        return
    global answers
    
    # Execution count must be calculated with consideration of dns_request_qnames count.
    for i in range(0, execute_count):  
        for current_query in dns_request_qnames:
            print(f"  Current query: {current_query}")
            for current_resolver_ip in resolver_ip_addresses:                
                resolver = dns.resolver.Resolver()
                # Set the resolver IP Address (multiple IP addresses as list possible)
                resolver.nameservers = [current_resolver_ip]  
                # Set the timeout of the query
                resolver.timeout = 10  
                resolver.lifetime = 10
                start_time = time.time()
                print(f"  Sending DNS query to {current_resolver_ip}")
                # Documentation: https://dnspython.readthedocs.io/en/latest/resolver-class.html
                try:
                    answers = resolver.resolve(current_query,'A')     
                # answers = dns.resolver.query(dns_request_qname, 'A', raise_on_no_answer=False)  # Alternative                  
                except:
                    print("    DNS Exception occured!")   
                    answers = None
                measured_time = time.time() - start_time
                print(f"  DNS Response time: {measured_time}")
                if answers is not None:
                    for answer in answers:
                        print(answer)
                    print("    RRset:")
                    if answers.rrset is not None:
                        print(answers.rrset)
                # time.sleep(1)  # Sleep after every query
            time.sleep(sleep_time) # Sleep after one domain name is sent to all resolver IP's


print("\n### Experiment starting ###\n")
send_queries(sleep_time, execute_count, resolver_ip_addresses)
print("\n### Experiment ended ###\n")

# TODO: Automation with different packetloss rates
# packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]
# for current_packetloss_rate in packetloss_rates:
#     if current_packetloss_rate != 0:
#         print(f"Simulate {current_packetloss_rate}% packetloss with the following command:")
#         print(f"sudo tc qdisc add dev ifb0 root netem loss {current_packetloss_rate}%")
#         input("Press ENTER after simulating packetloss")
#     print(f"Run packet capture on ifb0 interface with the following command:")
#     print(f"sudo tcpdump -w tcpdump_log_{current_packetloss_rate}.pcap -nnn -i ifb0 "src port 53"")
#     input("Press ENTER after running packet capture")
#     print(f"### Current packetloss rate: {current_packetloss_rate} ###")
#     send_queries(sleep_time, execute_count, resolver_ip_addresses)
#     print(f"Disable packetloss with following commands:")
#     print(f"sudo tc qdisc del dev ifb0 root")
#     print(f"sudo tc -s qdisc ls dev ifb0")
#     input("Press ENTER after disabling packetloss")





