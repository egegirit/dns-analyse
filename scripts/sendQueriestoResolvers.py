import time
from datetime import datetime
import dns.resolver
import dns.reversename

###############################################################
### Run packet capture program before executing this script ###
###############################################################

# Time to wait between the queries
sleep_time = 5

# Determines how many times the program sends the query
execute_count = 10

# Domain names to query
dns_request_qnames = [
    "google.com", 
    "amazon.com", 
    "securitycharms.com",
    "twitch.tv", 
    "diziwatch.net",
    "udemy.com"
]
# dns_request_qnames = [
    # "nameserver1.intranet.lol", 
    # "nameserver2.intranet.lol", 
    # "nameserver3.intranet.lol",
    # "nameserver4.intranet.lol", 
    # "nameserver5.intranet.lol", 
    # "nameserver6.intranet.lol",
    # "nameserver7.intranet.lol", 
    # "nameserver8.intranet.lol", 
    # "nameserver9.intranet.lol",
    # "nameserver10.intranet.lol"
# ]

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
  "64.6.64.6",        # Neustar 1  (?)
  "156.154.70.1",     # Neustar 2  (?)
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
    for i in range(0, execute_count):  # Execution count must be calculated with consideration of dns_request_qnames count.
        for current_query in dns_request_qnames:
            print(f"Current query: {current_query}")
            for current_resolver_ip in resolver_ip_addresses:                
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [current_resolver_ip]  # Set the resolver IP Address (multiple IP addresses as list possible)
                resolver.timeout = 10  # Set the timeout of the query
                resolver.lifetime = 10
                start_time = time.time()
                print(f"  Sending DNS query to {current_resolver_ip}")
                # Documentation: https://dnspython.readthedocs.io/en/latest/resolver-class.html
                try:
                    answers = resolver.resolve(current_query,'A')     
                # answers = dns.resolver.query(dns_request_qname, 'A', raise_on_no_answer=False)  # Alternative                  
                except:
                    print("DNS Exception occured!")   
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


send_queries(sleep_time, execute_count, resolver_ip_addresses)
