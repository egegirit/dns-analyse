import sys

packetloss_rates = ["pl0", "pl10", "pl20", "pl30", "pl40", "pl50", "pl60", "pl70", "pl80", "pl85", "pl90", "pl95"]

# DNS Open Resolver IP Addresses
resolver_ip_addresses = [
    "94.140.14.14",  # AdGuard 1  (dns.adguard.com)
    "94.140.14.15",  # AdGuard 2  (dns-family.adguard.com )
    "185.228.168.168",  # CleanBrowsing 1  (family-filter-dns.cleanbrowsing.org )
    "185.228.168.9",  # CleanBrowsing 2  (security-filter-dns.cleanbrowsing.org )
    "1.1.1.1",  # Cloudflare 1     (one.one.one.one)
    "1.0.0.1",  # Cloudflare 2     (1dot1dot1dot1.cloudflare-dns.com)
    "216.146.35.35",  # Dyn 1  (resolver1.dyndnsinternetguide.com)
    "216.146.36.36",  # Dyn 2  (resolver2.dyndnsinternetguide.com )
    "8.8.8.8",  # Google 1  (dns.google )
    "8.8.4.4",  # Google 2  (dns.google )
    "64.6.64.6",  # Neustar 1  (?)  ERROR
    "156.154.70.1",  # Neustar 2  (?)  ERROR
    "208.67.222.222",  # OpenDNS 1  (dns.opendns.com )
    "208.67.222.2",  # OpenDNS 2  (sandbox.opendns.com )
    "9.9.9.9",  # Quad9 1    (dns9.quad9.net )
    "9.9.9.11",  # Quad9 2    (dns11.quad9.net)
    "77.88.8.1",  # Yandex 1   (dns.yandex.ru)
    "77.88.8.8"  # Yandex 2   (secondary.dns.yandex.ru )
]

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

base_zone = "packetloss.syssec-research.mmci.uni-saarland.de"

# Results will be stored here
created_domain_names = []
created_prefixes = []
created_ns_definitions = []
created_a_records = []


# Nameserver definition example
# @	IN	NS	nameserver20.packetloss.syssec-research.mmci.uni-saarland.de.

# Creates nameserver definitions in this format:
# IP-Address.counter.packetloss-rate
# Change the delimeter to "-" if you want to create one big domain with one label
def create_nameserver_definitions(ip_addresses, domain_names, counter_min, counter_max, delimeter="-"):
    if counter_max < counter_min:
        print("Wrong counter")
        sys.exit()
    if len(ip_addresses) <= 0:  # empty list is False
        print("Empty IP Address")
        sys.exit()
    if len(domain_names) <= 0:
        print("Empty domain names")
        sys.exit()

        # Create zonefiles.txt in append mode
    f = open("domain_names.txt", "a")
    f2 = open("NS_definitions.txt", "a")
    f3 = open("prefixes.txt", "a")

    for ip_ad in resolver_ip_addresses:
        # Replace all the dots to dashes in the IP Address
        ip_addr = ip_ad.replace(".", "-")
        for counter in range(counter_min, counter_max + 1):
            for packetloss in packetloss_rates:
                prefix = ip_addr + delimeter + str(counter) + delimeter + packetloss
                result = ip_addr + delimeter + str(counter) + delimeter + packetloss + "." + base_zone
                print(f"Created prefix: {prefix}")
                print(f"Created domain name: {result}")
                created_domain_names.append(result)
                created_prefixes.append(prefix)
                f.write(result + "\n")
                f3.write(prefix + "\n")

                # @	IN	NS	nameserver20.packetloss.syssec-research.mmci.uni-saarland.de.
                result_2 = "@\tIN\tNS\t" + result + "."
                print(f"Created NS Record: {result_2}")
                created_ns_definitions.append(result_2)
                f2.write(result_2 + "\n")

    f.close()
    f2.close()


# A Record definition example
# nameserver1	IN	A	192.168.1.1

# Create A records for the domains
def create_a_records(nameservers, ip_addr, delimeter="\t"):
    if len(nameservers) <= 0:  # empty list is False
        print("Empty nameservers")
        sys.exit()
    if ip_addr is None:
        print("No ip_addr")
        sys.exit()

    # Create zonefiles.txt in append mode
    f = open("A_records.txt", "a")

    for ns in nameservers:
        result = ns + delimeter + "IN" + delimeter + "A" + delimeter + ip_addr
        print(f"Created A record: {result}")
        created_a_records.append(result + "\n")
        f.write(result + "\n")

    f.close()


# IP Address must be written without dots to not to create subdomains
ip_address = "139-19-117-11"
ip_address_with_dots = "139.19.117.11"

create_nameserver_definitions(resolver_ip_addresses, dns_request_qnames, 1, 200, "-")
create_a_records(created_prefixes, ip_address_with_dots)
