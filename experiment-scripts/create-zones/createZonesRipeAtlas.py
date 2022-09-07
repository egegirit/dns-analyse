import sys

# Domain name: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de

# *.ripeatlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de

# *.ripeatlas-<counter>-<packetloss-rate>.packetloss.syssec-research.mmci.uni-saarland.de

# Nameserver definition example
# @	IN	NS	nameserver20.packetloss.syssec-research.mmci.uni-saarland.de.

# A Record definition example
# ripe-atlas-<counter>	IN	A	192.168.1.1

base_zone = ".packetloss.syssec-research.mmci.uni-saarland.de"

# Results will be stored here
created_domain_names = []
created_prefixes = []
created_ns_definitions = []
created_a_records = []

ip_address_with_dots = "139.19.117.11"

packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

# Creates nameserver definitions
def create_nameserver_definitions():
    # f = open("NS_records.txt", "a")
    global created_domain_names
    for domain_name in created_domain_names:
        # @	IN	NS	.packetloss.syssec-research.mmci.uni-saarland.de.
        result = "@\tIN\tNS\t" + domain_name + "."
        print(f"Created NS Record: {result}")
        created_ns_definitions.append(result)
        # f.write(result + "\n")
    # f.close()


# Create A records for the domains
def create_a_records(ip_addr, delimeter="\t"):
    f = open("A_records_ripe-atlas.txt", "a")
    global created_domain_names
    for domain_name in created_domain_names:
        # print(f"domain_name: {domain_name}")
        result = domain_name + delimeter + "IN" + delimeter + "A" + delimeter + ip_addr
        print(f"Created A record: {result}")
        created_a_records.append(result)
        f.write(result + "\n")

    f.close()


domain_count = 1000

# *.ripeatlas-<counter>-<packetloss-rate>.packetloss.syssec-research.mmci.uni-saarland.de

for pl_rate in packetloss_rates:
    for counter in range(domain_count):
        created_domain = "*.ripeatlas-" + str(counter) + "-pl" + str(pl_rate) + base_zone
        # global created_domain_names
        created_domain_names.append(created_domain)

create_nameserver_definitions()
# create_a_records(ip_address_with_dots, delimeter="\t")
