import time
from datetime import datetime
import dns.resolver
import dns.reversename
import subprocess
import sys

# Execute this script as root user

# Time to wait after one domain query is sent to all resolver IP Addresses
sleep_time = 1
# 900 seconds = 15 minutes
sleep_time_between_packetloss_config = 900

# Determines how many times the program sends the query
execute_count = 1

# Domain names to query (TEST)
# dns_request_qnames = [
#    "google.com", 
#    "amazon.com", 
#    "securitycharms.com",
#    "twitch.tv", 
#    "udemy.com"
# ]

# Queries to send to resolvers
dns_request_qnames = []

# for k in range(5):
#    exec(f'cat_{k} = k*2')

# d = {}
# for x in range(1, 10):
#    d["string{0}".format(x)] = "Hello"

counter1 = []
counter2 = []

p0_queries = []
p10_queries = []
p20_queries = []
p30_queries = []
p40_queries = []
p50_queries = []
p60_queries = []
p70_queries = []
p80_queries = []
p85_queries = []
p90_queries = []
p95_queries = []
packetloss_queries = [p0_queries, p10_queries, p20_queries, p30_queries, p40_queries, p50_queries, p60_queries,
                      p70_queries, p80_queries, p85_queries, p90_queries, p95_queries]


class Domain:
    def __init__(self, ip_address, packetloss_rate, counter_no, query):
        self.ip_address = ip_address
        self.packetloss_rate = packetloss_rate
        self.counter_no = counter_no
        self.query = query


domain_list = []
domain_list.append(Domain('Resolver_Name', "pl_rate", "no", "query"))

# Read all the domain names from domain_names.txt
# and classify them according to their label structure
file1 = open("domain_names.txt", "r")
Lines = file1.readlines()
for line in Lines:
    dns_request_qnames.append(line)
    prefix = line.split('.')[0]  # Get the most left label of the domain
    splitted = line.split('-')
    packetloss_rate = splitted[len(splitted) - 1]  # Last label is the packetloss rate
    counter = splitted[len(splitted) - 2]  # Second last label is the counter
    # First 4 labels build the IP Address
    # Add dots to build the real IP Address
    ip_addr = splitted[0] + "." + splitted[1] + "." + splitted[2] + "." + splitted[3]
    # resolver_name = ""  # TODO with a function
    print(f"Domain: {line}")
    print(f"  packetloss_rate: {packetloss_rate}")
    print(f"  counter: {counter}")
    print(f"  IP Address: {ip_addr}")

    # Create the object
    domain_list.append(Domain(ip_addr, packetloss_rate, counter, line))
    print(f"Query object created")

    # print(f"  resolver_name: {resolver_name}")
    if packetloss_rate == "pl0":
        p0_queries.append(line.strip())
    if packetloss_rate == "pl10":
        p10_queries.append(line.strip())
    if packetloss_rate == "pl20":
        p20_queries.append(line.strip())
    if packetloss_rate == "pl30":
        p30_queries.append(line.strip())
    if packetloss_rate == "pl40":
        p40_queries.append(line.strip())
    if packetloss_rate == "pl50":
        p50_queries.append(line.strip())
    if packetloss_rate == "pl60":
        p60_queries.append(line.strip())
    if packetloss_rate == "pl70":
        p70_queries.append(line.strip())
    if packetloss_rate == "pl80":
        p80_queries.append(line.strip())
    if packetloss_rate == "pl85":
        p85_queries.append(line.strip())
    if packetloss_rate == "pl90":
        p90_queries.append(line.strip())
    if packetloss_rate == "pl95":
        p95_queries.append(line.strip())

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

# Set the interface names for packet capture with tcpdump
interface_1 = "eth0"  # The interface of auhtoritative server without the packetloss filter
interface_2 = "ifb0"  # The interface of auhtoritative server with the packetloss filter applied
interface_3 = "eth1"  # The interface of client which sends the queries

packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

# The name of the folder that will be created to store all the tcpdump files inside of it
directory_name_of_logs = "capture_logs"


# The function that sends the domain name queries to the defined resolver IP addresses execute_count times
def send_queries2(sleep_time, execute_count, resolver_ip_addresses, current_packetloss_rate):
    if sleep_time < 0:
        print(f"    Invalid sleep time! {sleep_time}")
        return
    if execute_count < 0:
        print(f"    Invalid execution count! {execute_count}")
        return
    global answers

    print(f"    Executing send_queries() function")

    # Delimeter that separates the labels in the domain name
    # Example: <ip_addr>-<counter>-<packetloss_rate>.packetloss.syssec-research.mmci.uni-saarland.de
    delimeter = "-"  # Execution count must be calculated with consideration of dns_request_qnames count.
    for i in range(0, execute_count):
        print(f"    {i+1}. Iteration")
        for c in range(1, 201):
            for current_resolver_ip in resolver_ip_addresses:
                ip_addr_with_dashes = current_resolver_ip.replace(".", "-")
                query_prefix = ip_addr_with_dashes + delimeter + c + delimeter + "pl" + \
                               str(current_packetloss_rate)
                print(f"      Current query_prefix: {query_prefix}")
                query = query_prefix + "." + "packetloss.syssec-research.mmci.uni-saarland.de"
                print(f"      Current query: {query}")
                resolver = dns.resolver.Resolver()
                # Set the resolver IP Address (multiple IP addresses as list possible)
                resolver.nameservers = [current_resolver_ip]
                # Set the timeout of the query
                resolver.timeout = 10
                resolver.lifetime = 10
                start_time = time.time()
                print(f"      Sending DNS query to: {current_resolver_ip}")
                try:
                    answers = resolver.resolve(query, 'A')
                    # answers = dns.resolver.query(dns_request_qname, 'A', raise_on_no_answer=False)  # Alternative
                except:
                    print("      DNS Exception occured!")
                    answers = None
                measured_time = time.time() - start_time
                print(f"    DNS Response time: {measured_time}")
                if answers is not None:
                    for answer in answers:
                        print("        ", end="")
                        print(answer)
                    print("      RRset:")
                    if answers.rrset is not None:
                        print("        ", end="")
                        print(answers.rrset)
                # time.sleep(1)  # Sleep after every query
            print(f"    Finished sending current query to all resolver IP Addresses.")
            print(f"    Sleeping for {sleep_time} seconds to continue with the next domain name.")
            time.sleep(sleep_time)  # Sleep after one domain name is sent to all resolver IP's

        print(f"    send_queries() function finished")



# The function that sends the domain name queries to the defined resolver IP addresses execute_count times
def send_queries(sleep_time, execute_count, resolver_ip_addresses):
    if sleep_time < 0:
        print(f"    Invalid sleep time! {sleep_time}")
        return
    if execute_count < 0:
        print(f"    Invalid execution count! {execute_count}")
        return
    global answers

    print(f"    Executing send_queries() function")

    # Execution count must be calculated with consideration of dns_request_qnames count.
    for i in range(0, execute_count):
        print(f"    {execute_count}. Iteration")
        for current_query in dns_request_qnames:
            print(f"      Current query: {current_query}")
            for current_resolver_ip in resolver_ip_addresses:
                resolver = dns.resolver.Resolver()
                # Set the resolver IP Address (multiple IP addresses as list possible)
                resolver.nameservers = [current_resolver_ip]
                # Set the timeout of the query
                resolver.timeout = 10
                resolver.lifetime = 10
                start_time = time.time()
                print(f"      Sending DNS query to: {current_resolver_ip}")
                # Documentation: https://dnspython.readthedocs.io/en/latest/resolver-class.html
                try:
                    answers = resolver.resolve(current_query, 'A')
                    # answers = dns.resolver.query(dns_request_qname, 'A', raise_on_no_answer=False)  # Alternative
                except:
                    print("      DNS Exception occured!")
                    answers = None
                measured_time = time.time() - start_time
                print(f"    DNS Response time: {measured_time}")
                if answers is not None:
                    for answer in answers:
                        print("        ", end="")
                        print(answer)
                    print("      RRset:")
                    if answers.rrset is not None:
                        print("        ", end="")
                        print(answers.rrset)
                # time.sleep(1)  # Sleep after every query
            print(f"    Finished sending current query to all resolver IP Addresses.")
            print(f"    Sleeping for {sleep_time} seconds to continue with the next domain name.")
            time.sleep(sleep_time)  # Sleep after one domain name is sent to all resolver IP's

    print(f"    send_queries() function finished")


# Create directory to store the packet capture log files
create_folder_command = f"mkdir {directory_name_of_logs}"
print(f"Creating a folder named {directory_name_of_logs} with the following command:")
print("  " + create_folder_command)
process_0 = subprocess.Popen(create_folder_command, shell=True, stdout=subprocess.PIPE)
process_0.wait()
process_0.terminate()

print("\n==== Experiment starting ====\n")
# Automation with different packetloss rates
for current_packetloss_rate in packetloss_rates:
    print(f"### Current packetloss rate: {current_packetloss_rate} ###")

    # If current packetloss rate is 0, dont execute packetloss filter
    # Workaround for process_1 is not defined
    process_1 = None
    if current_packetloss_rate != 0:
        packetloss_filter_command = f"sudo tc qdisc add dev {interface_2} root netem loss {current_packetloss_rate}%"
        print(
            f"  Simulating {current_packetloss_rate}% packetloss on interface {interface_2} with the following command:")
        print("    " + packetloss_filter_command)
        # Note: Without the "shell=True" option, I got a "file not found" error        
        process_1 = subprocess.Popen(packetloss_filter_command, shell=True, stdout=subprocess.PIPE)

        # Packet capture on authoritative server interface without the packetloss filter
    packet_capture_command_1 = f"sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_{interface_1}_{current_packetloss_rate}.pcap -nnn -i {interface_1} \"src port 53\""
    print(f"  (1) Running packet capture on {interface_1} interface with the following command:")
    print("    " + packet_capture_command_1)
    process_2 = subprocess.Popen(packet_capture_command_1, shell=True, stdout=subprocess.PIPE)

    # Packet capture on authoritative server interface with the packetloss filter applied
    packet_capture_command_2 = f"sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_{interface_2}_{current_packetloss_rate}.pcap -nnn -i {interface_2} \"src port 53\""
    print(f"  (2) Running packet capture on {interface_2} interface with the following command:")
    print("    " + packet_capture_command_2)
    process_3 = subprocess.Popen(packet_capture_command_2, shell=True, stdout=subprocess.PIPE)

    # Packet capture on client interface
    packet_capture_command_3 = f"sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_{interface_3}_{current_packetloss_rate}.pcap -nnn -i {interface_3} \"src port 53\""
    print(f"  (3) Running packet capture on {interface_3} interface with the following command:")
    print("    " + packet_capture_command_3)
    process_4 = subprocess.Popen(packet_capture_command_3, shell=True, stdout=subprocess.PIPE)

    # If packet capture commands are delayed for a reason, the send query function executes before the packet capture.
    # Added 1 second sleep to avoid this.
    print(f"  Sleeping 1 second to let the packet captures start")
    time.sleep(1)

    # Send queries to defined resolver IP addresses
    send_queries2(sleep_time, execute_count, resolver_ip_addresses, current_packetloss_rate)

    # End packet capture on all interfaces    
    print(f"  Disabling packetloss on {interface_2} interface with following commands:")
    disable_packetloss_1 = f"sudo tc qdisc del dev {interface_2} root"
    disable_packetloss_2 = f"sudo tc -s qdisc ls dev {interface_2}"
    print("    " + disable_packetloss_1)
    print("    " + disable_packetloss_2)
    process_5 = subprocess.Popen(disable_packetloss_1, shell=True, stdout=subprocess.PIPE)
    process_6 = subprocess.Popen(disable_packetloss_2, shell=True, stdout=subprocess.PIPE)

    # Terminate all created processes
    print(f"  Terminating processes/stopping packet capture.")
    # process_1.kill() if terminate doesn't work
    if process_1 != None:
        process_1.terminate()
    process_2.terminate()
    process_3.terminate()
    process_4.terminate()
    process_5.terminate()
    process_6.terminate()

    # Sleep for 15 mins between packetloss configurations
    print(f"  Packetloss Config Finished")
    print(f"  Sleeping for {sleep_time_between_packetloss_config} seconds for the next packetloss iteration.")
    print("  Remaining time:")
    # time.sleep(sleep_time_between_packetloss_config)
    # Output how many seconds left to sleep
    for i in range(sleep_time_between_packetloss_config, 0, -1):
        print(f"{i}", end="\r", flush=True)
        time.sleep(1)

print("\n==== Experiment ended ====\n")

# End packet capture on all interfaces    
compress_files_command = f"zip -r logs.zip {directory_name_of_logs}"
print("Compressing all log files into a zip file with the following command:")
print("  " + compress_files_command)
process_7 = subprocess.Popen(compress_files_command, shell=True, stdout=subprocess.PIPE)
process_7.wait()  # Wait for the zip command to finish
process_7.terminate()
