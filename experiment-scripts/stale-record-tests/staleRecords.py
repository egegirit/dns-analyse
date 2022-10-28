import subprocess
import concurrent.futures
import sys
import time
import os
import signal
import dns.resolver
import string
import random
from datetime import datetime

####################################
# Execute this script as root user #
####################################

# Time to wait after one query is sent to a resolver IP Addresses
sleep_time_between_counters = 1
# Time to sleep between packetloss configurations. (600 seconds = 10 minutes)
sleep_time_between_packetloss_config = 600
# Time to sleep in order the answer to become stale on the resolver
sleep_time_until_stale = 10

# The probability that we will hit all the caches of the resolver.
# This probability is used to calculate the query count to send to the resolver
# in the prefetch phase
cache_hit_probability = 0.95

# The minimum number of queries to send to a resolver in the prefetch phase,
# even when the resolver has only 1 cache.
minimum_prefetch_query_count = 10

# Minimum and maximum counter values for the domains
counter_min = 0  # Inclusive
counter_max = 50  # Exclusive

# Set the interface names for packet capture with tcpdump
auth_interface_name = "bond0"  # The interface of authoritative server
client_interface_name = "bond0"  # The interface of client

directory_name_of_logs = "packet_capture_logs"

# Packetloss rates to be simulated on the authoritative server
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

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
    "77.88.8.8",  # Yandex 2   (secondary.dns.yandex.ru )
]

# Define how many caches does the resolver have
caches_of_resolvers = {
    "94.140.14.14": 1,  # AdGuard 1
    "94.140.14.15": 1,  # AdGuard 2
    "185.228.168.168": 5,  # CleanBrowsing 1
    "185.228.168.9": 5,  # CleanBrowsing 2
    "1.1.1.1": 18,  # Cloudflare 1
    "1.0.0.1": 18,  # Cloudflare 2
    "216.146.35.35": 3,  # Dyn 1
    "216.146.36.36": 3,  # Dyn 2
    "8.8.8.8": 9,  # Google 1
    "8.8.4.4": 9,  # Google 2
    "64.6.64.6": 3,  # Neustar 1
    "156.154.70.1": 3,  # Neustar 2
    "208.67.222.222": 16,  # OpenDNS 1
    "208.67.222.2": 16,  # OpenDNS 2
    "9.9.9.9": 8,  # Quad9 1
    "9.9.9.11": 8,  # Quad9 2
    "77.88.8.1": 10,  # Yandex 1
    "77.88.8.8": 10,  # Yandex 2
}


# Simulate packetloss with iptables, in case of an exception, the code attempts to remove the rule
# Returns True when no error.
# Use `run()` with `check=True` when setting and deleting packetloss
# Otherwise process might not have finished before the next code runs
def simulate_packetloss(packetloss_rate, interface_name):
    packetloss_filter_command_1 = f'sudo iptables-legacy -A INPUT -d 139.19.117.11/32 --protocol tcp --match tcp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    packetloss_filter_command_2 = f'sudo iptables-legacy -A INPUT -d 139.19.117.11/32 --protocol udp --match udp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    print(
        f"  Simulating {packetloss_rate}% packetloss on interface {interface_name} with the following command:"
    )
    print("    " + packetloss_filter_command_1)
    print("    " + packetloss_filter_command_2)
    try:
        subprocess.run(packetloss_filter_command_1, shell=True, stdout=subprocess.PIPE, check=True)
        subprocess.run(packetloss_filter_command_2, shell=True, stdout=subprocess.PIPE, check=True)
        return True
    except Exception:
        print(
            f"  Exception occurred while simulating {packetloss_rate}% packetloss on interface {interface_name} !!"
        )
        print(
            f"  Removing packetloss rule by calling disable_packetloss_simulation({packetloss_rate}, {interface_name})")
        disable_packetloss_simulation(packetloss_rate, interface_name)
        print(f"  Skipping {packetloss_rate}% packetloss configuration")
        return False


# Disables packetloss simulation
# Returns true if no exception occurred. False, if subprocess.run() created an exception.
def disable_packetloss_simulation(packetloss_rate, interface_name):
    print(f"  Disabling packetloss on {interface_name} interface with following commands:")
    disable_packetloss_1 = f'sudo iptables-legacy -D INPUT -d 139.19.117.11/32 --protocol tcp --match tcp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    disable_packetloss_2 = f'sudo iptables-legacy -D INPUT -d 139.19.117.11/32 --protocol udp --match udp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    print("    " + disable_packetloss_1)
    print("    " + disable_packetloss_2)
    try:
        subprocess.run(
            disable_packetloss_1, shell=True, stdout=subprocess.PIPE, check=True
        )
        subprocess.run(
            disable_packetloss_2, shell=True, stdout=subprocess.PIPE, check=True
        )
        return True
    except Exception:
        print(
            f"  Exception occurred while removing {packetloss_rate}% packetloss rule on interface {interface_name} !!"
        )
        return False


# Start 2 packet captures with tcpdump and return the processes
# In case of an exception, the list will be empty
def start_packet_captures(directory_name_of_logs, current_packetloss_rate, auth_interface, client_interface):

    # Packet capture on authoritative server interface without the packetloss filter
    # source port should not be 53 but random.
    # The destination port is 53, but using that would only capture incoming, not outgoing traffic
    packet_capture_command_1 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_auth1_{auth_interface}_{current_packetloss_rate}.pcap -nnn -i {auth_interface} "host 139.19.117.11 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (1) Running packet capture on {auth_interface} interface with the following command:"
    )
    print("    " + packet_capture_command_1)

    # Packet capture on client interface
    packet_capture_command_2 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_client_{client_interface}_{current_packetloss_rate}.pcap -nnn -i {client_interface} "host 139.19.117.1 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (2) Running packet capture on {client_interface} interface with the following command:"
    )
    print("    " + packet_capture_command_2)

    # Store the process objects here and return it as output
    result_processes = []

    try:
        process_1 = subprocess.Popen(
            packet_capture_command_1, shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid
        )
        process_2 = subprocess.Popen(
            packet_capture_command_2, shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid
        )
        result_processes.append(process_1)
        result_processes.append(process_2)
    except Exception:
        print("    Packet capture failed!")
        return result_processes  # Empty list

    # If packet capture commands are delayed for a reason, the send_query function executes before the packet capture.
    # Added 1-second sleep to avoid this.
    print(f"  Sleeping 1 second to let the packet captures start")
    time.sleep(1)
    return result_processes


# Sleep for a duration and show the remaining time on the console
def sleep_for_seconds(sleeping_time):
    print("  Remaining time:")
    # Output how many seconds left to sleep
    for i in range(sleeping_time, 0, -1):
        print(f"{i}")
        time.sleep(1)
        # Delete the last output line of the console
        # to show the remaining time without creating new lines
        print("\033[A                             \033[A")


# Compress all the packet capture logs into a logs.zip file
def compress_log_files(directory_name):
    compress_files_command = f"zip -r logs.zip {directory_name}"
    print("Compressing all log files into a logs.zip file with the following command:")
    print("  " + compress_files_command)
    print("Compressing...")
    try:
        subprocess.run(compress_files_command, shell=True, stdout=subprocess.PIPE, check=True)
    except Exception:
        print("  Exception occurred while compressing the packet capture files !!")

    print("Compressing done")


# Create directory to store the packet capture log files
def create_folder(directory_name):
    create_folder_command = f"mkdir {directory_name}"
    print(f"Creating a folder named {directory_name} with the following command:")
    print("  " + create_folder_command)

    try:
        subprocess.run(create_folder_command, shell=True, stdout=subprocess.PIPE, check=True)
        print(f"Folder {directory_name} created.")
    except Exception:
        print(f"Folder not created.")


def calculate_query_count_with_desired_probability(ip_addr, cache_count_of_resolver, desired_probability):
    global minimum_prefetch_query_count
    query_count = 1

    print(f"{ip_addr} has {cache_count_of_resolver} caches")

    # cache_i_missed_total = ((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count
    cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count)
    # print(
    #     f"Probability of Cache_i is missed with {query_count} query:  ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
    #     f"{query_count} = {cache_i_missed_total}")
    # print(
    #     f"Probability of Cache_i is hit with {query_count} query:     1 - ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
    #     f"{query_count} = {cache_i_hit_total}\n")

    while cache_i_hit_total < desired_probability:
        # print(f"Probability of total cache hit was not {desired_probability * 100}%")
        # print(f"  Incrementing query count from {query_count} to {query_count + 1}")
        query_count += 1
        cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count)
        # print(
        #     f"  New probability of Cache hit with {query_count} query:  1 - ({cache_count_of_resolver}-1/{cache_count_of_resolver})^"
        #     f"{query_count} = {cache_i_hit_total}\n")

    print(f"{desired_probability * 100}% Probability is met with {query_count} queries.")

    # if query_count < minimum_prefetch_query_count:
    #    print(f"Query count set to {minimum_prefetch_query_count} (maximum)")

    return max(query_count, minimum_prefetch_query_count)


def calculate_prefetch_query_count(ip_addr, phase, pl_rate, desired_probability):
    global caches_of_resolvers
    if phase == "prefetch":
        return calculate_query_count_with_desired_probability(ip_addr, caches_of_resolvers[ip_addr], desired_probability) + 10
    elif phase == "stale":
        return 10


# Prefetch phase, send queries to resolvers to make them cache the entries
def send_queries_to_resolvers(ip_addr, sleep_time_after_send, pl_rate, generated_tokens, phase, desired_probability):
    print(f"\n  Sending query to IP: {ip_addr}")
    query_count = calculate_prefetch_query_count(ip_addr, phase, pl_rate, desired_probability)
    print(f"  Query Amount to send to the resolver: {query_count}")

    for counter in range(query_count):
        query_name = build_query(pl_rate, ip_addr, generated_tokens)
        print(f"   Query name: {query_name}")

        resolver = dns.resolver.Resolver()
        # Set the resolver IP Address
        resolver.nameservers = [ip_addr]
        # Set the timeout of the query
        resolver.timeout = 10
        resolver.lifetime = 10
        # Measure the time of the DNS response (Optional)
        # start_time = time.time()
        # Note: if multiple prints are used, other processes might print in between them
        print(f"      ({counter + 1}) Sending Query")
        try:
            answers = resolver.resolve(query_name, "A")
        except Exception:
            print(f"      ({counter + 1}) Exception or timeout occurred for {query_name} ")
            answers = None
        # measured_time = time.time() - start_time
        # print(f"      ({counter + 1}) Response time of {query_name}: {measured_time}")

        # print(f"Query sent at: {datetime.utcnow()}")
        try:
            # Show the DNS response and TTL time
            if answers is not None:
                print(f"TTL of Answer ({counter + 1}): {answers.rrset.ttl}")
        #         print(f"RRset:")
        #         if answers.rrset is not None:
        #             print("        ", end="")
        #             print(answers.rrset)
        except Exception:
            print(f"Error when showing results of ({counter + 1}) {query_name}")

        # Sleep after sending a query to the same resolver to not spam the resolver
        time.sleep(sleep_time_after_send)


# Build the query from packetloss rate and its type (prefetch phase or after the query becomes stale)
def build_query(packetloss_rate, ip_addr, generated_tokens):
    ip_addr_with_dashes = ip_addr.replace(".", "-")
    query = "stale-" + str(ip_addr_with_dashes) + "-" + str(packetloss_rate) + "-" + str(generated_tokens) + \
            ".packetloss.syssec-research.mmci.uni-saarland.de"
    print(f"  Built query: {query}")
    return query


# Switch to the zone file of the corresponding packetloss rate
def switch_zone_file(zone_type, generated_tokens, pl_rate):
    print(f"  Creating {zone_type} zone file with generated chars {generated_tokens} and packetloss rate {pl_rate}")

    a_record_ip_addr = ""

    if zone_type == "prefetch":
        a_record_ip_addr = str(pl_rate)
    elif zone_type == "stale":
        a_record_ip_addr = str(pl_rate + 1)
    else:
        print("Undefined zone type!")
        sys.exit()

    a_record_end = a_record_ip_addr + "." + a_record_ip_addr + "." + a_record_ip_addr

    # Write the contents of the desired zone file to the active.zone file
    # Opening the file with "w" mode erases the previous content of the file
    with open('boilerplate.zone', 'r') as first_file, open('active.zone', 'w') as second_file:
        # Read content from first zone file
        for line in first_file:
            # Append content to active zone file line by line
            second_file.write(line)

    a_records = ""
    created_A_record = ""  # DEBUG

    f = open('active.zone', 'a')

    for ip_addr in resolver_ip_addresses:
        ip_addr_with_dashes = ip_addr.replace(".", "-")

        a_records = "stale-" + str(ip_addr_with_dashes) + "-" + str(pl_rate) + "-" + str(
            generated_tokens) + "\tIN\tA\t139." + a_record_end + "\n"
        created_A_record += a_records
        f.write(a_records)
    f.close()

    print(f"\nCreated A record for {zone_type}, {pl_rate} Packetloss rate:")
    print(created_A_record)

    # Reload bind/dns services
    reload_command_1 = f"sudo rndc reload"
    print(
        f"  Reloading bind9 with the following command:"
    )
    print("    " + reload_command_1)

    try:
        subprocess.run(reload_command_1, shell=True, stdout=subprocess.PIPE, check=True)
    except Exception:
        print(
            f"  Exception occurred while reloading bind !"
        )


# Generate x random characters to add it at the end of the query names in the zone file
def generate_random_characters(length):
    result = ""
    for _ in range(length):
        result += random.choice(string.ascii_letters)
    return result


# Create log folder
create_folder(directory_name_of_logs)

print("\n==== Experiment starting ====\n")

generated_chars = generate_random_characters(3)
print(f"Current time: {datetime.utcnow()}")

for current_packetloss_rate in packetloss_rates:

    print(f"\nSwitching to Packetloss Rate: {current_packetloss_rate}%")

    # Start packet capture
    capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, auth_interface_name,
                                              client_interface_name)

    # Set the right zone file for the prefetching phase
    switch_zone_file("prefetch", generated_chars, current_packetloss_rate)

    print(f"\nPREFETCH PHASE BEGIN, SENDING QUERIES")

    # Context manager
    with concurrent.futures.ProcessPoolExecutor() as executor:
        # Using list comprehension to build the results list
        # submit() schedules the callable to be executed and returns a
        # future object representing the execution of the callable.
        results = [executor.submit(send_queries_to_resolvers,
                                   current_resolver_ip,
                                   sleep_time_between_counters,
                                   current_packetloss_rate,
                                   generated_chars,
                                   "prefetch",
                                   cache_hit_probability)
                   for current_resolver_ip in resolver_ip_addresses]

    print(f"\nPREFETCH PHASE DONE\n")

    # Non-multithreading code
    # send_queries_to_resolvers(resolver_ip_addresses,
    #                           sleep_time_between_counters, current_packetloss_rate, generated_chars, "prefetch")

    print(f"Sleeping for {sleep_time_until_stale} seconds until the records are stale")

    # Wait until we are certain that the answer which is stored in the resolver is stale
    sleep_for_seconds(sleep_time_until_stale)

    # Simulate packetloss on authoritative Server
    simulate_packetloss(int(current_packetloss_rate), auth_interface_name)

    # Set the right zone file for the phase after the answer is stale
    switch_zone_file("stale", generated_chars, current_packetloss_rate)

    # Send queries to resolvers again (and analyse the pcaps if the query was answered or not)
    # Non-Multithreading code
    # send_queries_to_resolvers(resolver_ip_addresses,
    #                           sleep_time_between_counters, current_packetloss_rate, generated_chars, "stale")

    print(f"\nSTALE PHASE BEGIN, SENDING QUERIES")

    # Context manager
    with concurrent.futures.ProcessPoolExecutor() as executor:
        # Using list comprehension to build the results list
        # submit() schedules the callable to be executed and returns a
        # future object representing the execution of the callable.
        results = [executor.submit(send_queries_to_resolvers,
                                   current_resolver_ip,
                                   sleep_time_between_counters,
                                   current_packetloss_rate,
                                   generated_chars,
                                   "stale",
                                   cache_hit_probability)
                   for current_resolver_ip in resolver_ip_addresses]

    print(f"\nSTALE PHASE DONE\n")
    print(f"Sleeping for {sleep_time_until_stale} seconds between packetloss rate configs (Cooldown)")

    # Cooldown between packetloss configurations
    sleep_for_seconds(sleep_time_between_packetloss_config)

    # Terminate packet captures / all created processes
    print(f"  Stopping packet capture")
    # Using .terminate() doesn't stop the packet capture
    if len(capture_processes) > 0:
        for process in capture_processes:
            try:
                # Send the SIGTERM signal to all the process groups
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            except Exception:
                print(f"    Exception while terminating tcpdump")
        print(f"    Sleeping for 1 seconds for tcpdump to terminate")
        sleep_for_seconds(1)

print("\n==== Experiment ended ====\n")

# Compress all the packet capture logs into a logs.zip file
compress_log_files(directory_name_of_logs)
