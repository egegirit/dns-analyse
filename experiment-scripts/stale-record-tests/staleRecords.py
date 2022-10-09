import subprocess
import concurrent.futures
import time
import os
import signal
import dns.resolver
import dns.reversename

####################################
# Execute this script as root user #
####################################

# Time to wait after one domain query is sent to all resolver IP Addresses
# (Sleeping time between counters)
sleep_time_between_counters = 1
# Time to sleep between packetloss configurations. (600 seconds = 10 minutes)
sleep_time_between_packetloss_config = 600
# Time to sleep in order the answer to become stale on the resolver
sleep_time_until_stale = 10

# Minimum and maximum counter values for the domains
counter_min = 0  # Inclusive
counter_max = 50  # Exclusive

# Set the interface names for packet capture with tcpdump
auth_interface_name = "bond0"  # The interface of authoritative server
client_interface_name = "bond0"  # The interface of client

directory_name_of_logs = "packet_capture_logs"

# Packetloss rates to be simulated on the authoritative server
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

# The amount of the query we will send to the resolver to
# make the resolver cache the answer to this query
count_of_prefetch_queries = 15

# The zone that will be active before the experiment
zone_file_A_name = "zone-A"
# The zone that will be active after the records are stale
zone_file_B_name = "zone-B"

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
            f"  Exception occured while removing {packetloss_rate}% packetloss rule on interface {interface_name} !!"
        )
        return False


# Start 2 packet captures with tcpdump and return the processes
# In case of an exception, the list will be empty
def start_packet_captures(directory_name_of_logs, current_packetloss_rate, auth_interface, client_interface):
    # DF (don't fragment) bit set (IP)
    # Example filter:
    # 'ip[6] & 64 != 64'

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
    try:
        subprocess.run(compress_files_command, shell=True, stdout=subprocess.PIPE, check=True)
    except Exception:
        print("  Exception occurred while compressing the packet capture files !!")


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


# Prefetch phase, send queries to resolvers to make them cache the entries
# Todo: multithreading, send queries to resolvers parallel
def send_queries_to_resolvers(query_count, query_name, ip_list_of_resolvers, sleep_time_after_send):
    print(f"   Query Amount to send to a resolver: {query_count}")
    print(f"   Query name: {query_name}")
    print(f"   IP Addresses to send: {ip_list_of_resolvers}\n")

    for ip_addr in ip_list_of_resolvers:
        print(f"     Sending query to IP: {ip_addr}\n")
        for counter in range(query_count):
            resolver = dns.resolver.Resolver()
            # Set the resolver IP Address
            resolver.nameservers = [ip_addr]
            # Set the timeout of the query
            resolver.timeout = 5
            resolver.lifetime = 5
            # Measure the time of the DNS response (Optional)
            start_time = time.time()
            # Note: if multiple prints are used, other processes might print in between them
            print(f"      ({counter}) Sending Query")
            try:
                answers = resolver.resolve(query_name, "A")
            except Exception:
                print(f"      ({counter}) Exception or timeout occurred for {query_name} ")
                answers = None
            measured_time = time.time() - start_time
            print(f"      ({counter}) Response time of {query_name}: {measured_time}")

            # Show the DNS response
            # if answers is not None:
            #     for answer in answers:
            #         print("        ", end="")
            #         print(answer)
            #     print(f"      RRset of {query_prefix}:")
            #     if answers.rrset is not None:
            #         print("        ", end="")
            #         print(answers.rrset)

            # Sleep after sending a query to the same resolver to not spam the resolver
            time.sleep(sleep_time_after_send)


# Build the query from packetloss rate and its type (prefetch phase or after the query becomes stale)
def build_query_from_pl_rate(packetloss_rate):
    query = "stale-test-" + str(packetloss_rate) + ".syssec-research.mmci.uni-saarland.de"
    print(f"  Built query: {query}")
    return query


# TODO
# Switch to the zone file of the corresponding packetloss rate
def switch_zone_file(packetloss_rate, zone_type):
    print(f"  Switching zone file to packetloss rate: {packetloss_rate}, zone type: {zone_type}")
    if zone_type == "prefetch":
        pass
    if zone_type == "postfetch":
        pass


# Create log folder
create_folder(directory_name_of_logs)

print("\n==== Experiment starting ====\n")

# TODO: Multithreading for each resolver IP Address we have

for current_packetloss_rate in packetloss_rates:

    print(f"Current Packetloss Rate: {current_packetloss_rate}")

    # Start packet capture
    capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, auth_interface_name, client_interface_name)

    # Set the right zone file for the prefetching phase
    switch_zone_file(current_packetloss_rate, "prefetch")

    # Send queries to resolvers to allow them to store the answer
    query_name_to_send = build_query_from_pl_rate(current_packetloss_rate)
    sleep_time_after_every_send = 0
    send_queries_to_resolvers(count_of_prefetch_queries, query_name_to_send, resolver_ip_addresses, sleep_time_after_every_send)

    # Wait until we are certain that the answer which is stored in the resolver is stale
    sleep_for_seconds(sleep_time_until_stale)

    # Simulate packetloss on authoritative Server
    simulate_packetloss(int(current_packetloss_rate), auth_interface_name)

    # Set the right zone file for the phase after the answer is stale
    switch_zone_file(current_packetloss_rate, "postfetch")

    # Send queries to resolvers again (and analyse the pcaps if the query was answered or not)
    send_queries_to_resolvers(1, query_name_to_send, resolver_ip_addresses, sleep_time_after_every_send)

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
