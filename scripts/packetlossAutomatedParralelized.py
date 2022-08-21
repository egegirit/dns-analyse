import subprocess
import concurrent.futures
import time

import dns.resolver
import dns.reversename

# Execute this script as root user

# Time to wait after one domain query is sent to all resolver IP Addresses
# (Sleeping time between counters)
sleep_time = 1
# Time to sleep between packetloss configurations. (600 seconds = 10 minutes)
sleep_time_between_packetloss_config = 600

# Determines how many times the program sends the query
execute_count = 1

# The name of the folder that will be created to store all the tcpdump files inside of it
directory_name_of_logs = "capture_logs"

# Minimun and maximum counter values for the domains
counter_min = 1
counter_max = 11

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

# Set the interface names for packet capture with tcpdump
interface_1 = (
    "bond0"  # The interface of auhtoritative server without the packetloss filter
)
interface_2 = (
    "bond0"  # The interface of auhtoritative server with the packetloss filter applied
)
interface_3 = "bond0"  # The interface of client which sends the queries

# Packetloss rates to be simulated on the authoritative server
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]


# Multiprocessing function that builds the all query names from a given IP address using a counter value
# and queries it to the resolver IP.
# Example query: <ip_addr>-<counter>-<packetloss_rate>.packetloss.syssec-research.mmci.uni-saarland.de
# Each call for this function runs at least (counter_max - counter_min) + (resolution time) seconds.
# Input is a list of these values: (ip_addr, packetloss_rate, counter_min, counter_max, sleep_time):
def build_and_send_query_mp(args_list):  
    # Read the parameters from the args_list
    ip_addr = args_list[0]
    packetloss_rate = str(args_list[1])
    counter_min = int(args_list[2])
    counter_max = int(args_list[3])
    sleep_between_counter = int(args_list[4])
    # Build the query with its current counter value from the given resolver ip address
    for c in range(counter_min, counter_max):
        ip_addr_with_dashes = ip_addr.replace(".", "-")
        query_prefix = (
            ip_addr_with_dashes
            + "-"
            + str(c)
            + "-"
            + "pl"
            + str(packetloss_rate)
        )
        query = (
            query_prefix
            + "."
            + "packetloss.syssec-research.mmci.uni-saarland.de"
        )
        resolver = dns.resolver.Resolver()
        # Set the resolver IP Address
        resolver.nameservers = [ip_addr]
        # Set the timeout of the query
        resolver.timeout = 10
        resolver.lifetime = 10
        # Measure the time of the DNS response (Optional)
        start_time = time.time()
        # Note: if multiple prints are used, other processes might print in between them
        print(f"      Sending Query {query_prefix}\n        (Packetloss rate: {str(packetloss_rate)},\tIP: {ip_addr},"
              f"\tCounter: {c})")
        try:
            answers = resolver.resolve(query, "A")
        except Exception:
            print(f"      Exception occured for {query_prefix}")
            answers = None
        measured_time = time.time() - start_time
        print(f"      Response time of {query_prefix}: {measured_time}")   
        
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
        time.sleep(sleep_between_counter)
    print(f"    Finished sending all {packetloss_rate}% packetloss queries for: {ip_addr}")    
    return f"  Done sending for {query_prefix} and packetloss rate {packetloss_rate}%"      


# Create directory to store the packet capture log files
create_folder_command = f"mkdir {directory_name_of_logs}"
print(f"Creating a folder named {directory_name_of_logs} with the following command:")
print("  " + create_folder_command)

try:
    subprocess.run(create_folder_command, shell=True, stdout=subprocess.PIPE, check=True)
    print(f"Folder {directory_name_of_logs} created.")
except Exception:
    print(f"Folder not created.")


print("\n==== Experiment starting ====\n")
# Parallelized and automated query sending with different packetloss rates
# For each packetloss rate, create subprocesses for each IP Address, and send queries to all of them at the same time.
for current_packetloss_rate in packetloss_rates:
    print(f"### Current packetloss rate: {current_packetloss_rate} ###")

    # If current packetloss rate is 0, dont execute packetloss filter
    # Use `run()` with `check=True` when setting and deleting packetloss
    # Otherwise process might not have finished before the next code runs
    if current_packetloss_rate != 0:
        packetloss_filter_command_1 = f'sudo iptables-legacy -A INPUT -d 139.19.117.11/32 --protocol tcp --match tcp --dport 53 --match statistic --mode random --probability {current_packetloss_rate / 10} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
        packetloss_filter_command_2 = f'sudo iptables-legacy -A INPUT -d 139.19.117.11/32 --protocol udp --match udp --dport 53 --match statistic --mode random --probability {current_packetloss_rate / 10} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
        print(
            f"  Simulating {current_packetloss_rate}% packetloss on interface {interface_2} with the following command:"
        )
        print("    " + packetloss_filter_command_1)
        print("    " + packetloss_filter_command_2)
        subprocess.run(
            packetloss_filter_command_1, shell=True, stdout=subprocess.PIPE, check=True
        )
        subprocess.run(
            packetloss_filter_command_1, shell=True, stdout=subprocess.PIPE, check=True
        )

    # Packet capture on authoritative server interface without the packetloss filter
    # source port should not be 53 but random.
    # The destination port is 53, but using that would only capture incoming, not outgoing traffic
    packet_capture_command_1 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_auth1_{interface_1}_{current_packetloss_rate}.pcap -nnn -i {interface_1} "host 139.19.117.11 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (1) Running packet capture on {interface_1} interface with the following command:"
    )
    print("    " + packet_capture_command_1)
    process_2 = subprocess.Popen(
        packet_capture_command_1, shell=True, stdout=subprocess.PIPE
    )

    # Packet capture on authoritative server interface with the packetloss filter applied
    packet_capture_command_2 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_auth2_{interface_2}_{current_packetloss_rate}.pcap -nnn -i {interface_2} "host 139.19.117.11 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (2) Running packet capture on {interface_2} interface with the following command:"
    )
    print("    " + packet_capture_command_2)
    process_3 = subprocess.Popen(
        packet_capture_command_2, shell=True, stdout=subprocess.PIPE
    )

    # Packet capture on client interface
    packet_capture_command_3 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_client_{interface_3}_{current_packetloss_rate}.pcap -nnn -i {interface_3} "host 139.19.117.1 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (3) Running packet capture on {interface_3} interface with the following command:"
    )
    print("    " + packet_capture_command_3)
    process_4 = subprocess.Popen(
        packet_capture_command_3, shell=True, stdout=subprocess.PIPE
    )

    # If packet capture commands are delayed for a reason, the send query function executes before the packet capture.
    # Added 1 second sleep to avoid this.
    print(f"  Sleeping 1 second to let the packet captures start")
    time.sleep(1)
    
    # Default value of execute_count is 1
    for exec_count in range(execute_count):
        # Send queries to defined resolver IP addresses
        print(f'  @@ Multiprocessing starting @@')
        # Measure the time of parallelization (Optional)
        start = time.perf_counter()
        # Context manager
        with concurrent.futures.ProcessPoolExecutor() as executor:
            # Using list comprehention to build the results list
            # submit() schedules the callable to be executed and returns a 
            # future object representing the execution of the callable.
            results = [executor.submit(build_and_send_query_mp, [current_resolver_ip,
                                                                 current_packetloss_rate,
                                                                 counter_min,
                                                                 counter_max,
                                                                 sleep_time])
                        for current_resolver_ip in resolver_ip_addresses]

        finish = time.perf_counter()
        # Show the finished processes' outputs
        for f in concurrent.futures.as_completed(results):
            print(f.result())
        print(f'  @@ Finished Multiprocessing with packetloss rate {current_packetloss_rate}% in {round(finish-start, 2)} seconds @@')

    # Disable packetloss on the authoritative server
    if current_packetloss_rate != 0:
        print(
            f"  Disabling packetloss on {interface_2} interface with following commands:"
        )
        # disable_packetloss_1 = f"sudo tc qdisc del dev {interface_2} root"
        # disable_packetloss_2 = f"sudo tc -s qdisc ls dev {interface_2}"
        disable_packetloss_1 = f'sudo iptables-legacy -D INPUT -d 139.19.117.11/32 --protocol tcp --match tcp --dport 53 --match statistic --mode random --probability {current_packetloss_rate / 10} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
        disable_packetloss_2 = f'sudo iptables-legacy -D INPUT -d 139.19.117.11/32 --protocol udp --match udp --dport 53 --match statistic --mode random --probability {current_packetloss_rate / 10} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
        print("    " + disable_packetloss_1)
        print("    " + disable_packetloss_2)
        subprocess.run(
            disable_packetloss_1, shell=True, stdout=subprocess.PIPE, check=True
        )
        subprocess.run(
            disable_packetloss_2, shell=True, stdout=subprocess.PIPE, check=True
        )

    # Terminate packet captures / all created processes
    print(f"  Terminating processes/stopping packet capture.")
    process_2.terminate()
    process_3.terminate()
    process_4.terminate()

    # Sleep for 10 mins between packetloss configurations
    print(f"  {current_packetloss_rate}% Packetloss Config Finished")

    # If we are in the last iteration, no need to wait
    if current_packetloss_rate != 95:
        print(
            f"  Sleeping for {sleep_time_between_packetloss_config} seconds for the next packetloss iteration."
        )
        print("  Remaining time:")
        # time.sleep(sleep_time_between_packetloss_config)
        # Output how many seconds left to sleep
        for i in range(sleep_time_between_packetloss_config, 0, -1):
            print(f"{i}", end="\r", flush=True)
            time.sleep(1)

print("\n==== Experiment ended ====\n")

# Compress all the packet capture logs into a logs.zip file
compress_files_command = f"zip -r logs.zip {directory_name_of_logs}"
print("Compressing all log files into a logs.zip file with the following command:")
print("  " + compress_files_command)
subprocess.run(compress_files_command, shell=True, stdout=subprocess.PIPE, check=True)
