import subprocess
import concurrent.futures
import time
import os
import signal

import dns.resolver
import dns.reversename

# Execute this script as root user

# Time to wait after one domain query is sent to all resolver IP Addresses
# (Sleeping time between counters)
sleep_time = 1
# Time to sleep between packetloss configurations. (600 seconds = 10 minutes)
sleep_time_between_packetloss_config = 600

max_worker_count = 30

# Determines how many times the program sends the query
execute_count = 1

# The name of the folder that will be created to store all the tcpdump files inside it
directory_name_of_logs = "capture_logs_truncation"

# Minimum and maximum counter values for the domains
counter_min = 1   # Inclusive
counter_max = 50  # Exclusive 

# DNS Open Resolver IP Addresses
resolver_ip_addresses = [
    "94.140.14.14",  # AdGuard_1
    "94.140.14.15",  # AdGuard_2
	"94.140.14.140",  # AdGuard_3

    "185.228.168.168",  # CleanBrowsing_1
    "185.228.168.9",  # CleanBrowsing_2
	"185.228.168.10",  # CleanBrowsing_3

    "1.1.1.1",  # Cloudflare_1
    "1.1.1.2",  # Cloudflare_2
	"1.1.1.3",  # Cloudflare_3

    "216.146.35.35",  # Dyn_1

    "8.8.8.8",  # Google_1

    "64.6.64.6",  # Neustar_1
    "156.154.70.2",  # Neustar_2
	"156.154.70.3",  # Neustar_3
	"156.154.70.4",  # Neustar_4
	"156.154.70.5",  # Neustar_5

    "208.67.222.222",  # OpenDNS_1
    "208.67.222.2",  # OpenDNS_2
	"208.67.222.123",  # OpenDNS_3

    "9.9.9.9",  # Quad9_1
    "9.9.9.11",  # Quad9_2
	"9.9.9.10",  # Quad9_3

    "77.88.8.1",  # Yandex_1
    "77.88.8.2",  # Yandex_2
	"77.88.8.3",  # Yandex_3

    "209.244.0.3",  # Level3_1
    "209.244.0.4",  # Level3_2

    "199.85.126.10",  # Norton_1
    "199.85.126.20",  # Norton_2
    "199.85.126.30"  # Norton_3
]

# Set the interface names for packet capture with tcpdump
interface_1 = (
    "bond0"  # The interface of authoritative server without the packetloss filter
)
interface_2 = (
    "bond0"  # The interface of authoritative server with the packetloss filter applied
)
interface_3 = "bond0"  # The interface of client which sends the queries

# Packetloss rates to be simulated on the authoritative server
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100]


# Multiprocessing function that builds the all query names from a given IP address using a counter value
# and queries it to the resolver IP.
# Example query: <ip_addr>-<counter>-<packetloss_rate>.packetloss.syssec-research.mmci.uni-saarland.de
# Each call for this function runs at least (counter_max - counter_min) + (resolution time) seconds.
# Input is a list of these values: (ip_addr, packetloss_rate, counter_min, counter_max, sleep_time_between_counters):
def build_and_send_query_mp(args_list):
    # Read the parameters from the args_list
    ip_addr = args_list[0]
    packetloss_rate = str(args_list[1])
    counter_min = int(args_list[2])
    counter_max = int(args_list[3])
    sleep_between_counter = int(args_list[4])  # sleep_time_between_counters variable from line 12
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
            print(f"      Exception or timeout occurred for {query_prefix} ")
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


# Disables packetloss simulation
# Returns true if no exception occurred. False, if subprocess.run() created an exception.
def disable_packetloss_simulation(packetloss_rate, interface_name):
    print(f"  Disabling packetloss on {interface_name} interface with following commands:")
    disable_packetloss_1 = f'sudo iptables-legacy -D INPUT -d 139.19.117.11/32 --protocol udp --match udp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    print("    " + disable_packetloss_1)

    try:
        subprocess.run(
            disable_packetloss_1, shell=True, stdout=subprocess.PIPE, check=True
        )
        return True
    except Exception:
        print(
            f"  Exception occurred while removing {current_packetloss_rate}% packetloss rule on interface {interface_name} !!"
        )
        return False


# Sleep for a duration and show the remaining time on the console
def sleep_for_seconds(sleep_time_between_packetloss_config):    
    print("  Remaining time:")
    # Output how many seconds left to sleep
    for i in range(sleep_time_between_packetloss_config, 0, -1):
        print(f"{i}")
        time.sleep(1)
        # Delete the last output line of the console
        # to show the remaining time without creating new lines
        print("\033[A                             \033[A")


# Compress all the packet capture logs into a logs.zip file
def compress_log_files(directory_name_of_logs):
    compress_files_command = f"zip -r logs.zip {directory_name_of_logs}"
    print("Compressing all log files into a logs.zip file with the following command:")
    print("  " + compress_files_command)
    try:
        subprocess.run(compress_files_command, shell=True, stdout=subprocess.PIPE, check=True)
    except Exception:
        print("  Exception occurred while compressing the packet capture files !!")

# Simulate packetloss with iptables, in case of an exception, the code attempts to remove the rule
# Returns True when no error.
# Use `run()` with `check=True` when setting and deleting packetloss
# Otherwise process might not have finished before the next code runs
def simulate_packetloss(packetloss_rate, interface_name):
    packetloss_filter_command_1 = f'sudo iptables-legacy -A INPUT -d 139.19.117.11/32 --protocol udp --match udp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    print(
        f"  Simulating {packetloss_rate}% packetloss on interface {interface_name} with the following command:"
    )
    print("    " + packetloss_filter_command_1)
    try:
        subprocess.run(packetloss_filter_command_1, shell=True, stdout=subprocess.PIPE, check=True)
        return True
    except Exception:
        print(
            f"  Exception occurred while simulating {packetloss_rate}% packetloss on interface {interface_name} !!"
        )
        print(f"  Removing packetloss rule by calling disable_packetloss_simulation({packetloss_rate}, {interface_name})")
        disable_packetloss_simulation(packetloss_rate, interface_name)
        print(f"  Skipping {packetloss_rate}% packetloss configuration")
        return False


# Start 2 packet captures with tcpdump and return the processes
# In case of an exception, the list will be empty
def start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_1, interface_2, interface_3):
    # DF (don't fragment) bit set (IP)
    # Example filter:
    # 'ip[6] & 64 != 64'

    # Packet capture on authoritative server interface without the packetloss filter
    # source port should not be 53 but random.
    # The destination port is 53, but using that would only capture incoming, not outgoing traffic
    packet_capture_command_1 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_auth_{interface_1}_{current_packetloss_rate}.pcap -nnn -i {interface_1} "host 139.19.117.11 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (1) Running packet capture on {interface_1} interface with the following command:"
    )
    print("    " + packet_capture_command_1)
    
    # Packet capture on client interface
    packet_capture_command_2 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_client_{interface_3}_{current_packetloss_rate}.pcap -nnn -i {interface_3} "host 139.19.117.1 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (2) Running packet capture on {interface_3} interface with the following command:"
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

    # If current packetloss rate is 0, no need to execute packetloss filter
    if current_packetloss_rate != 0:
        if not (simulate_packetloss(current_packetloss_rate, interface_2)):
            # if simulate_packetloss() returns false, there was an exception while simulating packetloss
            # continue with the next packetloss configuration
            continue
            
    capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_1, interface_2, interface_3)        

    # Default value of execute_count is 1
    for exec_count in range(execute_count):
        # Send queries to defined resolver IP addresses
        print(f'  @@ Multiprocessing starting @@')
        # Measure the time of parallelization (Optional)
        start = time.perf_counter()
        # Context manager
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_worker_count) as executor:
            # Using list comprehension to build the results list
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
        print(
            f'  @@ Finished Multiprocessing with packetloss rate {current_packetloss_rate}% in {round(finish - start, 2)} seconds @@')

    # Disable packetloss on the authoritative server
    if current_packetloss_rate != 0:
        # True -> No error. False -> Exception occurred while disabling packetloss.
        disable_packetloss_simulation(current_packetloss_rate, interface_2)
        # Exit the program because continuing would stack the packetloss rules.
        # exit()
        # Continue with next packetloss simulation because the next packetloss rule will overwrite the old one
        # Not disabling the old packetloss rule won't be a problem.
        # continue

    # Terminate packet captures / all created processes
    print(f"  Terminating processes/stopping packet capture.")
    # Using .terminate() did not stop the packet captures    
    if len(capture_processes) > 0:
        for process in capture_processes:
            try:
                # Send the signal to all the process groups
                os.killpg(os.getpgid(process.pid), signal.SIGTERM) 
            except Exception:
                print(f"    Exception while terminating tcpdump") 
        print(f"    Sleeping for 1 seconds for tcpdumps to terminate")    
        sleep_for_seconds(1) 

    # Sleep for 10 minutes between packetloss configurations
    print(f"  {current_packetloss_rate}% Packetloss Config Finished")

    # If we are in the last iteration, no need to wait
    if current_packetloss_rate != packetloss_rates[-1]:
        print(
            f"  Sleeping for {sleep_time_between_packetloss_config} seconds for the next packetloss iteration."
        )
        sleep_for_seconds(sleep_time_between_packetloss_config)

print("\n==== Experiment ended ====\n")

# Compress all the packet capture logs into a logs.zip file
compress_log_files(directory_name_of_logs)
