import subprocess
import concurrent.futures
import sys
import time
import os
import signal
import dns.resolver
import dns.name
import dns.message
import dns.query
import dns.flags
import string
import random
from datetime import datetime

####################################
# Execute this script as root user #
####################################

# Time to wait after one prefetch query is sent to a resolver IP Addresses
sleep_time_after_every_prefetch = 0.5

# For how many minutes we should keep send queries after prefetching phase
experiment_time_in_minutes = 360

max_worker_count = 30

# The TTL values that we will experiment with
ttl_values_of_records = [60, 120, 180, 600]

# Time to sleep in seconds between new TTL changes
cooldown_sleep_time = 600

# The probability that we will hit all the caches of the resolver.
# This probability is used to calculate the query count to send to the resolver
# in the prefetch phase
cache_hit_probability = 0.95

# The minimum number of queries to send to a resolver in the prefetch phase,
# even when the resolver has only 1 cache.
minimum_prefetch_query_count = 10
# After the required prefetch query count for a resolver is calculated, this value is added onto it
extra_query_count = 10

# active zone file path
# "/etc/bind/active.zone"
active_zone_file_path = "active.zone"

# active zone file path
# "/etc/bind/boilerplate.zone"
boilerplate_zone_file_path = "boilerplate.zone"

# Set the interface names for packet capture with tcpdump
auth_interface_name = "bond0"  # The interface of authoritative server
client_interface_name = "bond0"  # The interface of client

directory_name_of_logs = "packet_capture_logs_stale_duration2"

# Packetloss rates to be simulated on the authoritative server
packetloss_rates = [100]

# Stale record supporting resolvers
# "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "OpenDNS1", "Quad91", "Quad92"

# DNS Open Resolver IP Addresses
resolver_ip_addresses = [
    "1.1.1.1",  # Cloudflare 1     (one.one.one.one)
    "1.0.0.1",  # Cloudflare 2     (1dot1dot1dot1.cloudflare-dns.com)
    "216.146.35.35",  # Dyn 1  (resolver1.dyndnsinternetguide.com)
    "216.146.36.36",  # Dyn 2  (resolver2.dyndnsinternetguide.com )
    "208.67.222.222",  # OpenDNS 1  (dns.opendns.com )

    # TODO: Check if stale supported, add new stale supporting IPs
    "209.244.0.3",  # Level3_1
    "209.244.0.4",  # Level3_2

    "199.85.126.10",  # Norton_1
    "199.85.126.20",  # Norton_2
    "199.85.126.30"  # Norton_3
]

# Define how many caches does the resolver have
caches_of_resolvers = {
    "1.1.1.1": 18,  # Cloudflare 1
    "1.0.0.1": 18,  # Cloudflare 2
    "216.146.35.35": 3,  # Dyn 1
    "216.146.36.36": 3,  # Dyn 2
    "208.67.222.222": 16,  # OpenDNS 1

    "209.244.0.3": 2,  # Level3_1
	"209.244.0.4": 2,  # Level3_2

	"199.85.126.10": 4,  # Norton_1
	"199.85.126.20": 4,  # Norton_2
	"199.85.126.30": 4  # Norton_3
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
    except Exception as e:
        print(e)
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
    except Exception as e:
        print(e)
        print(
            f"  Exception occurred while removing {packetloss_rate}% packetloss rule on interface {interface_name} !!"
        )
        return False


# Start 2 packet captures with tcpdump and return the processes
# In case of an exception, the list will be empty
def start_packet_captures(directory_name_of_logs, current_packetloss_rate, auth_interface, client_interface, generated_chars, ttl_value):

    # Packet capture on authoritative server interface without the packetloss filter
    # source port should not be 53 but random.
    # The destination port is 53, but using that would only capture incoming, not outgoing traffic
    packet_capture_command_1 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_auth_{auth_interface}_{current_packetloss_rate}_{generated_chars}_TTL{str(ttl_value)}.pcap -nnn -i {auth_interface} "host 139.19.117.11 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (1) Running packet capture on {auth_interface} interface with the following command:"
    )
    print("    " + packet_capture_command_1)

    # Packet capture on client interface
    packet_capture_command_2 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_client_{client_interface}_{current_packetloss_rate}_{generated_chars}_TTL{str(ttl_value)}.pcap -nnn -i {client_interface} "host 139.19.117.1 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
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
    except Exception as e:
        print(e)
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
    except Exception as e:
        print(e)
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
    except Exception as e:
        print(e)
        print(f"Folder not created.")


def calculate_query_count_with_desired_probability(ip_addr, cache_count_of_resolver, desired_probability):
    global minimum_prefetch_query_count
    query_count = 1

    print(f"  {ip_addr} has {cache_count_of_resolver} caches")

    cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count)

    while cache_i_hit_total < desired_probability:
        query_count += 1
        cache_i_hit_total = 1 - (((cache_count_of_resolver - 1) / cache_count_of_resolver) ** query_count)

    print(f"  {desired_probability * 100}% Probability is met with {query_count} queries.")

    return max(query_count, minimum_prefetch_query_count)


def calculate_prefetch_query_count(ip_addr, phase, pl_rate, desired_probability):
    global extra_query_count
    global caches_of_resolvers
    if phase == "prefetch":
        return calculate_query_count_with_desired_probability(ip_addr, caches_of_resolvers[ip_addr], desired_probability) + extra_query_count
    elif phase == "stale":
        return 1


# Prefetch phase, send queries to resolvers to make them cache the entries
def send_queries_to_resolvers(ip_addr, pl_rate, generated_tokens, phase, desired_probability, ttl_value):
    global sleep_time_after_every_prefetch
    prefetch_query_timeout = 0.01

    print(f"\nSending query to IP: {ip_addr}")
    query_count = calculate_prefetch_query_count(ip_addr, phase, pl_rate, desired_probability)
    print(f"  Query Amount to send to the resolver: {query_count}")

    for counter in range(query_count):
        query_name = build_query(pl_rate, ip_addr, generated_tokens, ttl_value)
        print(f"   Query name: {query_name}")

        # Create Query
        request = dns.message.make_query(query_name, dns.rdatatype.A)
        print(f"      ({counter + 1}) Sending Query")

        try:
            dns.query.udp(request, ip_addr, timeout=prefetch_query_timeout)
        # Dont print timeout exceptions
        except dns.exception.Timeout:
            pass
            # print(f"Timeout")
        # Print all other exceptions
        except Exception as e:
            print(f"Exception occurred when sending prefetch query {query_name} for {ip_addr} (Not a timeout)")
            print(e)
        # Sleep after sending a query to the same resolver to not spam the resolver
        time.sleep(sleep_time_after_every_prefetch)


# Prefetch phase, send queries to resolvers to make them cache the entries
def stale_phase(ip_addr, generated_tokens, ttl_value):
    # Timeout value of the query in stale phase
    stale_query_timeout = 10
    stale_answer_count = 0
    no_answer_count = 0

    # If there was a stale record observed in the i-th iteration, mark the i-th element of list as 1
    stale_record_on_iterations = []

    print(f"\n  Sending query to IP: {ip_addr}")
    query_name = build_query(100, ip_addr, generated_tokens, ttl_value)
    print(f"   Query name: {query_name}")
    response = None

    # Keep sending queries for experiment_time_in_minutes minutes
    experiment_time_in_secs = experiment_time_in_minutes * 60
    start_time = time.time()
    print(f"   Start time: {start_time}")
    current_time = 0
    continue_experiment = True

    x = 0
    # Keep sending queries until max iteration count is reached
    while continue_experiment:
        print(f"    {x + 1}. iteration for {ip_addr}")
        request = dns.message.make_query(query_name, dns.rdatatype.A)
        print(f"      Sending Query")

        # Send query and wait for response
        try:
            response = dns.query.udp(request, ip_addr, timeout=stale_query_timeout)
        except Exception as e:
            print(f"      Exception or timeout occurred for {query_name} ")
            print(e)
        # Extract A record and TTL from response
        try:
            if response is not None:
                if not response.answer:
                    print(f"        No Answer")
                    no_answer_count += 1
                    stale_record_on_iterations.append(0)
                # If Answer was not empty, process
                else:
                    stale_answer_count += 1
                    stale_record_on_iterations.append(1)
                    for a in response.answer:
                        dataset = a.to_rdataset()
                        if "A" in str(dataset):
                            a_record = str(dataset).split("A ")[1]
                            print(f"        A record: {a_record}")
                        ttl = int(dataset.ttl)
                        print(f"        TTL:  {ttl}")
            else:
                stale_record_on_iterations.append(-1)
        except Exception as e:
            print(f"        Error reading the response of query {query_name}")
            print(e)
        # Wait TTL
        time.sleep(ttl_value)

        # Calculate the elapsed time and check we reached the time limit for the experiment
        current_time = time.time()
        elapsed_time = current_time - start_time
        remaining_time = experiment_time_in_secs - elapsed_time
        if remaining_time <= 0:
            continue_experiment = False
        else:
            print(f"        ({int(remaining_time)} seconds remaining for {ip_addr})")

        x += 1

    print(f"Ending stale phase for {ip_addr}")
    print(f"Results of {ip_addr}:")
    print(f"  stale_answer_count: {stale_answer_count}")
    print(f"  no_answer_count: {no_answer_count}")
    print(f"  stale_record_on_iterations: {stale_record_on_iterations}")


# Build the query from packetloss rate and its type (prefetch phase or after the query becomes stale)
# Example: stale-9-9-9-11-100-KGN-TTL130.packetloss.syssec-research.mmci.uni-saarland.de
def build_query(packetloss_rate, ip_addr, generated_tokens, ttl_value):
    ip_addr_with_dashes = ip_addr.replace(".", "-")
    query = f"stale-{ip_addr_with_dashes}-{str(packetloss_rate)}-{generated_tokens}-TTL{str(ttl_value)}.packetloss.syssec-research.mmci.uni-saarland.de"
    # print(f"  Built query: {query}")
    return query


# Switch to the zone file of the corresponding packetloss rate
def switch_zone_file(zone_type, generated_tokens, pl_rate, ttl_value):
    print(f"  Creating {zone_type} zone file with generated chars {generated_tokens}, packetloss rate {pl_rate} and TTL value {ttl_value}")

    a_record_ip_addr = ""

    if zone_type == "prefetch":
        a_record_ip_addr = str(pl_rate)
    elif zone_type == "stale":
        a_record_ip_addr = str(pl_rate + 1)
    else:
        print("Undefined zone type!")
        sys.exit()

    a_record_end = a_record_ip_addr + "." + a_record_ip_addr + "." + a_record_ip_addr

    # Write the contents of boilerplate zone file to the active.zone file
    # Opening the file with "w" mode erases the previous content of the file
    with open(boilerplate_zone_file_path, 'r') as boilerplate_file, open(active_zone_file_path, 'w') as active_zone_file:
        # Read content from first zone file
        for line in boilerplate_file:
            # When writing the TTL part of the zone file, modify the TTL value
            if "$TTL " in line:
                ttl_line = f"$TTL {ttl_value}\n"
                active_zone_file.write(ttl_line)
            else:
                # Append content to active zone file line by line
                active_zone_file.write(line)

    a_records = ""
    created_A_record = ""  # DEBUG

    f = open(active_zone_file_path, 'a')

    for ip_addr in resolver_ip_addresses:
        ip_addr_with_dashes = ip_addr.replace(".", "-")
        a_records = f"stale-{ip_addr_with_dashes}-{str(pl_rate)}-{generated_tokens}-TTL{ttl_value}\tIN\tA\t139.{a_record_end}\n"
        created_A_record += a_records
        f.write(a_records)
    f.close()

    print(f"\nCreated zone file and A records for {zone_type}, {pl_rate} Packetloss rate:")
    print(created_A_record)

    # Reload bind/dns services
    reload_command_1 = f"sudo rndc reload"
    print(
        f"  Reloading bind9 with the following command:"
    )
    print("    " + reload_command_1)

    try:
        subprocess.run(reload_command_1, shell=True, stdout=subprocess.PIPE, check=True)
    except Exception as e:
        print(
            f"  Exception occurred while reloading bind !"
        )
        print(e)


# Generate x random characters to add it at the end of the query names in the zone file
def generate_random_characters(length):
    result = ""
    for _ in range(length):
        result += random.choice(string.ascii_letters)
    return result


# Create log folder
create_folder(directory_name_of_logs)

print("\n==== Experiment starting ====\n")
print(f"Current time: {datetime.utcnow()}")

generated_chars = generate_random_characters(3)
print(f"Generated random tokens: {generated_chars}")

for current_ttl in ttl_values_of_records:
    print(f"\nCurrent TTL Value: {current_ttl}")

    for current_packetloss_rate in packetloss_rates:

        print(f"Current Packetloss Rate: {current_packetloss_rate}%")

        # Start packet capture
        capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, auth_interface_name,
                                                  client_interface_name, generated_chars, current_ttl)

        # Set the right zone file for the prefetching phase
        switch_zone_file("prefetch", generated_chars, current_packetloss_rate, current_ttl)

        print(f"\nPREFETCH PHASE BEGIN, SENDING QUERIES")

        # Context manager
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_worker_count) as executor:
            results = [executor.submit(send_queries_to_resolvers,
                                       current_resolver_ip,
                                       current_packetloss_rate,
                                       generated_chars,
                                       "prefetch",
                                       cache_hit_probability,
                                       current_ttl)
                       for current_resolver_ip in resolver_ip_addresses]

        print(f"\nPREFETCH PHASE DONE\n")

        print(f"Sleeping for {current_ttl} seconds until the records are stale")

        # Wait until we are certain that the answer which is stored in the resolver is stale
        sleep_for_seconds(current_ttl)

        # Simulate packetloss on authoritative Server
        simulate_packetloss(int(current_packetloss_rate), auth_interface_name)

        # Set the right zone file for the phase after the answer is stale
        switch_zone_file("stale", generated_chars, current_packetloss_rate, current_ttl)

        # Send queries to resolvers again (and analyse the pcaps if the query was answered or not)
        print(f"\nSTALE PHASE BEGIN, SENDING QUERIES")

        # Context manager
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_worker_count) as executor:
            results = [executor.submit(stale_phase,
                                       current_resolver_ip,
                                       generated_chars,
                                       current_ttl)
                       for current_resolver_ip in resolver_ip_addresses]

        print(f"\nSTALE PHASE DONE\n")
        print(f"Sleeping for {cooldown_sleep_time} seconds (Cooldown)")

        # Cooldown between packetloss configurations
        sleep_for_seconds(cooldown_sleep_time)

        # Terminate packet captures / all created processes
        print(f"  Stopping packet capture")
        # Using .terminate() doesn't stop the packet capture
        if len(capture_processes) > 0:
            for process in capture_processes:
                try:
                    # Send the SIGTERM signal to all the process groups
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except Exception as e:
                    print(f"    Exception while terminating tcpdump")
                    print(e)
            print(f"    Sleeping for 1 seconds for tcpdump to terminate")
            sleep_for_seconds(1)

        disable_packetloss_simulation(current_packetloss_rate, auth_interface_name)

    print("\n==== Experiment ended ====\n")

# Compress all the packet capture logs into a logs.zip file
compress_log_files(directory_name_of_logs)
