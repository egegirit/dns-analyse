import subprocess
import sys
import time
import os
import signal
from datetime import datetime, timedelta
from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest
# from ripe.atlas.sagan import DnsResult

####################################
# Execute this script as root user #
####################################

ATLAS_API_KEY = "0c51be25-dfac-4e86-9d0d-5fef89ea4670"

# File name of the Atlas API specification from https://ihr.iijlab.net/ihr/en-us/metis/selection
asn_file_name = "1000-probes.txt"

directory_name_of_logs = "stale_record_ripe_atlas_logs"
file_name_of_msm_logs = "selected-probes-logs.txt"

# Store the extracted asn_id's in this list
as_ids = []

# Time to wait after one domain query is sent to all resolver IP Addresses
# (Sleeping time between counters)
sleep_time_between_prefetch_queries = 2
# Sleep for 10 Minutes for delayed packets after stale phase
sleep_time_after_stale_phase = 600

stale_phase_duration_in_seconds = 7200
stale_phase_query_send_frequency_in_seconds = 60
prefetching_query_count_for_each_probe = 60

# Minimum and maximum counter values for the domains
counter_min = 0  # Inclusive
counter_max = 20  # Exclusive

timeout_value = 30000

# Set the interface names for packet capture with tcpdump
interface_name = "bond0"  # The interface of authoritative server without the packetloss filter

# Packetloss rates to be simulated on the authoritative server
packetloss_rates = [100]


# Extract the asn values from the global probe_dict variable
# and store them in the global list as_ids
# We create atlas sources from the id's stored in as_ids
def extract_asn_values(text_file_name):
    print(f"Reading the asn values from file: {text_file_name}")

    # This text file contains the Atlas API specification of the probe selection
    # from https://ihr.iijlab.net/ihr/en-us/metis/selection
    f = open(text_file_name, "r")
    probe_dict = json.loads(f.read())

    global as_ids

    # Get the probe count
    values = list(probe_dict.values())[0]
    probe_count = len(values)

    # Exit program if no probes found
    if probe_count <= 0:
        print(f"No probes found: {probe_count}")
        sys.exit()

    print(f"  Probe count: {probe_count}")

    # Extract the asn values from the given probes
    for index in range(probe_count):
        as_ids.append(values[index]['value'])
        print(f"  Asn Value: {values[index]['value']}")


# Disables packetloss simulation
# Returns true if no exception occurred. False, if subprocess.run() created an exception.
def disable_packetloss_simulation(packetloss_rate, interface_name_for_capture):
    print(f"  Disabling packetloss on {interface_name_for_capture} interface with following commands:")
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
            f"  Exception occurred while removing {current_packetloss_rate}% packetloss rule on interface {interface_name} !!"
        )
        return False


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


# Simulate packetloss with iptables, in case of an exception, the code attempts to remove the rule
# Returns True when no error.
# Use `run()` with `check=True` when setting and deleting packetloss
# Otherwise process might not have finished before the next code runs
def simulate_packetloss(packetloss_rate, interface_name_for_capture):
    packetloss_filter_command_1 = f'sudo iptables-legacy -A INPUT -d 139.19.117.11/32 --protocol tcp --match tcp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    packetloss_filter_command_2 = f'sudo iptables-legacy -A INPUT -d 139.19.117.11/32 --protocol udp --match udp --dport 53 --match statistic --mode random --probability {packetloss_rate / 100} --match comment --comment "Random packetloss for Ege Girit Bachelor" --jump DROP'
    print(
        f"  Simulating {packetloss_rate}% packetloss on interface {interface_name_for_capture} with the following command:"
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


# Start 2 packet captures with tcpdump and return the processes
# In case of an exception, the list will be empty
def start_packet_captures(directory_name, current_pl_rate, interface_name_for_capture):
    # Packet capture on authoritative server interface without the packetloss filter
    # source port should not be 53 but random.
    # The destination port is 53, but using that would only capture incoming, not outgoing traffic
    packet_capture_command_1 = f'sudo tcpdump -w ./{directory_name}/tcpdump_log_auth1_{interface_name}_{current_pl_rate}.pcap -nnn -i {interface_name_for_capture} "host 139.19.117.11 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
    print(
        f"  (1) Running packet capture on {interface_name} interface with the following command:"
    )
    print("    " + packet_capture_command_1)

    # Store the process objects here and return it as output
    result_processes = []

    try:
        process_1 = subprocess.Popen(
            packet_capture_command_1, shell=True, stdout=subprocess.PIPE, preexec_fn=os.setsid
        )
        result_processes.append(process_1)
    except Exception:
        print("    Packet capture failed!")
        return result_processes  # Empty list

    # If packet capture commands are delayed for a reason, the send_query function executes before the packet capture.
    # Added 1-second sleep to avoid this.
    print(f"  Sleeping 1 second to let the packet capture start")
    time.sleep(1)
    return result_processes


# Builds the query name string that the probe will send to its resolver
# from the given counter value and packetloss rate
# Query structure: *.ripeatlas-<plrate>-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
# Example: *.ripeatlas-pl95-15.packetloss.syssec-research.mmci.uni-saarland.de
def build_query_name_from_counter_and_pl(current_counter):
    return "$p-$t.ripeatlas-" + str(current_counter) + ".packetloss.syssec-research.mmci.uni-saarland.de"


# Create a source from asn_id and send a query with domain_name as query name
def start_prefetching_phase():
    print(f"  Building query name")
    # Build the query name from the counter value
    query_name = build_query_name_from_counter_and_pl(1)
    print(f"    Built query name: {query_name}")

    print(f"  Creating DNS Query")
    dns = Dns(
        key=ATLAS_API_KEY,
        description=f"Ege Girit Stale Record Experiment Prefetching Phase",
        protocol="UDP",
        af="4",

        # Enable more values as results
        include_abuf=True,
        include_qbuf=True,
        ttl=True,

        # Configure the DNS query
        query_class="IN",
        query_type="A",
        # Domain name: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
        query_argument=query_name,
        use_macros=True,
        # Each probe prepends its probe number and a timestamp to the DNS query argument to make it unique
        prepend_probe_id=False,

        # Use the probe's list of local resolvers instead of specifying a target to use as the resolver.
        use_probe_resolver=True,
        # Recursion Desired flag (RD, RFC1035)
        set_rd_bit=True,
        # DNSSEC OK flag (DO, RFC3225)
        set_do_bit=True,

        # Timeout in milliseconds
        timeout=timeout_value,
        # How often to retry the measurement
        retry=0,

        udp_payload_size=1200,
    )

    global as_ids
    print(f"  Creating sources from the selected asn ID's")

    # For each asn_id that is given in the probes_dict, create a source
    # using the asn_id to the sources list
    sources = []
    for as_id in as_ids:
        source = AtlasSource(
            type="asn",
            value=as_id,
            requested=1,
            tags_include=["system-resolves-a-correctly", "system-ipv4-works", "system-ipv4-stable-1d",
                          "system-ipv4-stable-30d", "system-ipv4-stable-90d"]
        )
        sources.append(source)

    print(f"  Starting Prefetching Phase")

    start_time = time.time()
    print(f"    Start time: {start_time}")

    # Send prefetching queries
    for i in range(prefetching_query_count_for_each_probe):
        print(f"    Creating request from source")

        seconds_to_add = 1
        # print(f"    Current time: {datetime.utcnow()}")

        past_time = datetime.utcnow()
        scheduled_time = past_time + timedelta(seconds=seconds_to_add)

        print(f"    Request scheduled for: {scheduled_time}")

        # Create request from given probe ID
        atlas_request = AtlasCreateRequest(
            start_time=scheduled_time,
            # stop_time=1671389437,
            key=ATLAS_API_KEY,
            measurements=[dns],
            # All probes with the selected asn_id's
            sources=sources,
            # Always set this to true
            # The measurement will only be run once
            is_oneoff=False
        )

        print(f"    {i}. Iteration in Prefetching Phase")
        (is_success, response) = atlas_request.create()

        time.sleep(sleep_time_between_prefetch_queries)
        print(f"\n      Results of {i}. Prefetching Iteration:\n")
        try:
            print(f"      is_success: {is_success}")
            print(f"      Response: {response}")
            msm_ids_of_experiment = (is_success, response)
            create_measurement_id_logs(directory_name_of_logs, file_name_of_msm_logs, msm_ids_of_experiment)
        except Exception:
            print("      Error while fetching/logging results")

    print(f"== Prefetching Phase Over ==")


# Send queries from probes using the ASN every x seconds till the duration of the experiment is reached
def start_stale_phase():
    print(f"Building query name")
    # Build the query name from the counter value
    query_name = build_query_name_from_counter_and_pl(1)
    print(f"    Built query name: {query_name}")

    print(f"Creating DNS Query")
    dns = Dns(
        key=ATLAS_API_KEY,
        description=f"Ege Girit Stale Record Experiment Prefetching Phase",
        protocol="UDP",
        af="4",

        # Enable more values as results
        include_abuf=True,
        include_qbuf=True,
        ttl=True,

        # Configure the DNS query
        query_class="IN",
        query_type="A",
        # Domain name: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
        query_argument=query_name,
        use_macros=True,
        # Each probe prepends its probe number and a timestamp to the DNS query argument to make it unique
        prepend_probe_id=False,

        # Use the probe's list of local resolvers instead of specifying a target to use as the resolver.
        use_probe_resolver=True,
        # Recursion Desired flag (RD, RFC1035)
        set_rd_bit=True,
        # DNSSEC OK flag (DO, RFC3225)
        set_do_bit=True,

        # Timeout in milliseconds
        timeout=timeout_value,
        # How often to retry the measurement
        retry=0,

        udp_payload_size=1200,
    )

    global as_ids
    print(f"Creating sources from the selected asn ID's")

    # For each asn_id that is given in the probes_dict, create a source
    # using the asn_id to the sources list
    sources = []
    for as_id in as_ids:
        source = AtlasSource(
            type="asn",
            value=as_id,
            requested=1,
            tags_include=["system-resolves-a-correctly", "system-ipv4-works", "system-ipv4-stable-1d",
                          "system-ipv4-stable-30d", "system-ipv4-stable-90d"]
        )
        sources.append(source)

    print(f" Starting Stale Phase")

    start_time = time.time()
    print(f"    Start time: {start_time}")
    current_time = 0
    continue_experiment = True

    # Send prefetching queries
    i = 1
    while continue_experiment:
        print(f"    Creating request from source")

        seconds_to_add = 1
        # print(f"    Current time: {datetime.utcnow()}")

        past_time = datetime.utcnow()
        scheduled_time = past_time + timedelta(seconds=seconds_to_add)

        print(f"    Request scheduled for: {scheduled_time}")

        # Create request from given probe ID
        atlas_request = AtlasCreateRequest(
            start_time=scheduled_time,
            # stop_time=1671389437,
            key=ATLAS_API_KEY,
            measurements=[dns],
            # All probes with the selected asn_id's
            sources=sources,
            # Always set this to true
            # The measurement will only be run once
            is_oneoff=False
        )

        print(f"    {i}. Iteration in Stale Phase")
        (is_success, response) = atlas_request.create()

        time.sleep(sleep_time_between_prefetch_queries)
        print(f"\n      Results of {i}. Stale Iteration:\n")
        try:
            print(f"      is_success: {is_success}")
            print(f"      Response: {response}")
            msm_ids_of_experiment = (is_success, response)
            create_measurement_id_logs(directory_name_of_logs, file_name_of_msm_logs, msm_ids_of_experiment)
        except Exception:
            print("      Error while fetching/logging results")

        # Calculate the elapsed time and check if we reached the time limit for the experiment
        current_time = time.time()
        elapsed_time = current_time - start_time
        remaining_time = stale_phase_duration_in_seconds - elapsed_time
        if remaining_time <= 0:
            continue_experiment = False
        else:
            print(f"        ({int(remaining_time)} seconds remaining for {ip_addr})")

        i += 1

    print(f"== Stale Phase Over ==")


# Create measurement logs in runtime so that if the program crashes, we can see the results obtained till the crash
def create_measurement_id_logs(directory_name, file_name_to_save, measurement_tuple, counter_value):
    currrent_working_path = os.path.dirname(os.path.realpath(__file__))
    print(f"Working path: {currrent_working_path}")
    save_path = "/" + directory_name

    # Get the full path of the directory that we will save the log file into
    file_path = currrent_working_path + save_path
    #  os.path.join(currrent_working_path, save_path, file_name_to_save)
    print(f"Save: {save_path}")
    print(f"Full path of log directory: {file_path}")

    if not os.path.exists(file_path):
        os.makedirs(file_path)
        print(f"Creating directory {file_path}")

    # Open/Create the log file in the given directory
    f = open(file_path + "/" + file_name_to_save, "a")

    f.write("Counter: " + str(counter_value) + " -> "
            + str(measurement_tuple) + "\n")
    print(f"Wrote to file: \nCounter: " + str(counter_value) + " -> "
            + str(measurement_tuple))

    f.close()


# Create directory with the given name
def create_folder(directory_name):
    create_folder_command = f"mkdir {directory_name}"
    print(f"Creating a folder named {directory_name} with the following command:")
    print("  " + create_folder_command)

    try:
        subprocess.run(create_folder_command, shell=True, stdout=subprocess.PIPE, check=True)
        print(f"Folder {directory_name} created.")
    except Exception:
        print(f"Folder not created.")


# Create log directory to store measurement results
create_folder(directory_name_of_logs)

# Extracts the asn values from the global variable probes_dict to the global as_ids list
extract_asn_values(asn_file_name)

print("\n==== Experiment starting ====\n")
# Parallelized and automated query sending with different packetloss rates
# For each packetloss rate, create subprocesses for each IP Address, and send queries to all of them at the same time.
for current_packetloss_rate in packetloss_rates:
    print(f"### Packetloss rate to simulate: {current_packetloss_rate} ###")

    # Start packet capture on interface_name of the authoritative server, store the pcap in directory_name_of_logs
    capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_name)

    # Start prefetching phase
    start_prefetching_phase()

    # Sleep till the records are stale
    sleep_for_seconds(ttl_value_of_a_records + 10)

    # Simulate 100% Packetloss on the server for the stale phase
    if current_packetloss_rate != 0:
        if simulate_packetloss(current_packetloss_rate, interface_name):
            # if simulate_packetloss() returns false, there was an exception while simulating packetloss
            # continue with the next packetloss configuration
            print(f"  {current_packetloss_rate}% Packetloss simulation successful")
        else:
            print(f"  {current_packetloss_rate}% Packetloss simulation failed!")

    # Start sending stale queries
    # Keep sending until the experiment finish time is reached
    start_stale_phase()

    # Sleep for 10 Minutes for delayed packets
    sleep_for_seconds(sleep_time_after_stale_phase)

    # Disable simulation on the authoritative server
    if current_packetloss_rate != 0:
        # Output of disable_packetloss_simulation():
        # True -> No error. False -> Exception occurred while disabling packetloss.
        disable_packetloss_simulation(current_packetloss_rate, interface_name)

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
