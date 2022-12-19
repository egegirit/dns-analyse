import subprocess
import sys
import time
import os
import signal
from datetime import datetime, timedelta
from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest
# from ripe.atlas.sagan import DnsResult
import json

####################################
# Execute this script as root user #
####################################

ATLAS_API_KEY = "0c51be25-dfac-4e86-9d0d-5fef89ea4670"

# File name of the Atlas API specification from https://ihr.iijlab.net/ihr/en-us/metis/selection
asn_file_name = "750-probes.txt"

# Folder to store pcaps and experiment logs
directory_name_of_logs = "stale_record_ripe_atlas_logs"

# File name to create for the experiment logs
file_name_of_msm_logs = "ripe-stale-experiment-logs.txt"

# Store the extracted asn_id's in this list
as_ids = []

# Interval meaning:
# The number of seconds each probe participating in the measurement
# will wait before attempting to perform the measurement again
# Intervall value must be equal or greater than 60

# Send query every x seconds in prefetching phase (send frequency)
prefetching_query_interval_in_seconds = 60
# Keep sending queries in prefetching phase till the duration is reached
prefetching_duration_in_seconds = 3600  # prefetching_query_interval_in_seconds * 60
# In stale phase, send queries from all probes every x seconds (send frequency)
stale_phase_query_send_interval_in_seconds = 60
# How long the stale phase should last
stale_phase_duration_in_seconds = 7200

# Sleep for 10 Minutes for delayed packets after stale phase
sleep_time_after_stale_phase = 600

# TTL value of the A records in the auth server
# After prefetching phase, we have to wait for TTL Value seconds to
# wait for the records to become stale on probe resolvers
ttl_value_of_a_records = 60

# Timeout value of a dns query
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
    print("    Starting packet capture")
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
def build_query_name_from_counter_and_pl():
    return "$p-$t.ripeatlas-stale.packetloss.syssec-research.mmci.uni-saarland.de"


# Send queries from probes using the ASN every x seconds till the duration of the experiment is reached
def start_experiment(interval_value, experiment_duration):
    print(f"  Building query name")
    # Build the query name from the counter value
    query_name = build_query_name_from_counter_and_pl()
    print(f"    Built query name: {query_name}")
    print(f"  Creating DNS Query with interval {interval_value} and duration {experiment_duration}")
    dns = Dns(
        key=ATLAS_API_KEY,
        description=f"Ege Girit Stale Record Experiment",
        protocol="UDP",
        af="4",

        # Enable more values as results
        include_abuf=True,
        include_qbuf=True,
        ttl=True,

        interval=interval_value,
        # start_time=,
        # stop_time=stop_time_of_prefetch,

        # Configure the DNS query
        query_class="IN",
        query_type="A",
        # Domain name: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
        query_argument=query_name,
        use_macros=True,
        # Each probe prepends its probe number and a timestamp to the DNS query argument to make it unique
        prepend_probe_id=True,
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

    print(f"  Source created")
    print(f"  Starting Experiment")
    print(f"    Creating request from source")

    # Calculate stop time of prefetching phase by adding the variable prefetching_duration_in_seconds
    # to the current time (MUST BE UTC time for ripe atlas!)
    current_time = datetime.utcnow()
    stop_time_of_experiment = current_time + timedelta(seconds=experiment_duration)

    # Create request from given probe ID
    atlas_request = AtlasCreateRequest(
        # start_time=scheduled_time,  # No start time -> start as soon as possible
        stop_time=stop_time_of_experiment,
        key=ATLAS_API_KEY,
        measurements=[dns],
        # All probes with the selected asn_id's
        sources=sources,
        # Always set this to true
        # The measurement will only be run once
        is_oneoff=False
    )

    print(f"    Request created and stop time set to: {stop_time_of_experiment}")
    (is_success, response) = atlas_request.create()

    print(f"\n      Result:\n")
    try:
        print(f"      is_success: {is_success}")
        print(f"      Response: {response}")
        msm_ids_of_experiment = (is_success, response)
        create_measurement_id_logs(directory_name_of_logs, file_name_of_msm_logs, msm_ids_of_experiment)
    except Exception:
        print("      Error while fetching/logging results")


# Create measurement logs in runtime so that if the program crashes, we can see the results obtained till the crash
def create_measurement_id_logs(directory_name, file_name_to_save, measurement_tuple):
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)
        print(f"Creating directory {directory_name}")

    # Open/Create the log file in the given directory
    f = open(directory_name + "/" + file_name_to_save, "a")

    f.write(str(measurement_tuple) + "\n")
    print(f"Wrote to file: \nCounter: " + str(measurement_tuple))

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
    # Start packet capture on interface_name of the authoritative server, store the pcap in directory_name_of_logs
    capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_name)

    # Start prefetching phase
    print(f"Starting prefetching phase")
    start_experiment(prefetching_query_interval_in_seconds, prefetching_duration_in_seconds)
    # Wait for the duration of the prefetching experiment
    print(f"Sleeping for {prefetching_duration_in_seconds} during the ripe atlas experiment")
    sleep_for_seconds(prefetching_duration_in_seconds)
    print(f"Ending prefetching phase")

    # Sleep till the records are stale
    print(f"Waiting for TTL ({ttl_value_of_a_records}) seconds before stale phase")
    # +5 because we don't want to begin early, if ripe atlas processes the request a little bit late.
    sleep_for_seconds(ttl_value_of_a_records + 5)

    print(f"Packetloss rate to simulate: {current_packetloss_rate}")
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
    print(f"Starting stale phase")
    start_experiment(stale_phase_query_send_interval_in_seconds, stale_phase_duration_in_seconds)
    # Wait for the duration of the prefetching experiment
    print(f"Sleeping for {stale_phase_duration_in_seconds} during the ripe atlas experiment")
    sleep_for_seconds(stale_phase_duration_in_seconds)
    print(f"Ending stale phase")

    # Sleep for 10 Minutes for delayed packets
    print(f"Sleeping for {sleep_time_after_stale_phase} (Cooldown for delayed packets)")
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
