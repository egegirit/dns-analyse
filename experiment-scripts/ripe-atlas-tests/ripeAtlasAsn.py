import subprocess
import time
import os
import sys
import json
from datetime import datetime, timedelta
from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
from ripe.atlas.sagan import DnsResult

ATLAS_API_KEY = "0c51be25-dfac-4e86-9d0d-5fef89ea4670"

# File name of the Atlas API specification from https://ihr.iijlab.net/ihr/en-us/metis/selection
asn_file_name = "830-probes-atlas-API.txt"

# Store the extracted asn_id's in this list
as_ids = []


# Builds the query name string that the probe will send to its resolver
# from the given counter value and packetloss rate
# Query structure: *.ripeatlas-<plrate>-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
# Example: *.ripeatlas-pl95-15.packetloss.syssec-research.mmci.uni-saarland.de
def build_query_name_from_counter_and_pl(current_counter, packetloss_rate):
    return "$p-$t.ripeatlas-" + "pl" + str(packetloss_rate) + "-" + str(current_counter) + \
           ".packetloss.syssec-research.mmci.uni-saarland.de"


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


# Create a source from asn_id and send a query with domain_name as query name
def send_query_from_asn(counter_value, packetloss_rate):
    print(f"  Building query name from current counter value: {counter_value}")
    # Build the query name from the counter value
    query_name = build_query_name_from_counter_and_pl(counter_value, packetloss_rate)
    print(f"    Built query name: {query_name}")

    print(f"  Creating DNS Query")
    dns = Dns(
        key=ATLAS_API_KEY,
        description=f"Ege Girit 1. Packetloss Experiment {counter_value}-{packetloss_rate}",
        protocol="UDP",
        af="4",

        # Enable more values as results
        include_abuf=True,
        include_qbuf=True,
        ttl=True,

        # Configure the DNS query
        query_class="IN",
        query_type="A",
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
        timeout=10000,
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

    print(f"  Creating request from source")

    seconds_to_add = 5
    print(f"Current time: {datetime.utcnow()}")

    past_time = datetime.utcnow()
    scheduled_time = past_time + timedelta(seconds=seconds_to_add)

    print(f"Request scheduled for: {scheduled_time}")

    # Create request from given probe ID
    atlas_request = AtlasCreateRequest(
        start_time=scheduled_time,
        key=ATLAS_API_KEY,
        measurements=[dns],
        # All probes with the selected asn_id's
        sources=sources,
        # Always set this to true
        # The measurement will only be run once
        is_oneoff=True
    )

    print(f"  Starting measurement")
    # Start the measurement
    (is_success, response) = atlas_request.create()

    time.sleep(1)
    print(f"\n    Results:\n")
    try:
        print(f"      is_success: {is_success}")
        print(f"      Response: {response}")
    except Exception:
        print("      Error while fetching results")

    # return is_success, response


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


# (OPTIONAL) Show the results of the experiment
def show_results(tuple_var):
    (is_success, response) = tuple_var
    # %%
    kwargs = {
        "msm_id": response["measurements"][0]
    }

    # Wait for the probes to upload their results before asking for the results
    # sleep_for_seconds(300)

    # No needed on authoritative Server
    # Results can be downloaded later using measurement ID's
    print(f"  Creating results")
    # Create results
    is_success, results = AtlasResultsRequest(**kwargs).create()

    # Print the measurement ID
    m = DnsResult.get(results[0])
    print(f"  Measurement ID: {m.measurement_id}")


# Compress all the packet capture logs into a logs.zip file
def compress_log_files(directory_name_of_logs):
    compress_files_command = f"zip -r logs.zip {directory_name_of_logs}"
    print("Compressing all log files into a logs.zip file with the following command:")
    print("  " + compress_files_command)
    try:
        subprocess.run(compress_files_command, shell=True, stdout=subprocess.PIPE, check=True)
    except Exception:
        print("  Exception occurred while compressing the packet capture files !!")


# (OPTIONAL) Start packet capture with tcpdump and return the processes
# In case of an exception, the processes object will be empty
def start_packet_capture(directory_name_of_logs, current_pl_rate, interface_name):
    # Packet capture on authoritative server interface without the packetloss filter
    # source port should not be 53 but random.
    # The destination port is 53, but using that would only capture incoming, not outgoing traffic
    packet_capture_command_1 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_auth_' \
                               f'{interface_name}_{current_pl_rate}.pcap -nnn -i {interface_name} ' \
                               f'"host 139.19.117.11 and (((ip[6:2] > 0) and ' \
                               f'(not ip[6] = 64)) or port 53)" '
    print(
        f"  Running packet capture on {interface_name} interface with the following command:"
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
    print(f"  Sleeping 1 second to let the packet captures start")
    time.sleep(1)
    return result_processes


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


print("\n==== 1. Experiment starting ====\n")

# (OPTIONAL) Create folder to store the packet capture logs of authoritative server
# create_folder(directory_name_of_logs)

# No packetloss simulation needed
current_packetloss_rate = 0

# (OPTIONAL) Start packet capture on the authoritative server
# capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_name)

# Extracts the asn values from the global variable probes_dict to the global as_ids list
extract_asn_values(asn_file_name)

counter = 0

# For each asn ID in as_ids, send a query from that probe and build the query with a counter value.
send_query_from_asn(counter, current_packetloss_rate)

# (OPTIONAL) Terminate packet captures / all created processes
# print(f"  Stopping packet capture.")
# if len(capture_processes) > 0:
#     for process in capture_processes:
#         try:
#             # Send the signal to all the process groups
#             os.killpg(os.getpgid(process.pid), signal.SIGTERM)
#         except Exception:
#             print(f"    Exception while terminating tcpdump")
#     print(f"    Sleeping for 1 seconds for tcpdump to terminate")
#     sleep_for_seconds(1)

# (OPTIONAL) Wait for the results to be uploaded
# sleep_for_seconds(300)
# for result in result_tuples:
#     show_results(result)

print("\n==== 1. Experiment ended ====\n")

# (OPTIONAL) Compress all the packet capture logs into a logs.zip file
# compress_log_files(directory_name_of_logs)
