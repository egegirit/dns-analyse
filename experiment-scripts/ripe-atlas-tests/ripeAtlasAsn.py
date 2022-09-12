import subprocess
import concurrent.futures
import time
import os
import sys
import signal
import dns.resolver
import dns.reversename
from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
from ripe.atlas.sagan import DnsResult
from pprint import pprint
from datetime import datetime

# Execute this script as root user

# Time to wait after one domain query is sent to all resolver IP Addresses
# (Sleeping time between counters)
sleep_time = 1
# Time to sleep between packetloss configurations. (600 seconds = 10 minutes)
sleep_time_between_packetloss_config = 600

# Minimum and maximum counter values for the domains
counter_min = 1  # Inclusive
counter_max = 50  # Exclusive 

# Set the interface names for packet capture with tcpdump
interface_name = "bond0"  # The interface of authoritative server without the packetloss filter

directory_name_of_logs = "packet_capture_logs"

# Packetloss rates to be simulated on the authoritative server
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

counter_min = 0  # Inclusive
counter_max = 50  # Exclusive

ATLAS_API_KEY = ""  # 0c51be25-dfac-4e86-9d0d-5fef89ea4670

# Atlas API specification from the probe selection website https://ihr.iijlab.net/ihr/en-us/metis/selection
probe_dict = {"probes":
    [
        {
            "type": "asn",
            "value": 24521,
            "requested": 1
        },  # ...
    ]}

# Store the extracted probe id's in a list
as_ids = []


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
            f"  Exception occured while removing {current_packetloss_rate}% packetloss rule on interface {interface_name} !!"
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


# Start 2 packet captures with tcpdump and return the processes
# In case of an exception, the list will be empty
def start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_name):
    # Packet capture on authoritative server interface without the packetloss filter
    # source port should not be 53 but random.
    # The destination port is 53, but using that would only capture incoming, not outgoing traffic
    packet_capture_command_1 = f'sudo tcpdump -w ./{directory_name_of_logs}/tcpdump_log_auth1_{interface_name}_{current_packetloss_rate}.pcap -nnn -i {interface_1} "host 139.19.117.11 and (((ip[6:2] > 0) and (not ip[6] = 64)) or port 53)"'
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
    print(f"  Sleeping 1 second to let the packet captures start")
    time.sleep(1)
    return result_processes


# Builds the query name string that the probe will send to the resolver
# from the given counter value
# Query structure: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
def build_query_name_from_counter(counter, packetloss_rate):
    if counter is not None and len(str(counter)) > 0:
        return ".ripeatlas-" + str(counter) + "-" + str(packetloss_rate) + ".packetloss.syssec-research.mmci.uni-saarland.de"


# Create a source from asn_id and send a query with domain_name as query name
def send_query_from_asn(asn_id, counter, packetloss_rate):
    print(f"  Building query name from current counter value: {counter}")
    # Build the query name from the counter value
    query_name = build_query_name_from_counter(counter, packetloss_rate)
    print(f"    Built query name: {query_name}")

    print(f"  Creating DNS Query")
    dns = Dns(
        key=ATLAS_API_KEY,
        description=f"Ege Girit Packetloss Experiment {counter}",
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
        prepend_probe_id=True,

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

    print(f"  Creating source from given asn_ID: {asn_id}")
    # Probe ID as parameter
    source1 = AtlasSource(
        "type": "asn",
                "value": asn_ID,
    "requested": 1
    )

    print(f"  Creating request from source")
    # Create request from given probe ID
    atlas_request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=ATLAS_API_KEY,
        measurements=[dns],
        sources=[source1],
        # Always set this to true
        # The measurement will only be run once
        is_oneoff=True
    )

    print(f"  Starting measurement")
    # Start the measurement
    (is_success, response) = atlas_request.create()
    is_success, response

    # %%
    kwargs = {
        "msm_id": response["measurements"][0]
    }

    # Wait for the probes to upload their results before asking for the results
    sleep_for_seconds(300)

    # No needed on authoritative Server
    # Results can be downloaded later using measurement ID's
    print(f"  Creating results")
    # Create results
    is_success, results = AtlasResultsRequest(**kwargs).create()

    # Print the measurement ID
    m = DnsResult.get(results[0])
    print(f"  Measurement ID: {m.measurement_id}")


# Extract the asn values from the global probe_dict variable
# and store them in the global list as_ids
def extract_asn_values():
    print("Reading the asn values")

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
        print(f"  Values: {values[index]['value']}")


def createFolder(directory_name_of_logs):
    # Create directory to store the packet capture log files
    create_folder_command = f"mkdir {directory_name_of_logs}"
    print(f"Creating a folder named {directory_name_of_logs} with the following command:")
    print("  " + create_folder_command)

    try:
        subprocess.run(create_folder_command, shell=True, stdout=subprocess.PIPE, check=True)
        print(f"Folder {directory_name_of_logs} created.")
    except Exception:
        print(f"Folder not created.")


# Create folder to store the packet capture logs of authoritative server
createFolder(directory_name_of_logs)

print("\n==== Experiment starting ====\n")

current_packetloss_rate = "pl0"
# Start packet capture on the authoritative server
capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_name)


# Ripe atlas
# Extracts the asn values in as_ids list
extract_asn_values()

# For each asn ID in as_ids, send a query from that probe and build the query with a counter value.
# Counter value must be equal or greater than probe count.
# Make sure the domain name is valid (A records are in authoritative server) for the given counter values.
counter = 0
for id in as_ids:
    # Example query: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
    send_query_from_asn(id, counter, current_packetloss_rate)
    counter += 1


# Terminate packet captures / all created processes
print(f"  Stopping packet capture.")
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


print("\n==== Experiment ended ====\n")

# Compress all the packet capture logs into a logs.zip file
compress_log_files(directory_name_of_logs)
