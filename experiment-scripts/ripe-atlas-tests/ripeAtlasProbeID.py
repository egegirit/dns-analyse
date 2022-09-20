import subprocess
import time
import os
import signal
from datetime import datetime
from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
# from ripe.atlas.sagan import DnsResult

# Execute this script as root user

# Time to wait after one domain query is sent to all resolver IP Addresses
# (Sleeping time between counters)
sleep_time = 1
# Time to sleep between packetloss configurations. (600 seconds = 10 minutes)
sleep_time_between_packetloss_config = 600

# Mit 6 Packetloss Raten und 20 Wiederholungen (counter) -> maximal 830 Probes am Tag

# Minimum and maximum counter values for the domains
counter_min = 0  # Inclusive
counter_max = 21  # Exclusive

# Set the interface names for packet capture with tcpdump
interface_name = "bond0"  # The interface of authoritative server without the packetloss filter

directory_name_of_logs = "packet_capture_logs"

# Packetloss rates to be simulated on the authoritative server
# packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]
# packetloss_rates = [0, 10, 20, 30, 50, 85]
packetloss_rates = [40, 60, 70, 80, 90, 95]

ATLAS_API_KEY = ""  # 0c51be25-dfac-4e86-9d0d-5fef89ea4670

# The measurement ID from the first experiment
# This allows us to use the same probes again that are selected in the first experiment
# But some probes might be unstable, expect unresponsive probes.
msm_id = 0


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
def build_query_name_from_counter_and_pl(current_counter, packetloss_rate):
    return "$p-$t.ripeatlas-" + "pl" + str(packetloss_rate) + "-" + str(current_counter) + ".packetloss.syssec-research.mmci.uni-saarland.de"


# Create a source from measurement ID msm_ID
def send_query_from_probe(measurement_id, counter_value, packetloss_rate):
    print(f"  Building query name from current counter value: {counter_value}")
    # Build the query name from the counter value
    query_name = build_query_name_from_counter_and_pl(counter_value, packetloss_rate)
    print(f"    Built query name: {query_name}")

    print(f"  Creating DNS Query")
    dns = Dns(
        key=ATLAS_API_KEY,
        description=f"Ege Girit 2. Packetloss Experiment {counter_value}-{packetloss_rate}",
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

    print(f"  Creating source from given measurement id: {measurement_id}")
    # Probe ID as parameter
    source1 = AtlasSource(
        "type": 'msm',
        "value": measurement_id
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

    # %%
    kwargs = {
        "msm_id": response["measurements"][0]
    }


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


create_folder(directory_name_of_logs)

print("\n==== Experiment starting ====\n")
# Parallelized and automated query sending with different packetloss rates
# For each packetloss rate, create subprocesses for each IP Address, and send queries to all of them at the same time.
for current_packetloss_rate in packetloss_rates:
    print(f"### Current packetloss rate: {current_packetloss_rate} ###")

    # If current packetloss rate is 0, no need to execute packetloss filter
    if current_packetloss_rate != 0:
        if not (simulate_packetloss(current_packetloss_rate, interface_name)):
            # if simulate_packetloss() returns false, there was an exception while simulating packetloss
            # continue with the next packetloss configuration
            continue

    # Start packet capture on the authoritative server
    capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_name)

    # TODO: Get probes of the last experiment from measurement ID

    # Ripe atlas
    # Measurement ID to get the same Probes as the first experiment
    global msm_id

    # Send a query from all probe and build the query with a counter value.
    # Do this for counter_max times
    # Make sure the domain name is valid (A records are in authoritative server) for the given counter values.

    # Send queries of the current packetloss rate with ripe atlas
    for counter in range(counter_min, counter_max):
        send_query_from_probe(msm_id, counter, current_packetloss_rate)

    # Disable packetloss on the authoritative server
    if current_packetloss_rate != 0:
        # True -> No error. False -> Exception occurred while disabling packetloss.
        disable_packetloss_simulation(current_packetloss_rate, interface_name)
        # Exit the program because continuing would stack the packetloss rules.
        # exit()
        # Continue with next packetloss simulation because the next packetloss rule will overwrite the old one
        # Not disabling the old packetloss rule won't be a problem.
        # continue

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
        print(f"    Sleeping for 1 seconds for tcpdump to terminate")
        sleep_for_seconds(1)

        # Sleep for 10 minutes between packetloss configurations
    print(f"  {current_packetloss_rate}% Packetloss Config Finished")

    # If we are in the last iteration, no need to wait
    if current_packetloss_rate != 95:
        print(
            f"  Sleeping for {sleep_time_between_packetloss_config} seconds for the next packetloss iteration."
        )
        sleep_for_seconds(sleep_time_between_packetloss_config)

print("\n==== Experiment ended ====\n")

# Compress all the packet capture logs into a logs.zip file
compress_log_files(directory_name_of_logs)
