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

# Time to wait after one domain query is sent to all resolver IP Addresses
# (Sleeping time between counters)
sleep_time_between_counters = 2
# Time to sleep between packetloss configurations. (600 seconds = 10 minutes)
sleep_time_between_packetloss_config = 600

# 1 Million daily ripe atlas kredit limit
# 1 DNS Query (UDP) = 10 Kredits, 1 DNS Query (TCP) = 20 Kredits
# With UDP -> 100000 Queries per day, 100000/12 = 8333 Queries per packetloss rate
# 8333/20 -> 416 Probes per day with counter 20
# With 6 packetloss rates and 20 repetitions (counter) -> maximum 830 Probes in one day

# Minimum and maximum counter values for the domains
counter_min = 0  # Inclusive
counter_max = 21  # Exclusive

# Set the interface names for packet capture with tcpdump
interface_name = "bond0"  # The interface of authoritative server without the packetloss filter

directory_name_of_logs = "packet_capture_logs"

file_name_of_msm_logs = "measurement-logs.txt"

# Packetloss rates to be simulated on the authoritative server
# packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]
# packetloss_rates = [0, 10, 20, 30, 50, 85]
packetloss_rates = [40, 60, 70, 80, 90, 95]
# Used to identify the end of an experiment and save time not to wait for 10 minutes at the end
last_index = len(packetloss_rates) - 1
if last_index >= 0:
    last_packetloss_rate = packetloss_rates[len(packetloss_rates) - 1]
else:
    print("Invalid packetloss rates")
    sys.exit()

ATLAS_API_KEY = "0c51be25-dfac-4e86-9d0d-5fef89ea4670"

# The measurement ID (integer) from the first experiment
# This allows us to use the same probes again that are selected in the first experiment
# But some probes might be unstable, expect unresponsive probes.
msm_id = ?

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

    print(f"  Creating source from given measurement id: {measurement_id}")
    # Probe ID as parameter
    source1 = AtlasSource(
        requested=830,
        type='msm',
        value=measurement_id
    )

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
        sources=[source1],
        # Always set this to true
        # The measurement will only be run once
        is_oneoff=True
    )

    print(f"  Starting measurement")
    # Start the measurement
    (is_success, response) = atlas_request.create()
    # return is_success, response

    time.sleep(1)
    print(f"\n    Results of Counter: {counter_value}, Packetloss rate: {packetloss_rate}\n")
    try:
        print(f"      is_success: {is_success}")
        print(f"      Response: {response}")
        msm_ids_of_experiment = (is_success, response)
        create_measurement_id_logs(directory_name_of_logs, file_name_of_msm_logs, msm_ids_of_experiment)

    except Exception:
        print("      Error while fetching results")


def create_measurement_id_logs(directory_name, file_name_to_save, measurement_tuple):
    save_path = "/" + directory_name
    file_path = os.path.join(save_path, file_name_to_save)
    f = open(file_path, "a")

    f.write(str(measurement_tuple) + "\n")

    # global msm_ids_of_experiment
    # i = 1
    # for log in msm_ids_of_experiment:
    #     f.write(str(i) + ". Measurement: \n  ")
    #     f.write(str(log) + "\n")
    #     i += 1

    f.close()


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
        if simulate_packetloss(current_packetloss_rate, interface_name):
            # if simulate_packetloss() returns false, there was an exception while simulating packetloss
            # continue with the next packetloss configuration
            print(f"  {current_packetloss_rate}% Packetloss simulation successful")
        else:
            print(f"  {current_packetloss_rate}% Packetloss simulation failed!")

    # Start packet capture on interface_name of the authoritative server, store the pcap in directory_name_of_logs
    capture_processes = start_packet_captures(directory_name_of_logs, current_packetloss_rate, interface_name)

    # Ripe atlas
    # Measurement ID to get the same Probes as the first experiment
    # Build a source with the measurement ID, build the query name for each probe with a counter value,
    # send a query from all probes, do this for counter_max times
    # Make sure the domain name is valid (A records are in authoritative server) for the given counter values.

    # Send queries of the current packetloss rate with ripe atlas
    for counter in range(counter_min, counter_max):
        send_query_from_probe(msm_id, counter, current_packetloss_rate)
        # Sleep a while after sending queries from Probes
        sleep_for_seconds(sleep_time_between_counters)

    # Sleep for 10 minutes between packetloss configurations
    print(f"  {current_packetloss_rate}% Packetloss Configuration Finished")

    # If we are in the last iteration, no need to wait
    if current_packetloss_rate != last_packetloss_rate:
        print(
            f"  Sleeping for {sleep_time_between_packetloss_config} seconds for the next packetloss iteration."
        )
        sleep_for_seconds(sleep_time_between_packetloss_config)

    # If there is packetloss simulation, disable simulation on the authoritative server
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
