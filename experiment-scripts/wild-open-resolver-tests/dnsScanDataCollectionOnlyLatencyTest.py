import sys
import numpy as np
import re
import os
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import pyshark

# The packetloss rates that are simulated in the experiment
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100]

# IPs of the server and client are used to filter irrelevant packets
client_ip_addr = "139.19.117.8"
auth_ip_addr = "139.19.117.11"

# The dictionaries to store extracted information
latencies_by_pl_and_rcode = {}
query_duplicate_by_pl = {}
ip_plrate_to_response_rcodes = {}
latencies_first_query_first_resp_OK = {}

# Compile search pattern for efficiency
query_pattern = "(^[A-Za-z0-9]{5})_([A-Za-z0-9]{8})\.public-pl([0-9]{1,2})\.packetloss\.syssec-research\.mmci\.uni-saarland\.de\.$"
compiled_pattern = re.compile(query_pattern)


# If a query name does not have the defined structure, skip examining the packet
def is_query_name_valid(query_name):
    search_result = compiled_pattern.search(query_pattern, query_name, re.IGNORECASE)

    if search_result is None:
        # print(f"Invalid query name: {query_name}")
        return []

    # Extract the query parts using groups
    random_5_chars = search_result.group(1)
    encoded_ip = search_result.group(2)
    pl_rate_of_query = search_result.group(3)

    return [random_5_chars, encoded_ip, pl_rate_of_query]


# Create a folder with the given name
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)


# Create a text file with given name and content
def create_file_write_content(file_name, content):
    f = open(str(file_name) + ".txt", "w")
    f.write(str(content))
    f.close()
    print(f"  Created file: {str(file_name)}")


# Encode an IP like "78.111.72.138" to its 8 byte hexadecimal encoding "0d274a62"
def encode_hexadecimal(ip_with_dots):
    # Split the string into a list of decimal numbers
    numbers = ip_with_dots.split('.')

    # Convert each decimal number to its hexadecimal equivalent
    hex_numbers = [hex(int(n))[2:] for n in numbers]

    # Concatenate the hexadecimal numbers together
    hex_string = ''.join(hex_numbers)

    # Return the 8-byte hexadecimal encoded string
    return hex_string[:8]


# Decode "0d274a62" to "78.111.72.138"
def decode_hexadecimal(encoded_ip):
    # Split the encoded string into a list of hexadecimal numbers
    hex_numbers = [encoded_ip[i:i+2] for i in range(0, len(encoded_ip), 2)]

    # Convert each hexadecimal number to its decimal equivalent
    numbers = [int(h, 16) for h in hex_numbers]

    # Concatenate the decimal numbers together with dots
    ip_with_dots = '.'.join(str(n) for n in numbers)

    return ip_with_dots


# Return all the values (lists) of the given dictionary
def get_values_of_dict(dictionary):
    all_values = list(dictionary.values())
    return all_values


# Check if the source or destination IP of the packet is valid, filter packets by IP Address
def is_src_and_dst_ip_valid(pcap_name, src_ip, dst_ip):
    # Client IP is 139.19.117.1
    if "client" in pcap_name:
        if src_ip != client_ip_addr and dst_ip != client_ip_addr:
            # print(f"  IP of client packet invalid: {src_ip}, {dst_ip}")
            return False
    # Server IP is 139.19.117.11
    elif "auth" in pcap_name:
        if src_ip != auth_ip_addr and dst_ip != auth_ip_addr:
            # print(f"  IP of auth packet invalid: {src_ip}, {dst_ip}")
            return False
    return True


# Initialize dictionaries with empty values
def initialize_dictionaries():
    rcodes = [0, 2, 5]
    for current_pl_rate in packetloss_rates:
        query_duplicate_by_pl[current_pl_rate] = 0
        latencies_first_query_first_resp_OK[current_pl_rate] = []
        for rcode in rcodes:
            latencies_by_pl_and_rcode[current_pl_rate, rcode] = []


# Read the pcap file with the given packetloss rate
def read_single_pcap(pcap_file_name, current_pl_rate):
    print(f"    Reading file: {pcap_file_name}  (Start at {datetime.now()})")

    # Calculate latency between first query and first response for RCODE 0 answers
    # Dictionary with (query_name, is_response_packet): packet_time
    first_latency_queries = {}

    # If a query is already answered but the query is sent again,
    # don't calculate latency again
    already_ok_answered_queries = {}

    # Read the packets in the pcap file one by one
    index = 1
    for packet in pyshark.FileCapture(pcap_file_name):  # PcapReader(pcap_file_name):
        # Examine only DNS packets
        if packet.dns:  # packet.haslayer(DNS):
            # print(f"========================")
            # print(f"Showing packet ({index})")
            # packet.show()
            try:
                rcode_string = int(packet.dns.rcode)  # int(packet[DNS].rcode)
                rcode = -1
                if rcode_string == "NOERROR":
                    rcode = 0
                elif rcode_string == "SERVFAIL":
                    rcode = 2
                else:
                    continue
                # If the RCODE is format-error, skip packet
                # if rcode == 1:
                #     # print(f"RCODE format-error, skipping")
                #     continue

                # Get source and destination IPs of packet
                dst_ip = packet.ip.dst  # packet[IP].dst
                src_ip = packet.ip.src  # packet[IP].src
                # Filter packet if source or destination IP is not valid
                if not is_src_and_dst_ip_valid(pcap_file_name, src_ip, dst_ip):
                    print(f" Invalid IP Skipping")
                    print(f"    dst_ip: {dst_ip}")
                    print(f"    src_ip: {src_ip}")
                    continue

                rec_type = packet.dns.qry_type  # packet[DNSQR].qtype  # Type 1 is A record
                # Filter if query is not an A record query
                if rec_type != 1:
                    print(f"  Query type is not an A record: {query_name}")
                    continue

                # Query name of packet
                query_name = packet.dns.qry_name.lower()  # packet[DNS].qd.qname.decode("utf-8").lower()
                # print(f"Qname: {query_name}")
                query_extract_result = is_query_name_valid(query_name)
                if len(query_extract_result) == 0:
                    print(f" Query name does not match: {query_name}")
                    continue
                else:
                    # random_5_character_of_query = query_extract_result[0]
                    hex_decoded_ip = query_extract_result[1]
                    pl_rate_of_packet = query_extract_result[2]

                # Extract ip address and pl rate from query name,
                # pl_rate_of_packet = query_name.split("public-pl")[1].split(".")[0]
                # random_5_character_of_query = query_name.split("_")[0]
                # hex_decoded_ip = query_name.split("_")[1].split(".public-pl")[0]
                ip_addr_of_query = decode_hexadecimal(hex_decoded_ip)

                # Filter if packetloss rate of packet does not match the pl rate of pcap file
                if str(current_pl_rate) != str(pl_rate_of_packet):
                    print(f" PL rate does not match for: {query}")
                    print(f" PL rate on query name does not match: {pl_rate_of_packet} != {current_pl_rate}")
                    continue

                # port = packet.sport
                # proto = packet[IP].proto  # 6 is TCP, 17 is UDP
                # dns_id = packet.dns.id  # packet[DNS].id  # DNS ID
                is_response_packet = packet.dns.flags_response  # int(packet[DNS].qr)  # Packet is a query (0), or a response (1)
                answer_count = int(packet.dns.ancount)  # int(packet[DNS].ancount)  # Count of answers

                # Arrival time of the packet
                packet_time = float(packet.sniff_time)  # float(packet.time)

                print(f"Query name: {query_name}")
                print(f"  Query type: {rec_type}")
                print(f"  Is response (0: Query, 1: Response): {is_response}")
                print(f"  DNS ID: {dns_id}")
                print(f"  RCODE: {rcode}")
                print(f"  Answer Count: {answer_count}")
                print(f"  SRC IP: {src_port}")
                print(f"  DST IP: {dst_port}")
                print(f"  Packetloss rate of packet: {pl_rate_of_packet}")
                print(f"  Arrival time of packet: {packet_time}")
                print(f"  Time difference to previous packet: {time_diff_to_previous}")

                # Packet is a query
                if is_response_packet == 0:
                    # Filter non-relevant packets by IP filtering
                    # For client pcaps, the query source should be the client IP
                    if "client" in pcap_file_name:
                        if src_ip != client_ip_addr:
                            # print(f"Invalid IP client src_ip {src_ip} for {query_name}")
                            continue
                    # For auth pcaps, the query destination should be the auth IP
                    elif "auth" in pcap_file_name:
                        if dst_ip != auth_ip_addr:
                            # print(f"Invalid IP auth dst_ip {dst_ip} for {query_name}")
                            continue

                    # Calculate latency between first query and first OK response to it
                    # Here, store the first query packets, in elif is_response_packet == 1: find the response
                    if (query_name, is_response_packet) not in first_latency_queries:
                        first_latency_queries[query_name, is_response_packet] = packet_time
                    #     print(f"Length: {len(first_latency_queries)}")
                    # else:
                    #     print(f"Duplicate query name: {query_name}")

                # Packet is a DNS response
                elif is_response_packet == 1:
                    # if answer_count > 0:
                    #     ans_type = int(packet[DNS].an.type)

                    # Filter non-relevant response packets by IP filtering
                    if "client" in pcap_file_name:
                        if dst_ip != client_ip_addr:
                            # print(f"Invalid IP for {query_name}")
                            continue

                    elif "auth" in pcap_file_name:
                        if src_ip != auth_ip_addr:
                            # print(f"Invalid IP for {query_name}")
                            continue
                        # For auth pcaps, if the response is truncated switch to TCP packet, ignore
                        if rcode == 0 and packet[DNS].tc == 1 and answer_count == 0:
                            # print(f"  -> Possible switch to TCP packet")
                            continue

                    # After all the packet filterings are done, if the packet is a response:
                    # For all packetloss rates, note the observed response codes of the IP Adresses in a list,
                    # this might be used later to filter some resolver that always send a non-OK rcode.
                    # In this case, the rcodes of that filter must be non 0 for all packetloss rates
                    if (current_pl_rate, ip_addr_of_query) not in ip_plrate_to_response_rcodes:
                        ip_plrate_to_response_rcodes[current_pl_rate, ip_addr_of_query] = []
                    ip_plrate_to_response_rcodes[current_pl_rate, ip_addr_of_query].append(rcode)

                    # Calculate latency between first query and first OK response to it
                    # We found a response to a query name, check if RCODE is 0 and calculate latency
                    if current_pl_rate not in already_ok_answered_queries:
                        already_ok_answered_queries[current_pl_rate] = []
                    if (query_name, 0) in first_latency_queries and rcode == 0 and answer_count > 0 \
                            and query_name not in already_ok_answered_queries[current_pl_rate]:
                        latency = float(packet_time - first_latency_queries[query_name, 0])
                        latencies_first_query_first_resp_OK[current_pl_rate].append(latency)
                        del first_latency_queries[query_name, 0]
                        already_ok_answered_queries[current_pl_rate].append(query_name)

            # Don't print IndexErrors such as DNSQR Layer not found
            except (IndexError, UnicodeDecodeError):
                pass
            except Exception as e:
                print(f"  Error reading packet: {e}")
                print(f"  Error Type: {type(e)}")
                traceback.print_exc()
                # packet.show()

        # See how far we are when running the script
        # if index % 1000000 == 0:
        #     print(f"      Packet number: ({datetime.now()}) {index}")
        print(f"      Packet number: {index}")
        index += 1


# Reset the dictionaries for the next plotting
def reset_for_next_plot():
    global latencies_by_pl_and_rcode
    global query_duplicate_by_pl
    global ip_plrate_to_response_rcodes
    global latencies_first_query_first_resp_OK

    latencies_by_pl_and_rcode = {}
    query_duplicate_by_pl = {}
    ip_plrate_to_response_rcodes = {}
    latencies_first_query_first_resp_OK = {}

    # print(f"Clean up for next plotting DONE")


# Read the pcaps of client or auth
def extract_data_from(file_name, pcap_file_prefix):

    # Check if client or auth data, create root folder for datas
    root_folder_name = "UnknownData"
    if "client" in pcap_file_prefix:
        root_folder_name ="ClientData"
    elif "auth" in pcap_file_prefix:
        root_folder_name = "AuthData"
    create_folder(root_folder_name)

    # Path to store datas
    data_path = root_folder_name + "/" + file_name

    # Create folder with the given name inside root data folder
    create_folder(data_path)

    # read the pcap files and initialize the dictionaries with the extracted information
    for current_pl_rate in packetloss_rates:
        print(f"  Current packetloss rate: {current_pl_rate}")
        pcap_file_name = pcap_file_prefix + str(current_pl_rate) + ".pcap"
        read_single_pcap(pcap_file_name, current_pl_rate)

    # Store all the extracted information as text files in the corresponding pcap type folder
    create_file_write_content(f"{data_path}/Latencies_(PacketLoss_RCODE)_[Latencies]", latencies_by_pl_and_rcode)
    create_file_write_content(f"{data_path}/IP_PLRate_to_RCODEs", ip_plrate_to_response_rcodes)


# Read all the pcaps first for client and then for auth
def extract_datas_from_pcap(file_name):
    initialize_dictionaries()

    # Prefixes of the pcap file names
    client_prefix = "tcpdump_log_client_eth2_pl"
    auth_prefix = "tcpdump_log_auth_bond0_pl"

    # Create client plots
    extract_data_from(file_name, client_prefix)

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()

    # Initialize dictionaries again
    initialize_dictionaries()

    # Create auth plots
    extract_data_from(file_name, auth_prefix)

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()


extract_datas_from_pcap("DnsScanPlots")
