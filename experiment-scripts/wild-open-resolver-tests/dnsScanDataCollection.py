import sys
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import re
import os
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

# The packetloss rates that are simulated in the experiment
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100]

# IPs of the server and client are used to filter irrelevant packets
client_ip_addr = "139.19.117.8"
auth_ip_addr = "139.19.117.11"

# The dictionaries to store extracted information
all_responses_count_pl = {}
all_queries_count_pl = {}
unanswered_query_count_by_pl = {}
responses_with_no_query_count_by_pl = {}
latencies_by_pl_and_rcode = {}
query_duplicate_by_pl = {}
rcodes_by_pl = {}
rcode_0_udp_count_pl = {}
rcode_0_tcp_count_pl = {}
all_query_names_pl = {}
all_response_names_pl = {}

# Store all query names of client to detect any missing queries on the auth pcap
# Queries that are in client pcaps but not in auth.
all_query_names_pl_for_missing = {}

tcp_counterpart_of_udp_query = {}
ip_plrate_to_response_rcodes = {}

# If a dns query is retransmitted 2 times and the 2. retransmission has a response packet to it
# then dont count as unanswered here.
query_names_with_no_ok_response_count = {}

latencies_first_query_first_resp_OK = {}


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


# If a query name does not have the defined structure, skip examining the packet
def is_query_name_valid(query_name):
    query_pattern = "^[A-Za-z0-9]{5}_[A-Za-z0-9]{8}\.public-pl[0-9]{1,2}\.packetloss\.syssec-research\.mmci\.uni-saarland\.de\.$"
    search_result = re.search(query_pattern, query_name, re.IGNORECASE)
    if search_result is None:
        # print(f"Invalid query name: {query_name}")
        return False
    else:
        return True


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
def initialize_dictionaries(pcap_type):
    rcodes = [0, 2, 5]
    for current_pl_rate in packetloss_rates:
        query_duplicate_by_pl[current_pl_rate] = 0
        # Only reset this after an auth pcap is read
        if "client" in pcap_type:
            all_query_names_pl_for_missing[current_pl_rate] = []

        # For auth
        tcp_counterpart_of_udp_query[current_pl_rate] = 0

        all_responses_count_pl[current_pl_rate] = 0
        rcode_0_udp_count_pl[current_pl_rate] = 0
        rcode_0_tcp_count_pl[current_pl_rate] = 0
        latencies_first_query_first_resp_OK[current_pl_rate] = []
        query_names_with_no_ok_response_count[current_pl_rate] = 0

        for rcode in rcodes:
            latencies_by_pl_and_rcode[current_pl_rate, rcode] = []
            rcodes_by_pl[current_pl_rate, rcode] = 0

        for prot in [6, 17]:
            all_queries_count_pl[current_pl_rate, prot] = 0
            # all_response_names_pl[current_pl_rate, prot] = 0


# Read the pcap file with the given packetloss rate
def read_single_pcap(pcap_file_name, current_pl_rate):
    print(f"    Reading file: {pcap_file_name}  (Start at {datetime.now()})")

    # Store the dns packets by their attributes: (dns_id, query_name, is_response_packet) in a hash table
    # to find corresponding responses to queries
    queries = {}
    responses = {}

    # Calculate latency between first query and first response for RCODE 0 answers
    first_latency_queries = {}

    # Read the packets in the pcap file one by one
    index = 1
    for packet in PcapReader(pcap_file_name):
        # Examine only DNS packets
        if packet.haslayer(DNS):
            # print(f"========================")
            # print(f"Showing packet ({index})")
            # packet.show()
            try:
                rcode = int(packet[DNS].rcode)
                # If the RCODE is format-error, skip packet
                if rcode == 1:
                    # print(f"RCODE format-error, skipping")
                    continue

                # Get source and destination IPs of packet
                dst_ip = packet[IP].dst
                src_ip = packet[IP].src
                # Filter packet if source or destination IP is not valid
                if not is_src_and_dst_ip_valid(pcap_file_name, src_ip, dst_ip):
                    # print(f" Invalid IP Skipping")
                    # print(f"    dst_ip: {dst_ip}")
                    # print(f"    src_ip: {src_ip}")
                    continue

                rec_type = packet[DNSQR].qtype  # Type 1 is A record
                # Filter if query is not an A record query
                if rec_type != 1:
                    # print(f"  Query type is not an A record: {query_name}")
                    continue

                # Query name of packet
                query_name = packet[DNS].qd.qname.decode("utf-8").lower()
                if not is_query_name_valid(query_name):
                    # print(f" Query name does not match: {query_name}")
                    continue

                # Extract ip address and pl rate from query name,
                pl_rate_of_packet = query_name.split("public-pl")[1].split(".")[0]
                random_5_character_of_query = query_name.split("_")[0]
                hex_decoded_ip = query_name.split("_")[1].split(".public-pl")[0]
                ip_addr_of_query = decode_hexadecimal(hex_decoded_ip)

                # Filter if packetloss rate of packet does not match the pl rate of pcap file
                if str(current_pl_rate) != str(pl_rate_of_packet):
                    # print(f"PL rate does not match for: {query}")
                    # print(f" PL rate on query name does not match: {pl_rate_of_packet} != {current_pl_rate}")
                    continue

                # port = packet.sport
                proto = packet[IP].proto  # 6 is TCP, 17 is UDP
                is_response_packet = int(packet[DNS].qr)  # Packet is a query (0), or a response (1)
                dns_id = packet[DNS].id  # DNS ID
                answer_count = int(packet[DNS].ancount)  # Count of answers

                # Arrival time of the packet
                packet_time = float(packet.time)
                # Time difference of the current and previous packet, used to determine phases in stale pcaps
                # time_diff_to_previous = packet_time - previous_packet_time

                # print(f"Query name: {query_name}")
                # print(f"  Query type: {rec_type}")
                # print(f"  Is response (0: Query, 1: Response): {is_response}")
                # print(f"  DNS ID: {dns_id}")
                # print(f"  RCODE: {rcode}")
                # print(f"  Answer Count: {answer_count}")
                # print(f"  SRC IP: {src_port}")
                # print(f"  DST IP: {dst_port}")
                # print(f"  Port: {port}")
                # print(f"  Protocol: {proto}")
                # print(f"  Packetloss rate of packet: {pl_rate_of_packet}")
                # print(f"  Operator Name: {operator_name}")
                # print(f"  Arrival time of packet: {packet_time}")
                # print(f"  Time difference to previous packet: {time_diff_to_previous}")

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

                    # Store query names on client pcap to detect missing queries on auth pcap
                    if "client" in pcap_file_name:
                        if query_name not in all_query_names_pl_for_missing[current_pl_rate]:
                            all_query_names_pl_for_missing[current_pl_rate].append(query_name)
                            # print(f"  Length Added: {len(all_query_names_pl_for_missing[current_pl_rate])}")
                    # After reading all the client pcaps, delete all the client queries which are also in auth pcap
                    elif "auth" in pcap_file_name:
                        # print(f"    Length Auth: {len(all_query_names_pl_for_missing[current_pl_rate])}")
                        if query_name in all_query_names_pl_for_missing[current_pl_rate]:
                            all_query_names_pl_for_missing[current_pl_rate].remove(query_name)
                            # print(f"    Length Deleted: {len(all_query_names_pl_for_missing[current_pl_rate])}")

                    if "auth" in pcap_file_name:
                        # In this experiment, queries are sent twice. First via UDP, then after switching to TCP,
                        # a query via TCP. So, we cant count dns retransmissions by only examining query name.
                        # Find the TCP query counterpart of a query sent via UDP
                        if proto == 6 and (current_pl_rate, query_name, 17) in all_query_names_pl:
                            tcp_counterpart_of_udp_query[current_pl_rate] += 1
                            # print(f"  TCP counterpart of UDP query: {query_name}")
                        # There was no TCP counterpart to the UDP query
                        else:
                            # print(f"  No TCP counterpart of UDP query: {query_name}")
                            pass

                    # Count unique query names of pl for dns retransmission plot
                    # Because we are counting retransmissions, the first found query count will be set to 0
                    if (current_pl_rate, query_name, proto) not in all_query_names_pl:
                        all_query_names_pl[current_pl_rate, query_name, proto] = 0
                    else:
                        all_query_names_pl[current_pl_rate, query_name, proto] += 1

                    # Count all the queries to build ratios
                    all_queries_count_pl[current_pl_rate, proto] += 1

                    # Only add it to the queries dictionary if it's not a duplicate
                    if (dns_id, query_name, is_response_packet) not in queries:
                        queries[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                    # Count query duplicate by packetloss rate
                    else:
                        # print(f"Query duplicate: {query_name}, {dns_id}")
                        query_duplicate_by_pl[current_pl_rate] += 1

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

                    # Count all the responses to build ratios
                    all_responses_count_pl[current_pl_rate] += 1

                    # Count unique query names of responses for response duplicate
                    if (current_pl_rate, query_name, proto) not in all_response_names_pl:
                        all_response_names_pl[current_pl_rate, query_name, proto] = 0
                    all_response_names_pl[current_pl_rate, query_name, proto] += 1

                    # Check if we found a corresponding response packet to a query
                    if (dns_id, query_name, 0) in queries:

                        # Calculate latency between response and query
                        latency = float(packet_time - queries[dns_id, query_name, 0][0])
                        # Delete the query from dictionary because we calculated its latency
                        del queries[dns_id, query_name, 0]

                        # Store the latency directly using the rcode and current packetloss rate
                        # Create the latency keys if not created before
                        if (current_pl_rate, rcode) not in latencies_by_pl_and_rcode:
                            latencies_by_pl_and_rcode[current_pl_rate, rcode] = []
                        latencies_by_pl_and_rcode[current_pl_rate, rcode].append(latency)

                        # Count the RCODEs of the packets of the pl rate
                        if (current_pl_rate, rcode) not in rcodes_by_pl:
                            rcodes_by_pl[current_pl_rate, rcode] = 0
                        rcodes_by_pl[current_pl_rate, rcode] += 1

                        # For RCODE 0 responses, check if its UDP or TCP and count it
                        if rcode == 0:
                            if packet.haslayer(UDP):
                                # print("UDP DNS response")
                                rcode_0_udp_count_pl[current_pl_rate] += 1
                            elif packet.haslayer(TCP):
                                # print("TCP DNS response")
                                rcode_0_tcp_count_pl[current_pl_rate] += 1

                    # The response packet has no corresponding query packet for now (and probably will not have any?)
                    # Add the response to the list
                    elif (dns_id, query_name, is_response_packet) not in responses:
                        responses[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                        # print(f"@@ Response has no query to it: {query_name}, {dns_id}")
                    # The response packet has no corresponding query to it and this packet is a duplicate
                    else:
                        # print(f"  @@ Duplicate response packet detected for {query_name}, {dns_id}")
                        pass

                    # After all the packet filterings are done, if the packet is a response:
                    # For all packetloss rates, note the observed response codes of the IP Adresses in a list,
                    # this might be used later to filter some resolver that always send a non-OK rcode.
                    # In this case, the rcodes of that filter must be non 0 for all packetloss rates
                    if (current_pl_rate, ip_addr_of_query) not in ip_plrate_to_response_rcodes:
                        ip_plrate_to_response_rcodes[current_pl_rate, ip_addr_of_query] = []
                    ip_plrate_to_response_rcodes[current_pl_rate, ip_addr_of_query].append(rcode)

                    # Calculate latency between first query and first OK response to it
                    # We found a response to a query name, check if RCODE is 0 and calculate latency
                    if (query_name, 0) in first_latency_queries and rcode == 0:
                        latency = float(packet_time - first_latency_queries[query_name, 0])
                        latencies_first_query_first_resp_OK[current_pl_rate].append(latency)
                        del first_latency_queries[query_name, 0]
                        # print(f"Response to query found: {query_name}")
                        # print(f"Length: {len(first_latency_queries)}")

            except (IndexError, UnicodeDecodeError):
                # Don't print IndexErrors such as DNSQR Layer not found
                pass
            except Exception as e:
                print(f"  Error reading packet: {e}")
                print(f"  Error Type: {type(e)}")  # the exception instance
                traceback.print_exc()
                # packet.show()

        # See how far we are when running the script
        if index % 200000 == 0:
            print(f"      Packet number: ({datetime.now()}) {index}")
            input("Press any key to continue: ")
        index += 1

    # After examining all the packets in the pcap file,
    # calculate unanswered query count,
    # the remaining queries in the queries dict are unanswered because all the
    # queries with a response packet to it are deleted before
    if current_pl_rate not in unanswered_query_count_by_pl:
        unanswered_query_count_by_pl[current_pl_rate] = 0
    unanswered_query_count_by_pl[current_pl_rate] = len(queries)
    # Response counts, which has no corresponding query packets
    if current_pl_rate not in responses_with_no_query_count_by_pl:
        responses_with_no_query_count_by_pl[current_pl_rate] = 0
    responses_with_no_query_count_by_pl[current_pl_rate] = len(responses)

    if current_pl_rate not in query_names_with_no_ok_response_count:
        query_names_with_no_ok_response_count[current_pl_rate] = 0
    query_names_with_no_ok_response_count[current_pl_rate] = len(first_latency_queries)


# Input: "10" Output 1
def get_index_of_packetloss_rate(input):
    pl_rate = str(input)
    if pl_rate == "0":
        return 0
    if pl_rate == "10":
        return 1
    if pl_rate == "20":
        return 2
    if pl_rate == "30":
        return 3
    if pl_rate == "40":
        return 4
    if pl_rate == "50":
        return 5
    if pl_rate == "60":
        return 6
    if pl_rate == "70":
        return 7
    if pl_rate == "80":
        return 8
    if pl_rate == "85":
        return 9
    if pl_rate == "90":
        return 10
    if pl_rate == "95":
        return 11
    if pl_rate == "100":
        return 12
    return None


# Reset all the values (lists) of the given dictionary
def reset_values_of_dict_to_zero(dictionary, init_value):
    all_keys = list(dictionary.keys())
    for key in all_keys:
        dictionary[key] = init_value


# Reset the dictionaries for the next plotting
def reset_for_next_plot():
    global all_query_names_pl
    global all_response_names_pl
    global all_responses_count_pl
    global all_queries_count_pl

    global unanswered_query_count_by_pl
    global responses_with_no_query_count_by_pl
    global latencies_by_pl_and_rcode
    global query_duplicate_by_pl
    global rcodes_by_pl
    global rcode_0_udp_count_pl
    global rcode_0_tcp_count_pl
    global tcp_counterpart_of_udp_query
    global ip_plrate_to_response_rcodes
    global latencies_first_query_first_resp_OK
    global query_names_with_no_ok_response_count

    all_query_names_pl = {}
    all_response_names_pl = {}
    all_responses_count_pl = {}
    all_queries_count_pl = {}
    unanswered_query_count_by_pl = {}
    responses_with_no_query_count_by_pl = {}
    latencies_by_pl_and_rcode = {}
    query_duplicate_by_pl = {}
    rcodes_by_pl = {}
    rcode_0_udp_count_pl = {}
    rcode_0_tcp_count_pl = {}
    tcp_counterpart_of_udp_query = {}
    ip_plrate_to_response_rcodes = {}
    latencies_first_query_first_resp_OK = {}
    unanswered_query_name_count = {}

    # print(f"Clean up for next plotting DONE")


# Missing query information is only relevant for auth pcaps,
# reset this only after reading auth pcaps
def reset_after_auth_pcaps():
    global all_query_names_pl_for_missing
    all_query_names_pl_for_missing = {}
    for current_pl_rate in packetloss_rates:
        all_query_names_pl_for_missing[current_pl_rate] = []

    # print(f"Clean up after auth DONE")


# Split latencies into OK latencies and ServFail latencies
def extract_latencies_from_dict():
    global latencies_by_pl_and_rcode
    keys_of_latency = list(latencies_by_pl_and_rcode.keys())
    rcode_0_keys = []
    rcode_2_keys = []
    for key in keys_of_latency:
        # Get only latencies of RCODE = 0
        if key[1] == 0:
            rcode_0_keys.append(key)
        # ServFail
        elif key[1] == 2:
            rcode_2_keys.append(key)

    ok_latencies = {}
    servfail_latencies = {}
    index = 0
    for key in rcode_0_keys:
        # print(f"latencies_by_pl_and_rcode[{key}]: {latencies_by_pl_and_rcode[key]}")
        ok_latencies[key[0]] = latencies_by_pl_and_rcode[key]
        index += 1

    index = 0
    for key in rcode_2_keys:
        # print(f"latencies_by_pl_and_rcode[{key}]: {latencies_by_pl_and_rcode[key]}")
        servfail_latencies[key[0]] = latencies_by_pl_and_rcode[key]

    # If some pl rate lists are empty, for example when there is 0 servfails packets in packetloss rate 0,
    # then pl 0 key of the dictionary wont exist. Fill the non existing keys with 0
    for pl in packetloss_rates:
        if pl not in ok_latencies:
            ok_latencies[pl] = [0]
        if pl not in servfail_latencies:
            servfail_latencies[pl] = [0]

    return [ok_latencies, servfail_latencies]


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
    create_file_write_content(f"{data_path}/RCODE_Counts_(PacketLoss_RCODE)_Count", rcodes_by_pl)
    create_file_write_content(f"{data_path}/Tcp_Counterpart_Of_Udp_Query_(PacketLoss)_Count", tcp_counterpart_of_udp_query)
    create_file_write_content(f"{data_path}/All_Responses_(PacketLoss)_Count", all_responses_count_pl)
    create_file_write_content(f"{data_path}/Unanswered_Query_Count_(PacketLoss)_Count", unanswered_query_count_by_pl)
    create_file_write_content(f"{data_path}/Responses_With_No_Query_Count_(PacketLoss)_Count", responses_with_no_query_count_by_pl)
    create_file_write_content(f"{data_path}/Response_Rcode_0_UDP_Count_(PacketLoss)_Count",
                              rcode_0_udp_count_pl)
    create_file_write_content(f"{data_path}/Response_Rcode_0_TCP_Count_(PacketLoss)_Count",
                              rcode_0_tcp_count_pl)
    create_file_write_content(f"{data_path}/Latencies_(PacketLoss_RCODE)_[Latencies]", latencies_by_pl_and_rcode)
    create_file_write_content(f"{data_path}/All_Queries_(PacketLoss_QueryName_Protocol)_Count", all_query_names_pl)
    create_file_write_content(f"{data_path}/All_Responses_(PacketLoss_QueryName_Protocol)_Count", all_response_names_pl)
    create_file_write_content(f"{data_path}/IP_PLRate_to_RCODEs", ip_plrate_to_response_rcodes)


def extract_datas_from_pcap(file_name):
    initialize_dictionaries("client")

    # Prefixes of the pcap file names
    client_prefix = "tcpdump_log_client_eth2_pl"
    auth_prefix = "tcpdump_log_auth_bond0_pl"

    # Create client plots
    extract_data_from(file_name, client_prefix)

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()

    # Initialize dictionaries again
    initialize_dictionaries("auth")

    # Create auth plots
    extract_data_from(file_name, auth_prefix)

    # Check if client or auth data, create root folder for datas
    root_folder_name = "AuthData"
    create_folder(root_folder_name)

    # Path to store datas
    data_path = root_folder_name + "/" + file_name

    # create_file_write_content(f"missing_query_count_list{file_name}", missing_query_count_list)
    create_file_write_content(f"{data_path}/Missing_Query_Names_On_Auth_(PacketLoss)_[QueryNames]", all_query_names_pl_for_missing)

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()

    # Reset missing query count
    reset_after_auth_pcaps()


extract_datas_from_pcap("DnsScanPlots")
