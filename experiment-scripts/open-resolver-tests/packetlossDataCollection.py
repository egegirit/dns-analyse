import sys
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import re
import os
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

# The packetloss rates that are simulated in the experiment
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

client_ip_addr = "139.19.117.1"
auth_ip_addr = "139.19.117.11"

# TODO: OPERATORS FOR THE FIRST PCAP
operators = {
    "AdGuard-1": "94-140-14-14",
    "AdGuard-2": "94-140-14-15",
    "CleanBrowsing-1": "185-228-168-168",
    "CleanBrowsing-2": "185-228-168-9",
    "Cloudflare-1": "1-1-1-1",
    "Cloudflare-2": "1-0-0-1",
    "Dyn-1": "216-146-35-35",
    "Dyn-2": "216-146-36-36",
    "Google-1": "8-8-8-8",
    "Google-2": "8-8-4-4",
    "Neustar-1": "64-6-64-6",
    "Neustar-2": "156-154-70-1",
    "OpenDNS-1": "208-67-222-222",
    "OpenDNS-2": "208-67-222-2",
    "Quad9-1": "9-9-9-9",
    "Quad9-2": "9-9-9-11",
    "Yandex-1": "77-88-8-1",
    "Yandex-2": "77-88-8-8"
}

# All operators with their IP Addresses with dashes
# operators = {
#     "AdGuard-1": "94-140-14-14",
#     "AdGuard-2": "94-140-14-15",
#     "AdGuard-3": "94-140-14-140",
#
#     "CleanBrowsing-1": "185-228-168-168",
#     "CleanBrowsing-2": "185-228-168-9",
#     "CleanBrowsing-3": "185-228-168-10",
#
#     "Cloudflare-1": "1-1-1-1",
#     "Cloudflare-2": "1-1-1-2",
#     "Cloudflare-3": "1-1-1-3",
#
#     "Dyn-1": "216-146-35-35",
#
#     "Google-1": "8-8-8-8",
#
#     "Neustar-1": "64-6-64-6",
#     "Neustar-2": "156-154-70-2",
#     "Neustar-3": "156-154-70-3",
#     "Neustar-4": "156-154-70-4",
#     "Neustar-5": "156-154-70-5",
#
#     "OpenDNS-1": "208-67-222-222",
#     "OpenDNS-2": "208-67-222-2",
#     "OpenDNS-3": "208-67-222-123",
#
#     "Quad9-1": "9-9-9-9",
#     "Quad9-2": "9-9-9-11",
#     "Quad9-3": "9-9-9-10",
#
#     "Yandex-1": "77-88-8-1",
#     "Yandex-2": "77-88-8-2",
#     "Yandex-3": "77-88-8-3",
#
#     "Level3-1": "209-244-0-3",
#     "Level3-2": "209-244-0-4",
#
#     "Norton-1": "199-85-126-10",
#     "Norton-2": "199-85-126-20",
#     "Norton-3": "199-85-126-30",
#
# }

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

# If a dns query is retransmitted 2 times and the 2. retransmission has a response packet to it
# then dont count as unanswered here.
unanswered_query_name_count = {}

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


# Input: IP Address with dashes (e.g. "8-8-8-8")
# Output: Name of the operator (e.g. "Google1")
def get_operator_name_from_ip(ip_addr_with_dashes):
    # print(f"  get_operator_name_from_ip() got parameter: {ip_addr_with_dashes}")
    for operator, ip_addr in operators.items():
        if ip_addr == ip_addr_with_dashes:
            return operator
    else:
        return "Not found!"


# Return all the values (lists) of the given dictionary
def get_values_of_dict(dictionary):
    all_values = list(dictionary.values())
    return all_values


# If a query name does not have the defined structure, skip examining the packet
def is_query_name_valid(query_name):
    query_pattern = "^[0-9]+-[0-9]+-[0-9]+-[0-9]+-[0-9]+-pl[0-9]{1,2}\.packetloss\.syssec-research\.mmci\.uni-saarland\.de\.$"
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
        unanswered_query_name_count[current_pl_rate] = 0

        for rcode in rcodes:
            latencies_by_pl_and_rcode[current_pl_rate, rcode] = []
            rcodes_by_pl[current_pl_rate, rcode] = 0

        for prot in [6, 17]:
            all_queries_count_pl[current_pl_rate, prot] = 0
            # all_response_names_pl[current_pl_rate, prot] = 0


# Read the pcap file with the given packetloss rate while filtering the specified resolver packets
def read_single_pcap(pcap_file_name, current_pl_rate, filtered_resolvers):
    print(f"    Reading file: {pcap_file_name}")

    # Store the dns packets by their attributes: (dns_id, query_name, is_response_packet) in a hash table
    queries = {}
    responses = {}

    # Calculate latency between first query and first response for RCODE 0 answers
    first_latency_queries = {}

    # Read the packets in the pcap file one by one
    index = 1
    for packet in PcapReader(pcap_file_name):
        # Examine only DNS packets
        if packet.haslayer(DNS):
            # print(f"=====================================")
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

                # Query name of packet
                query_name = packet[DNS].qd.qname.decode("utf-8").lower()
                if not is_query_name_valid(query_name):
                    # print(f" Query name does not match: {query_name}")
                    continue

                # Query name: "8-8-8-8-0-pl0.packetloss.syssec-research.mmci.uni-saarland.de
                # Extract ip address and pl rate from query name, find the corresponding operator name
                splitted_query = query_name.split("-")
                ip_with_dashes = splitted_query[0] + "-" + splitted_query[1] + "-" + \
                                 splitted_query[2] + "-" + splitted_query[3]
                operator_name = get_operator_name_from_ip(ip_with_dashes)
                counter = splitted_query[4]
                pl_rate_of_packet = splitted_query[5].split("pl")[1].split(".")[0]

                # Filter if packetloss rate of packet does not match the pl rate of pcap file
                if str(current_pl_rate) != str(pl_rate_of_packet):
                    # print(f"PL rate does not match for: {query}")
                    # print(f" PL rate on query name does not match: {pl_rate_of_packet} != {current_pl_rate}")
                    continue

                # Filter if its a filtered resolver packet
                skip_packet = False
                if filtered_resolvers:
                    for resolver in filtered_resolvers:
                        if resolver == operator_name:
                            skip_packet = True
                            break
                if skip_packet:
                    # print(f"Skipping resolver packet")
                    continue

                rec_type = packet[DNSQR].qtype  # Type 1 is A record
                # Filter if query is not an A record query
                if rec_type != 1:
                    # print(f"  Query type is not an A record: {query_name}")
                    continue

                port = packet.sport
                proto = packet[IP].proto  # 6 is TCP, 17 is UDP
                is_response_packet = int(packet[DNS].qr)  # Packet is a query (0), or a response (1)
                dns_id = packet[DNS].id
                answer_count = int(packet[DNS].ancount)

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

                # DNS query
                if is_response_packet == 0:
                    # Filter non-relevant client packets by IP filtering
                    if "client" in pcap_file_name:
                        if src_ip != client_ip_addr:
                            # print(f"Invalid IP client src_ip {src_ip} for {query_name}")
                            continue

                    elif "auth" in pcap_file_name:
                        if dst_ip != auth_ip_addr:
                            # print(f"Invalid IP auth dst_ip {dst_ip} for {query_name}")
                            continue

                    # TODO: Test this, it was above the "if is_response_packet == 0:"
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

                # DNS response
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
                        latencies_by_pl_and_rcode[current_pl_rate, rcode].append(latency)

                        # Count the RCODEs of the packets of the pl rate
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

                    # Calculate latency between first query and first OK response to it
                    # We found a response to a query name, check if RCODE is 0 and calculate latency
                    if (query_name, 0) in first_latency_queries and rcode == 0:
                        latency = float(packet_time - first_latency_queries[query_name, 0])
                        latencies_first_query_first_resp_OK[current_pl_rate].append(latency)
                        del first_latency_queries[query_name, 0]
                        # print(f"Response to query found: {query_name}")
                        # print(f"Length: {len(first_latency_queries)}")

            except Exception as e:
                print(f"  Error reading packet: {e}")
                print(f"  Error Type: {type(e)}")  # the exception instance
                traceback.print_exc()
                # packet.show()
        index += 1

    # After examining all the packets in the pcap file,
    # check the all_packets array to get unanswered queries
    if current_pl_rate not in unanswered_query_count_by_pl:
        unanswered_query_count_by_pl[current_pl_rate] = 0
    unanswered_query_count_by_pl[current_pl_rate] = len(queries)
    if current_pl_rate not in responses_with_no_query_count_by_pl:
        responses_with_no_query_count_by_pl[current_pl_rate] = 0
    responses_with_no_query_count_by_pl[current_pl_rate] = len(responses)

    # print(f"Unanswered query count/query packet count that doesn't have response: {len(queries)}")
    # print(f"Responses that doesn't have corresponding queries: {len(responses)}")

    if current_pl_rate not in unanswered_query_name_count:
        unanswered_query_name_count[current_pl_rate] = 0
    unanswered_query_name_count[current_pl_rate] = len(first_latency_queries)


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
    global latencies_first_query_first_resp_OK
    global unanswered_query_name_count

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
    latencies_first_query_first_resp_OK = {}
    unanswered_query_name_count = {}

    # print(f"Clean up for next plotting DONE")


def reset_after_auth_pcaps():
    global all_query_names_pl_for_missing
    all_query_names_pl_for_missing = {}
    for current_pl_rate in packetloss_rates:
        all_query_names_pl_for_missing[current_pl_rate] = []

    # print(f"Clean up after auth DONE")


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


def extract_data_from(file_name, pcap_file_prefix, resolvers_to_filter):

    # Check if client or auth data, create root folder for datas
    root_folder_name = "UnknownData"
    if "client" in pcap_file_prefix:
        root_folder_name ="ClientData"
    elif "auth" in pcap_file_prefix:
        root_folder_name = "AuthData"
    create_folder(root_folder_name)

    # Path to store datas
    data_path = root_folder_name + "/" + file_name

    # Create the folder for the current resolver/option
    create_folder(data_path)

    # read the pcap files
    for current_pl_rate in packetloss_rates:
        print(f"  Current packetloss rate: {current_pl_rate}")
        pcap_file_name = pcap_file_prefix + str(current_pl_rate) + ".pcap"
        read_single_pcap(pcap_file_name, current_pl_rate, resolvers_to_filter)

    create_file_write_content(f"{data_path}/RCODE_Counts_(PacketLoss_RCODE)_Count", rcodes_by_pl)
    create_file_write_content(f"{data_path}/Tcp_Counterpart_Of_Udp_Query_(PacketLoss)_Count", tcp_counterpart_of_udp_query)
    create_file_write_content(f"{data_path}/All_Responses_(PacketLoss)_Count", all_responses_count_pl)
    create_file_write_content(f"{data_path}/Unanswered_Query_Count_(PacketLoss)_Count", unanswered_query_count_by_pl)
    create_file_write_content(f"{data_path}/Responses_With_No_Query_Count_(PacketLoss)_Count", responses_with_no_query_count_by_pl)

    create_file_write_content(f"{data_path}/Response_Rcode_0_UDP_Count_(PacketLoss)_Count",
                              rcode_0_udp_count_pl)
    create_file_write_content(f"{data_path}/Response_Rcode_0_TCP_Count_(PacketLoss)_Count",
                              rcode_0_tcp_count_pl)

    # extracted_latencies = extract_latencies_from_dict()
    # ok_latencies = extracted_latencies[0]
    # servfail_latencies = extracted_latencies[1]

    create_file_write_content(f"{data_path}/Latencies_(PacketLoss_RCODE)_[Latencies]", latencies_by_pl_and_rcode)

    create_file_write_content(f"{data_path}/Latencies_First_Q_First_OKResp_(PacketLoss)_[Latencies]",
                              latencies_first_query_first_resp_OK)
    create_file_write_content(f"{data_path}/Unanswered_Query_Names_Count_(PacketLoss)_[Counts]",
                              unanswered_query_name_count)

    # for keys in list(all_query_names_pl.keys()):
    #     print(f"Key 2: {keys[2]}")
    #     # Check if there was really a retransmission
    #     # (count should be > 1 bcs first one is the original, not the duplicate)
    #     result = all_query_names_pl[keys]
    #     if result > 1:
    #         # TCP
    #         if keys[2] == 6:
    #             tcp_query_retransmission_count_list[keys[0]].append(result)
    #         elif keys[2] == 17:
    #             udp_query_retransmission_count_list[keys[0]].append(result)
    #             print(f"  UDP key 0: {keys[0]}")

    # for keys in list(all_response_names_pl.keys()):
    #     # Check if there was really a retransmission
    #     # (count should be > 1 bcs first one is the original, not the duplicate)
    #     # - 1 because 1 means the response query name was seen only once (no retransmission)
    #     result = all_response_names_pl[keys] - 1
    #     if result > 1:
    #         # TCP
    #         if keys[2] == 6:
    #             tcp_response_retransmission_count_list[keys[0]].append(result)
    #         elif keys[2] == 17:
    #             udp_response_retransmission_count_list[keys[0]].append(result)

    create_file_write_content(f"{data_path}/All_Queries_(PacketLoss_QueryName_Protocol)_Count", all_query_names_pl)
    create_file_write_content(f"{data_path}/All_Responses_(PacketLoss_QueryName_Protocol)_Count", all_response_names_pl)


def extract_datas_from_pcap(file_name, selected_resolvers_to_plot):
    print(f"Plot name: {file_name}")
    print(f"Plotting for: {selected_resolvers_to_plot}")

    initialize_dictionaries("client")

    global all_resolvers
    resolvers_to_filter = all_resolvers.copy()

    # Filter given resolver packets
    for selected in selected_resolvers_to_plot:
        if selected in all_resolvers:
            resolvers_to_filter.remove(selected)

    print(f"Filtering: {resolvers_to_filter}")

    # Prefixes of the pcap file names
    client_prefix = "tcpdump_log_client_bond0_"
    auth_prefix = "tcpdump_log_auth1_bond0_"

    # Create client plots
    extract_data_from(file_name, client_prefix, resolvers_to_filter)

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()

    # Initialize dictionaries again
    initialize_dictionaries("auth")

    # Create auth plots
    extract_data_from(file_name, auth_prefix, resolvers_to_filter)

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


# New Operators
# "AdGuard-1", "AdGuard-2", "AdGuard-3", "CleanBrowsing-1", "CleanBrowsing-2", "CleanBrowsing-3", "Cloudflare-1",
# "Cloudflare-2", "Cloudflare-3", "Dyn-1", "Google-1", "Neustar-1", "Neustar-2", "Neustar-3", "Neustar-4",
# "Neustar-5", "OpenDNS-1", "OpenDNS-2", "OpenDNS-3", "Quad9-1", "Quad9-2", "Quad9-3", "Yandex-1", "Yandex-2",
# "Yandex-3", "Level3-1", "Level3-2", "Norton-1", "Norton-2", "Norton-3"
#
# all_resolvers = ["AdGuard-1", "AdGuard-2", "AdGuard-3", "CleanBrowsing-1", "CleanBrowsing-2", "CleanBrowsing-3", "Cloudflare-1",
# "Cloudflare-2", "Cloudflare-3", "Dyn-1", "Google-1", "Neustar-1", "Neustar-2", "Neustar-3", "Neustar-4",
# "Neustar-5", "OpenDNS-1", "OpenDNS-2", "OpenDNS-3", "Quad9-1", "Quad9-2", "Quad9-3", "Yandex-1", "Yandex-2",
# "Yandex-3", "Level3-1", "Level3-2", "Norton-1", "Norton-2", "Norton-3"]

# --------------

# Old PCAP Operators
# "AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "Google1",
# "Google2", "Neustar1", "Neustar2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92", "Yandex1", "Yandex2"

all_resolvers = list(operators.keys())

# Create separate plots for all resolver IPs
for resolver in all_resolvers:
    # try:
    extract_datas_from_pcap(resolver, [resolver])
    # except Exception as e:
    #     print(f"Error creating plots for: {resolver}")
    #     print(f"{str(e)}")

extract_datas_from_pcap("OverallBehaviour", all_resolvers)
