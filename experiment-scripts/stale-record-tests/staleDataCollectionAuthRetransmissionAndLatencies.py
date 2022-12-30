import sys
import time

import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import re
import os
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR

# The packetloss rates that are simulated in the experiment
packetloss_rates = [100]

client_ip_addr = "139.19.117.1"
auth_ip_addr = "139.19.117.11"

# All operators with their IP Addresses with dashes
operators = {
    "Cloudflare-1": "1-1-1-1",
    "Cloudflare-2": "1-1-1-2",
    "Cloudflare-3": "1-1-1-3",

    "Dyn-1": "216-146-35-35",

    "OpenDNS-1": "208-67-222-222",
    "OpenDNS-3": "208-67-222-123",
}

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

tcp_counterpart_of_udp_query = {}

# If a dns query is retransmitted 2 times and the 2. retransmission has a response packet to it
# then dont count as unanswered here.
query_names_with_no_ok_response_count = {}

latencies_first_query_first_resp_OK = {}

# For a resolver, list all the response packets,
# encode 0 -> RCODE ServFail, 1 -> Stale record
# E.g. "8.8.8.8": [1,1,0] means Google-1 had 2 stale record and then ServFail
stale_records_iterations = {}
response_rcode_timings = {}

ttl_list = [60, 300, 900, 3600]

# Compile search pattern for efficiency

# stale-216-146-35-35-100-fzu-ttl60.packetloss.syssec-research.mmci.uni-saarland.de.

query_pattern = "^stale-([0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3}-[0-9]{1,3})-([0-9]{1,3})-[a-zA-Z0-9]{3}-TTL([0-9]{2,4})\.packetloss\.syssec\-research\.mmci\.uni\-saarland\.de\.$"
compiled_pattern = re.compile(query_pattern, re.I)


# Create a folder with the given name
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)


# Create a text file with given name and content
def create_file_write_content(file_name, content):
    f = open(str(file_name) + ".txt", "w")
    f.write(str(content))
    f.close()
    # print(f"  Created file: {str(file_name)}")


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
    search_result = compiled_pattern.search(query_name)
    # print(f"search_result: {search_result}")

    if search_result is None:
        # print(f"Invalid query name: {query_name}")
        return []

    # Extract the query parts using groups
    ip = search_result.group(1)
    pl = search_result.group(2)
    ttl = search_result.group(3)

    # print(f"    ip: {ip}")
    # print(f"    ttl: {ttl}")

    return [ip, pl, ttl]


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

    # for name in list(operators.keys()):
    #     stale_records_iterations[name] = []


# Read the pcap file with the given packetloss rate while filtering the specified resolver packets
def read_single_pcap(pcap_file_name, current_pl_rate, filtered_resolvers):
    print(f"    Reading file: {pcap_file_name}")

    # Store the dns packets by their attributes: (dns_id, query_name, is_response_packet) in a hash table
    queries = {}
    responses = {}

    # Calculate latency between first query and first response for RCODE 0 answers
    first_latency_queries = {}

    retransmission_counts = [0]

    # The time difference between the current packet and the previous packet in the PCAP
    # Used to determine phase switches
    previous_packet_time = 0

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
                    print(f"RCODE format-error, skipping")
                    continue

                # Get source and destination IPs of packet
                dst_ip = packet[IP].dst
                src_ip = packet[IP].src
                # Filter packet if source or destination IP is not valid
                if not is_src_and_dst_ip_valid(pcap_file_name, src_ip, dst_ip):
                    print(f" Invalid IP Skipping")
                    # print(f"    dst_ip: {dst_ip}")
                    # print(f"    src_ip: {src_ip}")
                    continue

                # Query name of packet
                query_name = packet[DNS].qd.qname.decode("utf-8").lower()
                query_extract_result = is_query_name_valid(query_name)
                if len(query_extract_result) == 0:
                    print(f" Query name does not match: {query_name}")
                    continue
                else:
                    # random_5_character_of_query = query_extract_result[0]
                    ip_with_dashes = query_extract_result[0]
                    pl_rate_of_packet = query_extract_result[2]
                    pcap_ttl_value = query_extract_result[2]

                # print(f"TTL: {pcap_ttl_value}")
                operator_name = get_operator_name_from_ip(ip_with_dashes)

                # print(f"Query name: {query_name}")
                # print(f"  ip_with_dashes: {ip_with_dashes}")
                # print(f"  pl_rate_of_packet: {pl_rate_of_packet}")
                # print(f"  random_chars_of_query: {random_chars_of_query}")
                # print(f"  pcap_ttl_value: {pcap_ttl_value}")
                # print(f"  operator_name: {operator_name}")

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

                proto = packet[IP].proto  # 6 is TCP, 17 is UDP
                is_response_packet = int(packet[DNS].qr)  # Packet is a query (0), or a response (1)
                dns_id = packet[DNS].id
                answer_count = int(packet[DNS].ancount)

                # Arrival time of the packet
                packet_time = float(packet.time)
                if previous_packet_time == 0:
                    time_diff = 0
                else:
                    time_diff = packet_time - previous_packet_time
                # print(f"    Query name: {query_name}")
                # print(f"    time_diff: {time_diff}")
                # if time_diff > 60:
                #     time.sleep(5)

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
                    else:
                        #     print(f"Duplicate query name: {query_name}")
                        if time_diff < 60:
                            # continue calculate
                            if not retransmission_counts[len(retransmission_counts) - 1]:
                                retransmission_counts[len(retransmission_counts) - 1] = 0
                            retransmission_counts[len(retransmission_counts) - 1] += 1
                        else:
                            # Create new array beginning from 0
                            retransmission_counts.append(0)
                            retransmission_counts[-1] += 1  # len(retransmission_counts) - 1

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

                    # For response packets, check RCODE and save them as list
                    if operator_name not in stale_records_iterations:
                        stale_records_iterations[operator_name] = []
                    stale_records_iterations[operator_name].append(rcode)
                    # For response packets, check RCODE and save them as list
                    if (operator_name, rcode) not in response_rcode_timings:
                        response_rcode_timings[operator_name, rcode] = []
                    response_rcode_timings[operator_name, rcode].append(packet_time)

            except Exception as e:
                print(f"  Error reading packet: {e}")
                print(f"  Error Type: {type(e)}")  # the exception instance
                traceback.print_exc()
                # packet.show()
        previous_packet_time = packet_time
        # print(f"      retransmission_counts: {retransmission_counts}")
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

    if current_pl_rate not in query_names_with_no_ok_response_count:
        query_names_with_no_ok_response_count[current_pl_rate] = 0
    query_names_with_no_ok_response_count[current_pl_rate] = len(first_latency_queries)

    print(f"retransmission_counts:\n    {retransmission_counts}")


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
    global query_names_with_no_ok_response_count
    global stale_records_iterations
    global response_rcode_timings

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
    stale_records_iterations = {}
    response_rcode_timings = {}

    # print(f"Clean up for next plotting DONE")

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

    # read the pcap files
    for ttl in ttl_list:
        # Path to store datas
        data_path = root_folder_name + "TTL" + str(ttl) + "/" + file_name

        # Create the folder for the current resolver/option
        create_folder(data_path)

        pcap_file_name = pcap_file_prefix + str(ttl) + ".pcap"
        read_single_pcap(pcap_file_name, packetloss_rates[0], resolvers_to_filter)

        create_file_write_content(f"{data_path}/Stale_Record_Iterations_(IP-Of-Resolver)_[RCODEs]",
                                  stale_records_iterations)

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

        create_file_write_content(f"{data_path}/Latencies_First_Q_First_OKResp_(PacketLoss)_[Latencies]",
                                  latencies_first_query_first_resp_OK)
        create_file_write_content(f"{data_path}/Query_Names_With_No_OK_Response_Count_(PacketLoss)_[Counts]",
                                  query_names_with_no_ok_response_count)

        create_file_write_content(f"{data_path}/Response_Rcode_Timings_(IP-Of-Resolver_Rcode)_[Packet_time]",
                                  response_rcode_timings)

        create_file_write_content(f"{data_path}/All_Queries_(PacketLoss_QueryName_Protocol)_Count", all_query_names_pl)
        create_file_write_content(f"{data_path}/All_Responses_(PacketLoss_QueryName_Protocol)_Count", all_response_names_pl)

        if "auth" in pcap_file_prefix:

            reset_for_next_plot()
            initialize_dictionaries("auth")
        else:
            reset_for_next_plot()
            initialize_dictionaries("client")


def extract_datas_from_pcap(file_name, selected_resolvers_to_plot):
    print(f"Plot name: {file_name}")
    print(f"Plotting for: {selected_resolvers_to_plot}")

    # initialize_dictionaries("client")

    global all_resolvers
    resolvers_to_filter = all_resolvers.copy()

    # Filter given resolver packets
    for selected in selected_resolvers_to_plot:
        if selected in all_resolvers:
            resolvers_to_filter.remove(selected)

    print(f"Filtering: {resolvers_to_filter}")

    # Prefixes of the pcap file names
    # client_prefix = "tcpdump_log_client_bond0_FZU_TTL"
    auth_prefix = "tcpdump_log_auth_bond0_FZU_TTL"

    # Create client plots
    # extract_data_from(file_name, client_prefix, resolvers_to_filter)

    # reset the dictionaries for the next plotting/pcaps
    # reset_for_next_plot()

    # Initialize dictionaries again
    initialize_dictionaries("auth")

    # Create auth plots
    extract_data_from(file_name, auth_prefix, resolvers_to_filter)

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()


all_resolvers = list(operators.keys())

# Create separate plots for all resolver IPs
for resolver in all_resolvers:
    # try:
    extract_datas_from_pcap(resolver, [resolver])
    # except Exception as e:
    #     print(f"Error creating plots for: {resolver}")
    #     print(f"{str(e)}")

extract_datas_from_pcap("OverallBehaviour", all_resolvers)
