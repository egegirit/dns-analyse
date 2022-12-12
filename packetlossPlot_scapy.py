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
# TODO: Filter query names with a regex
def is_query_name_valid(query_name):
    if "-pl" not in query_name or "packetloss.syssec-research.mmci.uni-saarland.de" not in query_name:
        # print(f"Invalid query name for: {query}")
        return False
    else:
        return True


# Check if the source or destination IP of the packet is valid, filter packets by IP Address
def is_src_and_dst_ip_valid(pcap_name, src_ip, dst_ip):
    # Client IP is 139.19.117.1
    if "client" in pcap_name:
        if src_ip != "139.19.117.1" and dst_ip != "139.19.117.1":
            # print(f"  IP of client packet invalid: {src_ip}, {dst_ip}")
            return False
    # Server IP is 139.19.117.11
    elif "auth" in pcap_name:

        if src_ip != "139.19.117.11" and dst_ip != "139.19.117.11":
            # print(f"  IP of auth packet invalid: {src_ip}, {dst_ip}")
            return False
    return True


def initialize_dictionaries(pcap_type):
    rcodes = [0, 2, 5]
    for current_pl_rate in packetloss_rates:
        query_duplicate_by_pl[current_pl_rate] = 0
        all_queries_count_pl[current_pl_rate] = 0
        # Only reset this after an auth pcap is read
        if pcap_type == "client":
            all_query_names_pl_for_missing[current_pl_rate] = []
        all_responses_count_pl[current_pl_rate] = 0
        rcode_0_udp_count_pl[current_pl_rate] = 0
        rcode_0_tcp_count_pl[current_pl_rate] = 0

        for rcode in rcodes:
            latencies_by_pl_and_rcode[current_pl_rate, rcode] = []
            rcodes_by_pl[current_pl_rate, rcode] = 0


# Read the pcap file with the given packetloss rate while filtering the specified resolver packets
def read_pcap(pcap_file_name, current_pl_rate, filtered_resolvers):
    print(f"    Reading file: {pcap_file_name}")

    # Get a list of all packets (Very slow if the PCAP file is large)
    # all_packets = rdpcap(pcap_file_name)
    # print(f"Count of packets in pcap: {len(all_packets)}")

    # Store the dns packets by their attributes: (dns_id, query_name, is_response_packet) in a hash table
    queries = {}
    responses = {}

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
                    continue

                # Query name of packet
                query_name = packet[DNSQR].qname.decode("utf-8")
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
                proto = packet[IP].proto
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

                # DNS query
                if is_response_packet == 0:
                    # Filter non-relevant client packets by IP filtering
                    if "client" in pcap_file_name:
                        if src_ip != "139.19.117.1":
                            # print(f"Invalid IP for {query_name}")
                            continue

                    elif "auth" in pcap_file_name:
                        if dst_ip != "139.19.117.11":
                            # print(f"Invalid IP for {query_name}")
                            continue

                    # Count unique query names of pl for dns retransmission plot
                    if (current_pl_rate, query_name) not in all_query_names_pl:
                        all_query_names_pl[current_pl_rate, query_name] = 0
                    else:
                        all_query_names_pl[current_pl_rate, query_name] += 1

                    # Count all the queries to build ratios
                    all_queries_count_pl[current_pl_rate] += 1

                    # Only add it to the queries dictionary if it's not a duplicate
                    if (dns_id, query_name, is_response_packet) not in queries:
                        queries[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                    # Count query duplicate by packetloss rate
                    else:
                        # print(f"Query duplicate: {query_name}, {dns_id}")
                        query_duplicate_by_pl[current_pl_rate] += 1
                # DNS response
                elif is_response_packet == 1:

                    # if answer_count > 0:
                    #     ans_type = int(packet[DNS].an.type)

                    # Filter non-relevant response packets by IP filtering
                    if "client" in pcap_file_name:
                        if dst_ip != "139.19.117.1":
                            # print(f"Invalid IP for {query_name}")
                            continue

                    elif "auth" in pcap_file_name:
                        if src_ip != "139.19.117.11":
                            # print(f"Invalid IP for {query_name}")
                            continue

                    # Count all the responses to build ratios
                    all_responses_count_pl[current_pl_rate] += 1

                    # Count unique query names of responses for response duplicate
                    if (current_pl_rate, query_name) not in all_response_names_pl:
                        all_response_names_pl[current_pl_rate, query_name] = 0
                    all_response_names_pl[current_pl_rate, query_name] += 1

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
                                rcode_0_udp_count_pl[current_pl_rate] += 1
                            elif packet.haslayer(TCP):
                                rcode_0_tcp_count_pl[current_pl_rate] += 1

                    # The response packet has no corresponding query packet for now (and probably will not have any?)
                    # Add the response to the list
                    elif (dns_id, query_name, is_response_packet) not in responses:
                        responses[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                        # print(f"@@ Response has no query to it: {query_name}, {dns_id}")
                    # The response packet has no corresponding query to it and this packet is a duplicate
                    else:
                        print(f"  @@ Duplicate response packet detected for {query_name}, {dns_id}")
                        pass

            except Exception as e:
                print(f"  Error reading packet: {e}")
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


# Create stacked bar chart (rates of: non_stale, stale, refused and servfail packets)
def create_combined_plots(file_name_prefix, directory_name, plots_directory_name):
    n = 12  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5])  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    rcode_0_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    rcode_0_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    global rcode_0_udp_count_pl
    global rcode_0_tcp_count_pl
    rcode_0_udp_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    rcode_0_tcp_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    rcode_2_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    rcode_2_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    rcode_5_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    rcode_5_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    other_rcode_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    other_rcode_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    # unanswered_query_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # unanswered_query_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    #
    # # We will divide all the counts to this basis
    # all_query_names_pl_count = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    # # Calculate unique query names
    # for current_pl_rate, query_name in all_query_names_pl:
    #     index = get_index_of_packetloss_rate(current_pl_rate)
    #     all_query_names_pl_count[index] += all_query_names_pl[current_pl_rate, query_name]
    #
    # print(f"@@ all_query_names_pl_count:\n{all_query_names_pl_count}")

    # # Calculate unanswered_query_counts
    # for key in list(unanswered_query_count_by_pl.keys()):
    #     unanswered_query_counts[get_index_of_packetloss_rate(key)] = unanswered_query_count_by_pl[key]
    #
    # # Calculate unanswered_query_rates
    # for current_pl_rate in packetloss_rates:
    #     try:
    #         index = get_index_of_packetloss_rate(current_pl_rate)
    #         unanswered_query_rates[index] = (unanswered_query_counts[index] / all_query_names_pl_count[
    #             index]) * 100
    #     except ZeroDivisionError:
    #         unanswered_query_rates[index] = 0

    # Calculate RCODE counts
    keys_of_rcodes_by_pl = list(rcodes_by_pl.keys())
    for key in keys_of_rcodes_by_pl:
        # Get only latencies of RCODE = 0
        if key[1] == 0:
            rcode_0_counts[get_index_of_packetloss_rate(key[0])] = rcodes_by_pl[key[0], key[1]]
        # ServFail
        elif key[1] == 2:
            rcode_2_counts[get_index_of_packetloss_rate(key[0])] = rcodes_by_pl[key[0], key[1]]
        # Refused
        elif key[1] == 5:
            rcode_5_counts[get_index_of_packetloss_rate(key[0])] = rcodes_by_pl[key[0], key[1]]
        # Other RCODES
        else:
            other_rcode_counts[get_index_of_packetloss_rate(key[0])] = rcodes_by_pl[key[0], key[1]]

    # Calculate RCODE ratios
    for current_pl_rate in packetloss_rates:
        try:
            index = get_index_of_packetloss_rate(current_pl_rate)
            rcode_0_rates[index] = (rcode_0_counts[index] / all_responses_count_pl[
                current_pl_rate]) * 100  # OLD: all_query_names_pl_count[index]
        except ZeroDivisionError:
            rcode_0_rates[index] = 0
        try:
            rcode_2_rates[index] = (rcode_2_counts[index] / all_responses_count_pl[current_pl_rate]) * 100
        except ZeroDivisionError:
            rcode_2_rates[index] = 0
        try:
            rcode_5_rates[index] = (rcode_5_counts[index] / all_responses_count_pl[current_pl_rate]) * 100
        except ZeroDivisionError:
            rcode_5_rates[index] = 0
        try:
            other_rcode_rates[index] = (other_rcode_counts[index] / all_responses_count_pl[current_pl_rate]) * 100
        except ZeroDivisionError:
            other_rcode_rates[index] = 0

    # Calculate UDP and TCP rate of RCODE 0 packets
    for current_pl_rate in packetloss_rates:
        try:
            index = get_index_of_packetloss_rate(current_pl_rate)
            rcode_0_udp_rates[index] = (rcode_0_udp_count_pl[current_pl_rate] / all_responses_count_pl[
                current_pl_rate]) * 100
        except ZeroDivisionError:
            rcode_0_udp_rates[index] = 0
        try:
            index = get_index_of_packetloss_rate(current_pl_rate)
            rcode_0_tcp_rates[index] = (rcode_0_tcp_count_pl[current_pl_rate] / all_responses_count_pl[
                current_pl_rate]) * 100
        except ZeroDivisionError:
            rcode_0_tcp_rates[index] = 0

    # print(f"all_responses_count_pl: {all_responses_count_pl}")
    # print(f"rcode_0_rates: {rcode_0_rates}")
    # print(f"rcode_2_rates: {rcode_2_rates}")
    # print(f"rcode_5_rates: {rcode_5_rates}")
    # print(f"other_rcode_counts: {other_rcode_counts}")

    # Calculate bottom of refused
    refused_bottom = list()
    for item1, item2 in zip(rcode_0_udp_rates, rcode_0_tcp_rates):
        refused_bottom.append(item1 + item2)

    # Calculate bottom of failed bars by adding ok + refused ratios
    failure_bottom = list()
    for item1, item2 in zip(refused_bottom, rcode_5_rates):
        failure_bottom.append(item1 + item2)

    # Calculate bottom of Other RCODES bar
    other_rcods_bottom = list()
    for item1, item2 in zip(failure_bottom, rcode_2_rates):
        other_rcods_bottom.append(item1 + item2)

    # Calculate bottom of unanswered_rects
    # unanswered_bottom = list()
    # for item1, item2 in zip(other_rcods_bottom, other_rcode_rates):
    #     unanswered_bottom.append(item1 + item2)

    # print(f"failure_bottom: {failure_bottom}")
    # print(f"other_rcods_bottom: {other_rcods_bottom}")
    # print(f"unanswered_bottom: {unanswered_bottom}")
    # print(f"unanswered_query_rates: {unanswered_query_rates}")

    rcode_0_udp_rects = ax.bar(bar_pos, rcode_0_udp_rates, width, bottom=0, color='limegreen')
    rcode_0_tcp_rects = ax.bar(bar_pos, rcode_0_tcp_rates, width, bottom=rcode_0_udp_rates, color='green')
    refused_rects = ax.bar(bar_pos, rcode_5_rates, width, bottom=refused_bottom, color='orange')
    failure_rects = ax.bar(bar_pos, rcode_2_rates, width, bottom=failure_bottom, color='red')
    others_rects = ax.bar(bar_pos, other_rcode_rates, width, bottom=other_rcods_bottom, color='dodgerblue')
    # unanswered_rects = ax.bar(bar_pos, unanswered_query_rates, width, bottom=unanswered_bottom, color='silver')

    # Title of the graph, x and y label
    plot_title = f"Packetloss Experiment ({file_name_prefix})"
    plt.xlabel("Packetloss rate")
    plt.ylabel("Rate of results")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0, top=100)

    ax.set_xticks(bar_pos)
    ax.set_xticklabels((0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95))

    # Create legend at the top left of the plot
    ax.legend((others_rects[0], failure_rects[0], refused_rects[0], rcode_0_tcp_rects[0],
               rcode_0_udp_rects[0]),
              ('Other RCODE', 'Failure', 'Refused', 'OK (TCP)', 'OK (UDP)'), framealpha=0.5,
              bbox_to_anchor=(0.1, 1.1))  # 'Unanswered queries', unanswered_rects[0]

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_rcode_0_udp_rects(rects):
        index = 0
        for rect in rects:
            if rcode_0_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"OK-U#{rcode_0_counts[index]}",  # /{all_queries_count_pl[packetloss_rates[index]]}
                        ha='center', va='bottom')
            index += 1

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_rcode_0_tcp_rects(udp_rects, tcp_rects):
        hight_of_non_stale_plus_stale = []
        index = 0
        for rect in udp_rects:
            h = rect.get_height()
            hight_of_non_stale_plus_stale.append(int(h))
            index += 1

        index = 0
        for rect in tcp_rects:
            if rcode_5_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_stale_plus_stale[index],
                        f"OK-T#{rcode_5_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    # Text of refused bars
    def autolabel_refused(udp_rects, tcp_rects, refused_rects):
        hight_of_non_stale_plus_stale = []
        index = 0
        for rect in udp_rects:
            h = rect.get_height()
            hight_of_non_stale_plus_stale.append(int(h))
            index += 1

        for rect in tcp_rects:
            h = rect.get_height()
            hight_of_non_stale_plus_stale.append(int(h))
            index += 1

        index = 0
        for rect in refused_rects:
            if rcode_5_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_stale_plus_stale[index],
                        f"R#{rcode_5_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    # Text of failed bars
    def autolabel_fail(udp_rects, tcp_rects, refused_rects, fail_rects):
        hight_of_non_failed = []
        index = 0
        for rect in udp_rects:
            h = rect.get_height()
            hight_of_non_failed.append(int(h))
            index += 1

        index = 0
        for rect in tcp_rects:
            h = rect.get_height()
            hight_of_non_failed.append(int(h))
            index += 1

        index = 0
        for rect in refused_rects:
            h = rect.get_height()
            hight_of_non_failed[index] += int(h)
            index += 1

        index = 0
        for rect in fail_rects:
            if rcode_2_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_failed[index],
                        f"F#{rcode_2_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    # Text of others
    def autolabel_other(udp_rects, tcp_rects, refused_rects, fail_rects, other_rects):
        hight_of_non_failed = []
        index = 0
        for rect in udp_rects:
            h = rect.get_height()
            hight_of_non_failed.append(int(h))
            index += 1

        index = 0
        for rect in tcp_rects:
            h = rect.get_height()
            hight_of_non_failed.append(int(h))
            index += 1

        index = 0
        for rect in refused_rects:
            h = rect.get_height()
            hight_of_non_failed[index] += int(h)
            index += 1

        index = 0
        for rect in fail_rects:
            h = rect.get_height()
            hight_of_non_failed[index] += int(h)
            index += 1

        index = 0
        for rect in other_rects:
            if other_rcode_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_failed[index],
                        f"Other#{other_rcode_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    # Text of others
    # def autolabel_unanswered(udp_rects, tcp_rects, refused_rects, fail_rects, other_rects, unanswered_rects):
    #     hight_of_non_failed = []
    #     index = 0
    #     for rect in udp_rects:
    #         h = rect.get_height()
    #         hight_of_non_failed.append(int(h))
    #         index += 1
    #
    #     index = 0
    #     for rect in tcp_rects:
    #         h = rect.get_height()
    #         hight_of_non_failed.append(int(h))
    #         index += 1
    #
    #     index = 0
    #     for rect in refused_rects:
    #         h = rect.get_height()
    #         hight_of_non_failed[index] += int(h)
    #         index += 1
    #
    #     index = 0
    #     for rect in fail_rects:
    #         h = rect.get_height()
    #         hight_of_non_failed[index] += int(h)
    #         index += 1
    #
    #     index = 0
    #     for rect in other_rects:
    #         h = rect.get_height()
    #         hight_of_non_failed[index] += int(h)
    #         index += 1
    #
    #     index = 0
    #     for rect in unanswered_rects:
    #         if unanswered_query_counts[index] != 0:
    #             h = rect.get_height()
    #             ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_failed[index],
    #                     f"U#{unanswered_query_counts[index]}",
    #                     ha='center', va='bottom')
    #         index += 1

    autolabel_rcode_0_udp_rects(rcode_0_udp_rects)
    autolabel_rcode_0_tcp_rects(rcode_0_udp_rects, rcode_0_tcp_rects)
    autolabel_refused(rcode_0_udp_rects, rcode_0_tcp_rects, refused_rects)
    autolabel_fail(rcode_0_udp_rects, rcode_0_tcp_rects, refused_rects, failure_rects)
    autolabel_other(rcode_0_udp_rects, rcode_0_tcp_rects, refused_rects, failure_rects, others_rects)
    # autolabel_unanswered(rcode_0_udp_rects, rcode_0_tcp_rects, refused_rects, failure_rects, others_rects,
    #                      unanswered_rects)

    # plt.show()

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    if not os.path.exists(plots_directory_name + "/" + directory_name):
        os.makedirs(plots_directory_name + "/" + directory_name)

    plot_type = ""
    directory_name_lower = plots_directory_name.lower()
    if "client" in directory_name_lower:
        plot_type = "client"
    elif "auth" in directory_name_lower:
        plot_type = "auth"

    save_path = plots_directory_name + "/" + directory_name + "/" + plot_type + "_" + file_name_prefix + '_combinedPlot.png'

    plt.savefig(save_path, dpi=100, bbox_inches='tight')

    # save plot as png
    # plt.savefig((file_name_prefix + '_StaleRecordPlot.png'))
    print(f"      Created box plot: {save_path}")
    # Clear plots
    plt.cla()
    plt.close()


# Create stacked bar chart (rates of: non_stale, stale, refused and servfail packets)
def create_bar_plot(file_name_prefix, directory_name, unanswered_dict, plots_directory_name, plot_title, y_label):
    print(f"    Creating unanswered bar plot")
    n = 12  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5])  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    dict_values = get_values_of_dict(unanswered_dict)
    non_stale_rects = ax.bar(bar_pos, dict_values, width, bottom=0, color='dodgerblue')

    # Title of the graph, x and y label
    plot_title = f"{plot_title} ({file_name_prefix})"
    plt.xlabel("Packetloss rate")
    plt.ylabel(f"{y_label}")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0)

    ax.set_xticks(bar_pos)
    ax.set_xticklabels((0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95))

    # Create legend at the top left of the plot
    # ax.legend((non_stale_rects[0]), ('OK'), framealpha=0.5, bbox_to_anchor=(0.1, 1.25))

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_non_stale(rects):
        index = 0
        for rect in rects:
            if dict_values[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"U#{dict_values[index]}",
                        ha='center', va='bottom')
            index += 1

    autolabel_non_stale(non_stale_rects)

    # plt.show()

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    if not os.path.exists(plots_directory_name + "/" + directory_name):
        os.makedirs(plots_directory_name + "/" + directory_name)

    plot_type = ""
    directory_name_lower = plots_directory_name.lower()
    if "client" in directory_name_lower:
        plot_type = "client"
    elif "auth" in directory_name_lower:
        plot_type = "auth"

    save_path = plots_directory_name + "/" + directory_name + "/" + plot_type + "_" + file_name_prefix + '_UnansweredQueryPlot.png'

    plt.savefig(save_path, dpi=100, bbox_inches='tight')

    # save plot as png
    # plt.savefig((file_name_prefix + '_StaleRecordPlot.png'))
    print(f"      Created box plot: {save_path}")
    # Clear plots
    plt.cla()
    plt.close()


# Create box plot for the calculated latencies
def create_latency_box_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, latency_dict,
                            plots_directory_name, log_scale=False):
    print(f"    Creating box plot: {file_name_prefix}")
    # print(f"   Inside the folder: {directory_name}")
    # print(f"   Limits: [{bottom_limit}, {upper_limit}]")

    # Split the _OK or _Error part from the resolver name
    operator_name = file_name_prefix.split("_")[0]

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    ax.set_title(f"Response Latency of " + file_name_prefix)

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    if log_scale:
        ax.set_yscale('log', base=2)
    # else: ax.set_yscale('linear')

    dict_values = get_values_of_dict(latency_dict)

    # Add the data counts onto the plot as text
    data_count_string = ""
    for i in range(len(dict_values)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(dict_values[i])) + "\n"

    left, width = .25, .5
    bottom, height = .25, .5
    right = left + width
    top = bottom + height
    ax.text(0.5 * (left + right), .80 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Creating plot
    ax.boxplot(dict_values, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95],
               widths=4.4)

    if not os.path.exists(plots_directory_name + "/" + directory_name + "/" + operator_name):
        os.makedirs(plots_directory_name + "/" + directory_name + "/" + operator_name)

    plot_type = ""
    directory_name_lower = plots_directory_name.lower()
    if "client" in directory_name_lower:
        plot_type = "client"
    elif "auth" in directory_name_lower:
        plot_type = "auth"

    save_path = plots_directory_name + "/" + directory_name + "/" + operator_name + "/" + plot_type + "_" + file_name_prefix + '_LatencyBoxPlot.png'

    # save plot as png
    plt.savefig(save_path, bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created box plot: {save_path}")
    # Clear plots
    plt.cla()
    plt.close()


# Create violin plots of the calculated latencies
def create_latency_violin_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, latency_dict,
                               plots_directory_name, log_scale=False):
    print(f"    Creating violin plot: {file_name_prefix}")
    # print(f"   Inside the folder: {directory_name}")
    # print(f"   Log-scale: {log_scale}")

    # Split the _OK or _Error part from the resolver name
    operator_name = file_name_prefix.split("_")[0]

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    ax.set_title(f"Response Latency of " + file_name_prefix)

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Handle zero values with a -1 dummy value
    data = get_values_of_dict(latency_dict)
    for i in range(len(data)):
        if len(data[i]) == 0:
            data[i] = [0]

    # Create and save Violinplot
    bp = ax.violinplot(dataset=data, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(get_values_of_dict(latency_dict))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(get_values_of_dict(latency_dict)[i])) + "\n"

    left, width = .25, .5
    bottom, height = .25, .5
    right = left + width
    top = bottom + height
    ax.text(0.5 * (left + right), .80 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')

    # Add legend for mean and median
    blue_line = mlines.Line2D([], [], color='blue', marker='', markersize=15, label='mean')
    red_line = mlines.Line2D([], [], color='red', marker='', markersize=15, label='median')
    ax.legend(handles=[blue_line, red_line], loc='upper left')

    if not os.path.exists(plots_directory_name + "/" + directory_name + "/" + operator_name):
        os.makedirs(plots_directory_name + "/" + directory_name + "/" + operator_name)

    plot_type = ""
    directory_name_lower = plots_directory_name.lower()
    if "client" in directory_name_lower:
        plot_type = "client"
    elif "auth" in directory_name_lower:
        plot_type = "auth"

    save_path = plots_directory_name + "/" + directory_name + "/" + operator_name + "/" + plot_type + "_" + file_name_prefix + '_LatencyViolinPlot.png'

    # save plot as png
    plt.savefig(save_path, bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created violin plot: {save_path}")
    # Clear plots
    plt.cla()
    plt.close()


# Create retransmission plot
def create_violin_plot(directory_name, file_name_prefix, latency_dict, plots_directory_name, plot_title, y_label,
                       plot_postfix_name):
    print(f"    Creating violin plot: {file_name_prefix}")
    # print(f"   Inside the folder: {directory_name}")
    # print(f"   Log-scale: {log_scale}")

    # Split the _OK or _Error part from the resolver name
    operator_name = file_name_prefix.split("_")[0]

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    ax.set_ylabel(f'{y_label}')
    ax.set_xlabel('Packetloss in percentage')
    ax.set_title(f"{plot_title} " + file_name_prefix)

    # Handle zero values with a -1 dummy value
    data = get_values_of_dict(latency_dict)
    plot_upper_limit = 1
    for i in range(len(data)):
        if len(data[i]) == 0:
            data[i] = [0]
        else:
            # Find maximum count for top limit of plot
            for number in data[i]:
                if number > plot_upper_limit:
                    plot_upper_limit = number

    # print(f"Data of {plot_title}: {data}")
    # print(f" plot_upper_limit: {plot_upper_limit}")

    plt.ylim(bottom=0, top=plot_upper_limit + 1)

    # Create and save Violinplot
    bp = ax.violinplot(dataset=data, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(get_values_of_dict(latency_dict))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(get_values_of_dict(latency_dict)[i])) + "\n"

    left, width = .25, .5
    bottom, height = .25, .5
    right = left + width
    top = bottom + height
    ax.text(0.5 * (left + right), .80 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')

    # Add legend for mean and median
    blue_line = mlines.Line2D([], [], color='blue', marker='', markersize=15, label='mean')
    red_line = mlines.Line2D([], [], color='red', marker='', markersize=15, label='median')
    ax.legend(handles=[blue_line, red_line], loc='upper left')

    if not os.path.exists(plots_directory_name + "/" + directory_name + "/" + operator_name):
        os.makedirs(plots_directory_name + "/" + directory_name + "/" + operator_name)

    plot_type = ""
    directory_name_lower = plots_directory_name.lower()
    if "client" in directory_name_lower:
        plot_type = "client"
    elif "auth" in directory_name_lower:
        plot_type = "auth"

    save_path = plots_directory_name + "/" + directory_name + "/" + operator_name + "/" + plot_type + "_" + file_name_prefix + f'_{plot_postfix_name}.png'

    # save plot as png
    plt.savefig(save_path, bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created violin plot: {save_path}")
    # Clear plots
    plt.cla()
    plt.close()


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


client_plots_directory_name = "ClientPlots"
auth_plots_directory_name = "AuthPlots"
latency_directory_name = "LatencyPlots"
rate_plots_directory_name = "RatePlots"
unanswered_query_plots_directory_name = "UnansweredQueryPlots"
missing_query_plots_directory_name = "MissingQueryPlots"
retransmission_plots_directory_name = "RetransmissionPlots"
latency_upper_limit = 20


def create_plots_of_type(file_name, pcap_file_prefix, resolvers_to_filter, directory_type):
    # read the client pcap files
    for current_pl_rate in packetloss_rates:
        print(f"  Current packetloss rate: {current_pl_rate}")

        pcap_file_name = pcap_file_prefix + str(current_pl_rate) + ".pcap"
        read_pcap(pcap_file_name, current_pl_rate, resolvers_to_filter)

    # create rate plot
    create_combined_plots(file_name, rate_plots_directory_name, directory_type)

    extracted_latencies = extract_latencies_from_dict()
    ok_latencies = extracted_latencies[0]
    servfail_latencies = extracted_latencies[1]

    # print(f"@@@@ servfail_latencies: {servfail_latencies}")

    # create OK latency plots
    create_latency_violin_plot(latency_directory_name, file_name + "_OK", 0, latency_upper_limit,
                               ok_latencies, directory_type, log_scale=False)
    create_latency_box_plot(latency_directory_name, file_name + "_OK", 0, latency_upper_limit,
                            ok_latencies, directory_type,
                            log_scale=False)

    # create ServFail latency plots
    create_latency_violin_plot(latency_directory_name, file_name + "_Error", 0, latency_upper_limit,
                               servfail_latencies, directory_type, log_scale=False)
    create_latency_box_plot(latency_directory_name, file_name + "_Error", 0, latency_upper_limit,
                            servfail_latencies, directory_type,
                            log_scale=False)

    # Create unanswered query plot
    create_bar_plot(file_name, unanswered_query_plots_directory_name, unanswered_query_count_by_pl,
                    directory_type, "Unanswered Queries", "Unanswered Query Count")

    # Create retransmission plots
    query_retransmission_count_list = {
        "0": [], "10": [], "20": [], "30": [],
        "40": [], "50": [], "60": [], "70": [],
        "80": [], "85": [], "90": [], "95": []
    }

    response_retransmission_count_list = {
        "0": [], "10": [], "20": [], "30": [],
        "40": [], "50": [], "60": [], "70": [],
        "80": [], "85": [], "90": [], "95": []
    }

    for pl_rate, query_name in all_query_names_pl:
        # Check if there was really a retransmission
        # (count should be > 1 bcs first one is the original, not the duplicate)
        result = all_query_names_pl[pl_rate, query_name]
        if result > 1:
            query_retransmission_count_list[str(pl_rate)].append(result)

    for pl_rate, query_name in all_response_names_pl:
        # Check if there was really a retransmission
        # (count should be > 1 bcs first one is the original, not the duplicate)
        result = all_response_names_pl[pl_rate, query_name]
        if result > 1:
            response_retransmission_count_list[str(pl_rate)].append(result)

    # print(f"query_retransmission_count_list: {query_retransmission_count_list}")
    # print(f"response_retransmission_count_list: {response_retransmission_count_list}")

    create_violin_plot(retransmission_plots_directory_name, file_name, query_retransmission_count_list, directory_type,
                       "DNS Query Retransmissions", "Query Retransmission Counts", "QueryRetransmissionPlot")

    create_violin_plot(retransmission_plots_directory_name, file_name, response_retransmission_count_list,
                       directory_type, "DNS Response Retransmissions", "Response Retransmission Counts",
                       "ResponseRetransmissionPlot")


def create_plot_for(file_name, selected_resolvers_to_plot):
    print(f"Plot name: {file_name}")
    print(f"Plotting for: {selected_resolvers_to_plot}")

    initialize_dictionaries("client")

    global all_resolvers
    resolvers_to_filter = all_resolvers.copy()

    for selected in selected_resolvers_to_plot:
        if selected in all_resolvers:
            resolvers_to_filter.remove(selected)

    print(f"Filtering: {resolvers_to_filter}")

    # Prefixes of the pcap file names
    client_prefix = "tcpdump_log_client_bond0_"
    auth_prefix = "tcpdump_log_auth1_bond0_"

    # Create client plots
    create_plots_of_type(file_name, client_prefix, resolvers_to_filter, client_plots_directory_name)
    # print(f"latencies_by_pl_and_rcode:\n{latencies_by_pl_and_rcode}")

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()

    # Initialize dictionaries again
    initialize_dictionaries("auth")

    # Create auth plots
    create_plots_of_type(file_name, auth_prefix, resolvers_to_filter, auth_plots_directory_name)

    # Create missing query plots
    missing_query_count_list = {
        "0": 0, "10": 0, "20": 0, "30": 0,
        "40": 0, "50": 0, "60": 0, "70": 0,
        "80": 0, "85": 0, "90": 0, "95": 0
    }

    for pl in packetloss_rates:
        missing_query_count_list[str(pl)] = len(all_query_names_pl_for_missing[pl])

    # print(f"  all_query_names_pl_for_missing:\n{all_query_names_pl_for_missing}")
    # print(f"  missing_query_count_list:\n{missing_query_count_list}")

    create_bar_plot(file_name, missing_query_plots_directory_name, missing_query_count_list,
                    auth_plots_directory_name, "Missing Queries", "Missing Query Count")

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()

    # Reset missing query count
    reset_after_auth_pcaps()


# New Operators
# "AdGuard-1", "AdGuard-2", "AdGuard-3", "CleanBrowsing-1", "CleanBrowsing-2", "CleanBrowsing-3", "Cloudflare-1",
# "Cloudflare-2", "Cloudflare-3", "Dyn-1", "Google-1", "Neustar-1", "Neustar-2", "Neustar-3", "Neustar-4",
# "Neustar-5", "OpenDNS-1", "OpenDNS-2", "OpenDNS-3", "Quad9-1", "Quad9-2", "Quad9-3", "Yandex-1", "Yandex-2",
# "Yandex-3", "Level3-1", "Level3-2", "Norton-1", "Norton-2", "Norton-3"

# --------------

# Old PCAP Operators
# "AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "Google1",
# "Google2", "Neustar1", "Neustar2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92", "Yandex1", "Yandex2"

all_resolvers = ["AdGuard-1", "AdGuard-2", "CleanBrowsing-1", "CleanBrowsing-2",
                 "Cloudflare-1", "Cloudflare-2", "Dyn-1", "Dyn-2", "Google-1", "Google-2",
                 "Neustar-1", "Neustar-2", "OpenDNS-1", "OpenDNS-2", "Quad9-1", "Quad9-2",
                 "Yandex-1", "Yandex-2"]

# Create separate plots for all resolver IPs
for resolver in all_resolvers:
    # try:
    create_plot_for(resolver, [resolver])
    # except Exception as e:
    #     print(f"Error creating plots for: {resolver}")
    #     print(f"{str(e)}")

create_plot_for("OverallBehaviour", ["AdGuard-1", "AdGuard-2", "CleanBrowsing-1", "CleanBrowsing-2",
                                     "Cloudflare-1", "Cloudflare-2", "Dyn-1", "Dyn-2", "Google-1", "Google-2",
                                     "Neustar-1", "Neustar-2", "OpenDNS-1", "OpenDNS-2", "Quad9-1", "Quad9-2",
                                     "Yandex-1", "Yandex-2"])
