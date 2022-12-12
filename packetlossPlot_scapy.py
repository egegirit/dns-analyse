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
    "AdGuard1": "94-140-14-14",
    "AdGuard2": "94-140-14-15",
    "CleanBrowsing1": "185-228-168-168",
    "CleanBrowsing2": "185-228-168-9",
    "Cloudflare1": "1-1-1-1",
    "Cloudflare2": "1-0-0-1",
    "Dyn1": "216-146-35-35",
    "Dyn2": "216-146-36-36",
    "Google1": "8-8-8-8",
    "Google2": "8-8-4-4",
    "Neustar1": "64-6-64-6",
    "Neustar2": "156-154-70-1",
    "OpenDNS1": "208-67-222-222",
    "OpenDNS2": "208-67-222-2",
    "Quad91": "9-9-9-9",
    "Quad92": "9-9-9-11",
    "Yandex1": "77-88-8-1",
    "Yandex2": "77-88-8-8"
}

# All operators with their IP Addresses with dashes
# operators = {
#     "AdGuard_1": "94-140-14-14",
#     "AdGuard_2": "94-140-14-15",
#     "AdGuard_3": "94-140-14-140",
#
#     "CleanBrowsing_1": "185-228-168-168",
#     "CleanBrowsing_2": "185-228-168-9",
#     "CleanBrowsing_3": "185-228-168-10",
#
#     "Cloudflare_1": "1-1-1-1",
#     "Cloudflare_2": "1-1-1-2",
#     "Cloudflare_3": "1-1-1-3",
#
#     "Dyn_1": "216-146-35-35",
#
#     "Google_1": "8-8-8-8",
#
#     "Neustar_1": "64-6-64-6",
#     "Neustar_2": "156-154-70-2",
#     "Neustar_3": "156-154-70-3",
#     "Neustar_4": "156-154-70-4",
#     "Neustar_5": "156-154-70-5",
#
#     "OpenDNS_1": "208-67-222-222",
#     "OpenDNS_2": "208-67-222-2",
#     "OpenDNS_3": "208-67-222-123",
#
#     "Quad9_1": "9-9-9-9",
#     "Quad9_2": "9-9-9-11",
#     "Quad9_3": "9-9-9-10",
#
#     "Yandex_1": "77-88-8-1",
#     "Yandex_2": "77-88-8-2",
#     "Yandex_3": "77-88-8-3",
#
#     "Level3_1": "209-244-0-3",
#     "Level3_2": "209-244-0-4",
#
#     "Norton_1": "199-85-126-10",
#     "Norton_2": "199-85-126-20",
#     "Norton_3": "199-85-126-30",
#
# }

unanswered_query_count_by_pl = {}
responses_with_no_query_count_by_pl = {}
latencies_by_pl_and_rcode = {}
query_duplicate_by_pl = {}
rcodes_by_pl = {}

# Store all query names of client to detect any missing queries on the auth pcap
# Queries that are in client pcaps but not in auth.
all_query_names_pl = {}

all_responses_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}
missing_query_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}


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
def is_src_or_dst_ip_valid(pcap_name, src_ip, dst_ip):
    # Client IP is 139.19.117.1
    if "client" in pcap_name:
        if src_ip != "139.19.117.1" and dst_ip != "139.19.117.1":
            # print(f"IP of client packet invalid: {query}")
            return False
    # Server IP is 139.19.117.11
    elif "auth" in pcap_name:
        if src_ip != "139.19.117.11" and dst_ip != "139.19.117.11":
            # print(f"IP of auth packet invalid: {query}")
            return False
    else:
        return True


# Read the pcap file with the given packetloss rate while filtering the specified resolver packets
def read_pcap(pcap_file_name, current_pl_rate, filtered_resolvers):
    print(f"  Reading file: {pcap_file_name}")

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
                dst_port = packet[IP].dst
                src_port = packet[IP].src
                # Filter packet if source or destination IP is not valid
                if not is_src_or_dst_ip_valid(pcap_file_name, src_port, dst_port):
                    continue

                # Query name of packet
                query_name = packet[DNSQR].qname.decode("utf-8")
                if not is_query_name_valid(query_name):
                    continue

                # Query name: "8-8-8-8-0-pl0.packetloss.syssec-research.mmci.uni-saarland.de
                # Extract ip address and pl rate from query name, find the corresponding operator name
                splitted_query = query_name.split("-")
                ip_with_dashes = splitted_query[0] + "-" + splitted_query[1] + "-" + \
                                 splitted_query[2] + "-" + splitted_query[3]
                operator_name = get_operator_name_from_ip(ip_with_dashes)
                counter = splitted_query[4]
                pl_rate_of_packet = splitted_query[5].split("pl")[1]

                # Filter if packetloss rate of packet does not match the pl rate of pcap file
                if str(current_pl_rate) != str(pl_rate_of_packet):
                    # print(f"PL rate does not match for: {query}")
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
                    # print(f"  Query type is not an A record: {query}")
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

                # print(f"Query name: {query}")
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
                    if current_pl_rate not in all_query_names_pl:
                        all_query_names_pl[current_pl_rate] = []
                    else:
                        all_query_names_pl[current_pl_rate].append(query_name)
                # After reading all the client pcaps, delete all the client queries which are also in auth pcap
                elif "auth" in pcap_file_name:
                    if query_name in all_query_names_pl[current_pl_rate]:
                        all_query_names_pl[current_pl_rate].remove(query_name)

                # DNS query
                if is_response_packet == 0:
                    # Only add it to the queries dictionary if it's not a duplicate
                    if (dns_id, query_name, is_response_packet) not in queries:
                        queries[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                    # Count query duplicate by packetloss rate
                    else:
                        print(f"Query duplicate: {query_name}, {dns_id}")
                        if current_pl_rate not in query_duplicate_by_pl:
                            query_duplicate_by_pl[current_pl_rate] = 0
                        else:
                            query_duplicate_by_pl[current_pl_rate] += 1
                # DNS response
                elif is_response_packet == 1:
                    # Check if we found a corresponding response packet to a query
                    if (dns_id, query_name, 0) in queries:
                        latency = float(packet_time - queries[dns_id, query_name, 0][0])
                        # Delete the query from dictionary because we calculated its latency
                        del queries[dns_id, query_name, 0]

                        # Store the latency directly using the rcode and current packetloss rate
                        # Create the latency keys if not created before
                        if (current_pl_rate, rcode) not in latencies_by_pl_and_rcode:
                            latencies_by_pl_and_rcode[current_pl_rate, rcode] = []
                        else:
                            latencies_by_pl_and_rcode[current_pl_rate, rcode].append(latency)

                        # Count the RCODEs of the packets of the pl rate
                        if (current_pl_rate, rcode) not in rcodes_by_pl:
                            rcodes_by_pl[current_pl_rate, rcode] = 0
                        else:
                            rcodes_by_pl[current_pl_rate, rcode] += 1

                    # The response packet has no corresponding query packet for now (and probably will not have any?)
                    # Add the response to the list
                    elif (dns_id, query_name, is_response_packet) not in responses:
                        responses[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                    # The response packet has no corresponding query to it and this packet is a duplicate
                    else:
                        pass
                        # print(f"Duplicate response packet detected for {query_name}, {dns_id}")

            except Exception as e:
                print(f"  Error reading packet: {str(e)}")
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
def create_combined_plots(file_name_prefix, directory_name):
    n = 13  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10])  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    # Non stale datas
    ok_rate_vals = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    ok_counts = list(ok_count_pl.values())
    for i in range(len(ok_rate_vals)):
        try:
            ok_rate_vals[i] = (ok_counts[i] / all_responses_count_pl[
                str(packetloss_rates[i])]) * 100
        except ZeroDivisionError:
            ok_rate_vals[i] = 0

    # Failure datas
    failure_rate_vals = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    failure_rate_counts = list(servfail_count_pl.values())
    for i in range(len(failure_rate_vals)):
        try:
            failure_rate_vals[i] = (failure_rate_counts[i] / all_responses_count_pl[
                str(packetloss_rates[i])]) * 100
        except ZeroDivisionError:
            failure_rate_vals[i] = 0

    # Refused datas
    refused_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    refused_counts = list(refused_count_pl.values())
    for i in range(len(refused_rates)):
        try:
            refused_rates[i] = (refused_counts[i] / all_responses_count_pl[str(packetloss_rates[i])]) * 100
        except ZeroDivisionError:
            refused_rates[i] = 0

    # TODO: Other RCODES
    other_rates = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    other_counts = list(other_rcodes_count_pl.values())
    for i in range(len(refused_rates)):
        try:
            other_rates[i] = (other_counts[i] / all_responses_count_pl[str(packetloss_rates[i])]) * 100
        except ZeroDivisionError:
            refused_rates[i] = 0

    # Calculate bottom of failed bars by adding ok + refused ratios
    refused_plus_ok = list()
    for item1, item2 in zip(ok_rate_vals, refused_rates):
        refused_plus_ok.append(item1 + item2)

    # Calculate bottom of Other RCODES bar
    other_rcods_bottom = list()
    for item1, item2 in zip(refused_plus_ok, failure_rate_vals):
        other_rcods_bottom.append(item1 + item2)

    ok_rects = ax.bar(bar_pos, ok_rate_vals, width, bottom=0, color='green')
    refused_rects = ax.bar(bar_pos, refused_rates, width, bottom=ok_rate_vals, color='orange')
    failure_rects = ax.bar(bar_pos, failure_rate_vals, width, bottom=refused_plus_ok, color='red')

    # Title of the graph, x and y label
    plot_title = f"Stale Record Experiment ({file_name_prefix})"
    plt.xlabel("Packetloss rate")
    plt.ylabel("Rate of results")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0, top=100)

    ax.set_xticks(bar_pos)
    ax.set_xticklabels((0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100))

    # Create legend at the top left of the plot
    ax.legend((failure_rects[0], refused_rects[0], ok_rects[0]),
              ('Failure', 'Refused', 'OK'), framealpha=0.5,
              bbox_to_anchor=(0.1, 1.14))

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_ok(rects):
        index = 0
        for rect in rects:
            if ok_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"OK#{ok_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    # Text of refused bars
    def autolabel_refused(ok_rects, refused_rects):
        hight_of_non_stale_plus_stale = []
        index = 0
        for rect in ok_rects:
            h = rect.get_height()
            hight_of_non_stale_plus_stale.append(int(h))
            index += 1

        index = 0
        for rect in refused_rects:
            if refused_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_stale_plus_stale[index],
                        f"R#{refused_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    # Text of failed bars
    def autolabel_fail(ok_rects, refused_rects, fail_rects):
        hight_of_non_failed = []
        index = 0
        for rect in ok_rects:
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
            if failure_rate_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_failed[index],
                        f"F#{failure_rate_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    autolabel_ok(ok_rects)
    autolabel_refused(ok_rects, refused_rects)
    autolabel_fail(ok_rects, refused_rects, failure_rects)

    # plt.show()

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    plt.savefig((directory_name + "/" + file_name_prefix + '_StaleRecordPlot.png'), dpi=100, bbox_inches='tight')

    # save plot as png
    # plt.savefig((file_name_prefix + '_StaleRecordPlot.png'))
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create stacked bar chart (rates of: non_stale, stale, refused and servfail packets)
def create_unanswered_query_plots(file_name_prefix, directory_name, unanswered_dict):
    n = 13  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10])  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    dict_values = get_values_of_dict(unanswered_dict)
    non_stale_rects = ax.bar(bar_pos, dict_values, width, bottom=0, color='green')

    # Title of the graph, x and y label
    plot_title = f"Unanswered query count ({file_name_prefix})"
    plt.xlabel("Packetloss rate")
    plt.ylabel("Unanswered query count")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0)

    ax.set_xticks(bar_pos)
    ax.set_xticklabels((0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100))

    # Create legend at the top left of the plot
    # ax.legend((non_stale_rects[0]), ('OK'), framealpha=0.5, bbox_to_anchor=(0.1, 1.25))

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_non_stale(rects):
        index = 0
        for rect in rects:
            if dict_values[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"OK#{dict_values[index]}",
                        ha='center', va='bottom')
            index += 1

    autolabel_non_stale(non_stale_rects)

    # plt.show()

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    plt.savefig((directory_name + "/" + file_name_prefix + '_UnansweredQueryPlot.png'), dpi=100, bbox_inches='tight')

    # save plot as png
    # plt.savefig((file_name_prefix + '_StaleRecordPlot.png'))
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create box plot for the calculated latencies
def create_latency_box_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, latency_dict, log_scale=False):
    print(f" Creating box plot: {file_name_prefix}")
    print(f"   Inside the folder: {directory_name}")
    print(f"   Limits: [{bottom_limit}, {upper_limit}]")

    operator_name = file_name_prefix.split("_")[0]
    if not os.path.exists(directory_name + "/" + operator_name):
        os.makedirs(directory_name + "/" + operator_name)

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
    ax.text(0.5 * (left + right), .75 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Creating plot
    ax.boxplot(dict_values, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95],
               widths=4.4)

    # save plot as png
    plt.savefig(directory_name + "/" + operator_name + "/" + file_name_prefix + '_LatencyBoxPlot.png',
                bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create violin plots of the calculated latencies
def create_latency_violin_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, latency_dict,
                               log_scale=False):
    print(f" Creating violin plot: {file_name_prefix}")
    print(f"   Inside the folder: {directory_name}")
    print(f"   Limits: [{bottom_limit}, {upper_limit}]")
    # print(f"   Log-scale: {log_scale}")

    operator_name = file_name_prefix.split("_")[0]
    if not os.path.exists(directory_name + "/" + operator_name):
        os.makedirs(directory_name + "/" + operator_name)

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

    if log_scale:
        ax.set_yscale('log', base=2)

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
    ax.text(0.5 * (left + right), .75 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')
    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Add legend for mean and median
    blue_line = mlines.Line2D([], [], color='blue', marker='', markersize=15, label='mean')
    red_line = mlines.Line2D([], [], color='red', marker='', markersize=15, label='median')
    ax.legend(handles=[blue_line, red_line], loc='upper left')

    # save plot as png
    plt.savefig(directory_name + "/" + operator_name + "/" + file_name_prefix + '_LatencyViolinPlot.png',
                bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created violin plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Reset all the values (lists) of the given dictionary
def reset_values_of_dict_to_zero(dictionary, init_value):
    all_keys = list(dictionary.keys())
    for key in all_keys:
        dictionary[key] = init_value


# Reset the dictionaries for the next plotting
def reset_for_next_plot():
    global all_responses_count_pl
    global missing_query_count_pl

    global all_query_names_pl

    global unanswered_query_count_by_pl
    global responses_with_no_query_count_by_pl
    global latencies_by_pl_and_rcode
    global query_duplicate_by_pl
    global rcodes_by_pl

    reset_values_of_dict_to_zero(all_responses_count_pl, 0)
    reset_values_of_dict_to_zero(missing_query_count_pl, 0)

    all_query_names_pl = {}

    unanswered_query_count_by_pl = {}
    responses_with_no_query_count_by_pl = {}
    latencies_by_pl_and_rcode = {}
    query_duplicate_by_pl = {}
    rcodes_by_pl = {}

    print(f"Clean up for next plotting DONE")


def extract_latencies_from_dict():
    global latencies_by_pl_and_rcode
    keys_of_latency = list(latencies_by_pl_and_rcode.keys())
    rcode_0_keys = []
    rcode_2_keys = []
    rcode_5_keys = []
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

def create_plot_for(file_name, selected_resolvers_to_plot):
    print(f"Plot name: {file_name}")
    print(f"Plotting for: {selected_resolvers_to_plot}")

    global all_resolvers
    to_filter = all_resolvers.copy()

    for selected in selected_resolvers_to_plot:
        if selected in all_resolvers:
            to_filter.remove(selected)

    print(f"Filtering: {to_filter}")

    latency_upper_limit = 10
    latency_directory_name = "LatencyPlots"
    rate_plots_directory_name = "RatePlots"
    unanswered_query_plots_directory_name = "UnansweredQueryPlots"

    # Create directory to store logs into it
    if not os.path.exists(latency_directory_name):
        os.makedirs(latency_directory_name)

    if not os.path.exists(rate_plots_directory_name):
        os.makedirs(rate_plots_directory_name)

    if not os.path.exists(unanswered_query_plots_directory_name):
        os.makedirs(unanswered_query_plots_directory_name)

    # Name of the directory that will be created for the plots
    directory_name = file_name

    # Prefixes of the pcap file names
    client_prefix = "tcpdump_log_client_bond0_"
    # auth_prefix = "tcpdump_log_auth1_bond0_"

    # read all the pcap files
    for current_pl_rate in packetloss_rates:
        print(f"  Current packetloss rate: {current_pl_rate}")

        client_file_name = client_prefix + str(current_pl_rate) + ".pcap"
        # auth_file_name = auth_prefix + str(current_pl_rate) + ".pcap"
        read_pcap(client_file_name, current_pl_rate, to_filter)

    # TODO: missing query plot

    # create rate plot
    create_combined_plots(file_name, rate_plots_directory_name)

    # create latency plots
    create_latency_violin_plot(latency_directory_name, file_name + "_Error", 0, latency_upper_limit,
                               latencies_by_pl_and_rcode, log_scale=False)
    create_latency_box_plot(latency_directory_name, file_name + "_Error", 0, latency_upper_limit,
                            latencies_by_pl_and_rcode,
                            log_scale=False)

    create_unanswered_query_plots(file_name, unanswered_query_plots_directory_name, unanswered_query_count_by_pl)

    print(f"rcodes_by_pl: {rcodes_by_pl}")
    print(f"query_duplicate_by_pl: {query_duplicate_by_pl}")

    # reset the dictionaries for the next plotting/pcaps
    reset_for_next_plot()


# New Operators
# "AdGuard_1", "AdGuard_2", "AdGuard_3", "CleanBrowsing_1", "CleanBrowsing_2", "CleanBrowsing_3", "Cloudflare_1",
# "Cloudflare_2", "Cloudflare_3", "Dyn_1", "Google_1", "Neustar_1", "Neustar_2", "Neustar_3", "Neustar_4",
# "Neustar_5", "OpenDNS_1", "OpenDNS_2", "OpenDNS_3", "Quad9_1", "Quad9_2", "Quad9_3", "Yandex_1", "Yandex_2",
# "Yandex_3", "Level3_1", "Level3_2", "Norton_1", "Norton_2", "Norton_3"

# --------------

# Old PCAP Operators
# "AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "Google1",
# "Google2", "Neustar1", "Neustar2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92", "Yandex1", "Yandex2"

all_resolvers = ["AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Cloudflare1", "Cloudflare2", "Dyn1",
                 "Dyn2", "Google1", "Google2", "Neustar1", "Neustar2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92",
                 "Yandex1", "Yandex2"]

# Create separate plots for all resolver IPs
for resolver in all_resolvers:
    try:
        create_plot_for(resolver, [resolver])
    except Exception as e:
        print(f"Error creating plots for: {resolver}")

create_plot_for("Overall behaviour plot", [])
