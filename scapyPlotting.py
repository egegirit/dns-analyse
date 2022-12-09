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

# All operators with their IP Addresses with dashes
operators = {
    "AdGuard_1": "94-140-14-14",
    "AdGuard_2": "94-140-14-15",
    "AdGuard_3": "94-140-14-140",

    "CleanBrowsing_1": "185-228-168-168",
    "CleanBrowsing_2": "185-228-168-9",
    "CleanBrowsing_3": "185-228-168-10",

    "Cloudflare_1": "1-1-1-1",
    "Cloudflare_2": "1-1-1-2",
    "Cloudflare_3": "1-1-1-3",

    "Dyn_1": "216-146-35-35",

    "Google_1": "8-8-8-8",

    "Neustar_1": "64-6-64-6",
    "Neustar_2": "156-154-70-2",
    "Neustar_3": "156-154-70-3",
    "Neustar_4": "156-154-70-4",
    "Neustar_5": "156-154-70-5",

    "OpenDNS_1": "208-67-222-222",
    "OpenDNS_2": "208-67-222-2",
    "OpenDNS_3": "208-67-222-123",

    "Quad9_1": "9-9-9-9",
    "Quad9_2": "9-9-9-11",
    "Quad9_3": "9-9-9-10",

    "Yandex_1": "77-88-8-1",
    "Yandex_2": "77-88-8-2",
    "Yandex_3": "77-88-8-3",

    "Level3_1": "209-244-0-3",
    "Level3_2": "209-244-0-4",

    "Norton_1": "199-85-126-10",
    "Norton_2": "199-85-126-20",
    "Norton_3": "199-85-126-30",

}

all_responses_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

all_queries_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

non_stale_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

stale_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

servfail_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

refused_count_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

# Latency of non stale ok packets in the stale phase
latency_of_ok_nonstale_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

# Latency of stale record packets
latency_of_stales_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

# Latency of error packets in the stale phase
latency_of_servfails_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

# Latency of error packets in the stale phase
latency_of_refused_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

ttl_wait_time = 115
wait_packetloss_config = 595

# A list that stores packet_dict's
all_packets = []


# Input: IP Address with dashes (e.g. "8-8-8-8")
# Output: Name of the operator (e.g. "Google1")
def get_operator_name_from_ip(ip_addr_with_dashes):
    # print(f"  get_operator_name_from_ip() got parameter: {ip_addr_with_dashes}")
    for operator, ip_addr in operators.items():
        if ip_addr == ip_addr_with_dashes:
            return operator
    else:
        return "Not found!"


def get_dict_from_op_name(operator_name):
    global cloudflare_packets
    global dyn_packets
    global opendns_packets
    global quad9_packets

    if "cloudflare" in operator_name.lower():
        return cloudflare_packets
    elif "dyn" in operator_name.lower():
        return dyn_packets
    elif "opendns" in operator_name.lower():
        return opendns_packets
    elif "quad9" in operator_name.lower():
        return quad9_packets


# Return all the values (lists) of the given dictionary
def get_values_of_dict(dictionary):
    all_values = list(dictionary.values())
    return all_values


def read_pcap(pcap_file_name, current_pl_rate, filtered_resolvers):
    print(f"Reading file: {pcap_file_name}")

    # Get a list of all packets (Very slow if the PCAP file is large)
    # all_packets = rdpcap(pcap_file_name)
    # print(f"Count of packets in pcap: {len(all_packets)}")

    # Initialization is 0 because for the first packet (packet_time - 0) is the correct packet time of the first packet
    previous_packet_time = 0

    index = 1
    for packet in PcapReader(pcap_file_name):
        # Examine only DNS packets

        if packet.haslayer(DNS):
            # print(f"=====================================")
            # print(f"Showing packet ({index})")
            # packet.show()
            # print(f"-------------")
            # print(f" TIME @@@@@@@@@@@ {packet.time}")
            try:

                dst = packet[IP].dst
                src = packet[IP].src

                query = packet[DNSQR].qname.decode("utf-8")
                # TODO: Filter query names with a regex
                if "stale-" not in query or "packetloss.syssec-research.mmci.uni-saarland.de" not in query:
                    # print(f"Invalid query name for: {query}")
                    continue

                # Filter by IP Address
                # Client IP is 139.19.117.1
                if "client" in pcap_file_name:
                    if src != "139.19.117.1" and dst != "139.19.117.1":
                        # print(f"IP of client packet invalid: {query}")
                        continue
                # Server IP is 139.19.117.11
                elif "auth" in pcap_file_name:
                    if src != "139.19.117.11" and dst != "139.19.117.11":
                        # print(f"IP of auth packet invalid: {query}")
                        continue

                # Examine query name, get ip address and pl rate and operator name
                splitted_query = query.split("-")
                ip_with_dashes = splitted_query[1] + "-" + splitted_query[2] + "-" + \
                                 splitted_query[3] + "-" + splitted_query[4]
                operator_name = get_operator_name_from_ip(ip_with_dashes)
                pl_rate_of_packet = splitted_query[5]

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
                    # print(f"Skipping")
                    continue

                # Time of the packet
                packet_time = packet.time
                # Time difference of the current and previous packet
                time_diff_to_previous = packet_time - previous_packet_time

                rec_type = packet[DNSQR].qtype  # Type 1 is A record
                port = packet.sport
                proto = packet[IP].proto
                is_query = packet[DNS].qr  # QR specifies whether this message is a query (0), or a response (1)
                rcode = packet[DNS].rcode
                dns_id = packet[DNS].id
                answer_count = packet[DNS].ancount
                #
                # print(f"Query name: {query}")
                # print(f"  Query type: {rec_type}")
                # print(f"  Is response (0: Query, 1: Response): {is_query}")
                # print(f"  DNS ID: {dns_id}")
                # print(f"  RCODE: {rcode}")
                # print(f"  Answer Count: {answer_count}")
                # print(f"  SRC IP: {src}")
                # print(f"  DST IP: {dst}")
                # print(f"  Port: {port}")
                # print(f"  Protocol: {proto}")
                # print(f"  Packetloss rate of packet: {pl_rate_of_packet}")
                # print(f"  Operator Name: {operator_name}")
                # print(f"  Arrival time of packet: {packet_time}")
                # print(f"  Time difference to previous packet: {time_diff_to_previous}")

                # TODO: Latency calculation via hash map/dictionary

                if answer_count > 0:
                    rrname = packet[DNS].an.rrname.decode("utf-8")
                    ans_type = packet[DNS].an.type
                    ttl = packet[DNS].an.ttl
                    a_record = packet[DNS].an.rdata
                    # print(f"    RRNAME: {rrname}")
                    # print(f"    Resp Type: {ans_type}")
                    # print(f"    TTL: {ttl}")
                    # print(f"    A Record: {a_record}")

                previous_packet_time = packet_time

                # If DNS packet is a query
                if is_query == 0:
                    all_queries_count_pl[str(current_pl_rate)] += 1
                    # DNS packet is response
                elif is_query == 1:
                    all_responses_count_pl[str(current_pl_rate)] += 1

                # TODO: Check if stale or not
                expected_stale_a_record = (
                            "139." + str(current_pl_rate) + "." + str(current_pl_rate) + "." + str(current_pl_rate))
                expected_noerror_a_record = (
                            "139." + str(int(current_pl_rate) + 1) + "." + str(int(current_pl_rate) + 1) + "." + str(
                            int(current_pl_rate) + 1))
                # The record was stale
                if expected_stale_a_record == a_record:
                    stale_count_pl[pl_rate_of_packet] += 1
                    latency_of_stales_pl[pl_rate_of_packet].append(dns_time)
                    # print(f"    Marked as stale")
                # The record was non-stale
                elif expected_noerror_a_record == a_record:
                    latency_of_ok_nonstale_pl[pl_rate_of_packet].append(dns_time)
                    non_stale_count_pl[pl_rate_of_packet] += 1
                    # print(f"    Marked as Non-stale")

                # Add the current packet to list
                current_packet_attributes = [query, src, dst, dns_id, rec_type, is_query, packet_time]  # , port]
                should_be_added = True
                difference_detected_of_previous = True
                found_duplicate = None
                for pkt in all_packets:
                    # print(f"------------------")
                    difference_detected = False
                    is_query_difference = False
                    response_to_query_found = False
                    # Query comparison
                    if pkt[0] != current_packet_attributes[0]:
                        difference_detected = True
                    # else:
                    #     print(f"Same query name found")
                    # TODO: What if you send to 8.8.8.8 but it comes from another IP, then query source != response dest
                    # # Source IP comparison
                    # if pkt[1] != current_packet_attributes[1]:
                    #     # print(f"Same query name found: {pkt[1]}")
                    #     difference_detected = True
                    # else:
                    #     print(f"Same source")
                    # # Destination IP comparison
                    # if pkt[2] != current_packet_attributes[2]:
                    #     # print(f"Same query name found: {pkt[2]}")
                    #     difference_detected = True
                    # else:
                    #     print(f"Same DST")
                    # DNS ID comparison
                    if pkt[3] != current_packet_attributes[3]:
                        # print(f"Same query name found: {pkt[3]}")
                        difference_detected = True
                    # else:
                    #     print(f"Same DNS ID")
                    # Record Type comparison
                    if pkt[4] != current_packet_attributes[4]:
                        # print(f"Same query name found: {pkt[4]}")
                        difference_detected = True
                    # else:
                    #     print(f"Same Record Type")
                    # Query or response comparison
                    if pkt[5] != current_packet_attributes[5]:
                        # TODO: if both are query, ignore for latency list because duplicate query,
                        # if both are response, ignore for latency list because duplicate response
                        # if one is query and one is response, add to list,
                        # BUT ignore the ones that comes afterwards!!
                        is_query_difference = True
                        if pkt[5] == 0 and current_packet_attributes[5] == 1:
                            # Because we will delete the query, we dont need to add the response to the list
                            response_to_query_found = True

                            # Delete from list (for wild pcap scans) because we only send 1 to query
                            all_packets.remove(pkt)
                    # else:
                    #     print(f"Same is_response")
                    # Port comparison
                    # if pkt[6] != current_packet_attributes[6]:
                    #     # print(f"Same query name found: {pkt[6]}")
                    #     difference_detected = True

                    query_response_match = not (
                                difference_detected and difference_detected_of_previous) and response_to_query_found
                    if query_response_match:
                        latency = current_packet_attributes[6] - pkt[6]
                        print(f"  Response to query found:")
                        print(f"      {current_packet_attributes}")
                        print(f"        AND")
                        print(f"      {pkt}")
                        print(f"      Latency: {latency}")
                        print(f"-----------------------")

                    # If the packet should be added to the list
                    should_be_added = (difference_detected and difference_detected_of_previous)
                    # At least 1 duplicate packet is found, don't add
                    if not should_be_added:
                        found_duplicate = pkt
                        break
                    difference_detected_of_previous = difference_detected

                # Add packet if the packet is different from the others in the list
                if should_be_added:
                    all_packets.append(current_packet_attributes)
                # Don't add packet if it's a duplicate
                else:
                    print(f"  Duplicate for (Query name, SRC, DST, DNS ID, Record type, Is response):")
                    print(f"      {current_packet_attributes}")
                    print(f"        AND")
                    print(f"      {found_duplicate}")

            except Exception as e:
                print(f"Error reading packet: {str(e)}")

        index += 1


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
    non_stale_rate_vals = [30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 0]
    non_stale_counts = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 0]

    # Stale datas
    stale_rate_vals = [10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 0]
    stale_rate_counts = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0]

    # Failure datas
    failure_rate_vals = [50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 0]
    failure_rate_counts = [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 0]

    # Refused datas
    refused_rates = [10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 0]
    refused_counts = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0]

    # Calculate bottom of refused bars by adding non stale + stale ratios
    non_stale_plus_stale = list()
    for item1, item2 in zip(non_stale_rate_vals, stale_rate_vals):
        non_stale_plus_stale.append(item1 + item2)

    # Calculate bottom of failed bars by adding non stale + stale + refused ratios
    refused_plus_non_stale_plus_stale = list()
    for item1, item2 in zip(non_stale_plus_stale, refused_rates):
        refused_plus_non_stale_plus_stale.append(item1 + item2)

    non_stale_rects = ax.bar(bar_pos, non_stale_rate_vals, width, bottom=0, color='green')
    stale_rects = ax.bar(bar_pos, stale_rate_vals, width, bottom=non_stale_rate_vals, color='yellow')
    refused_rects = ax.bar(bar_pos, refused_rates, width, bottom=non_stale_plus_stale, color='orange')
    failure_rects = ax.bar(bar_pos, failure_rate_vals, width, bottom=refused_plus_non_stale_plus_stale, color='red')

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
    ax.legend((failure_rects[0], refused_rects[0], stale_rects[0], non_stale_rects[0]),
              ('Failure', 'Refused', 'Stale', 'OK'), framealpha=0.5,
              bbox_to_anchor=(0.1, 1.25))

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_non_stale(rects):
        index = 0
        for rect in rects:
            if non_stale_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"OK#{non_stale_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    # Text of stale bars
    def autolabel_stale(non_stale_rects, stale_rects):
        hight_of_non_stale = []
        index = 0
        for rect in non_stale_rects:
            h = rect.get_height()
            hight_of_non_stale.append(int(h))
            index += 1

        i = 0
        for rect in stale_rects:
            if stale_rate_counts[i] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_stale[i],
                        f"S#{stale_rate_counts[i]}",
                        ha='center', va='bottom')
            i += 1

    # Text of refused bars
    def autolabel_refused(non_stale_rects, stale_rects, refused_rects):
        hight_of_non_stale_plus_stale = []
        index = 0
        for rect in non_stale_rects:
            h = rect.get_height()
            hight_of_non_stale_plus_stale.append(int(h))
            index += 1

        index = 0
        for rect in stale_rects:
            h = rect.get_height()
            hight_of_non_stale_plus_stale[index] += int(h)
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
    def autolabel_fail(non_stale_rects, stale_rects, refused_rects, fail_rects):
        hight_of_non_failed = []
        index = 0
        for rect in non_stale_rects:
            h = rect.get_height()
            hight_of_non_failed.append(int(h))
            index += 1

        index = 0
        for rect in stale_rects:
            h = rect.get_height()
            hight_of_non_failed[index] += int(h)
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

    autolabel_non_stale(non_stale_rects)
    autolabel_stale(non_stale_rects, stale_rects)
    autolabel_refused(non_stale_rects, stale_rects, refused_rects)
    autolabel_fail(non_stale_rects, stale_rects, refused_rects, failure_rects)

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
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

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
    ax.boxplot(dict_values, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100],
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
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    ax.set_title(f"Response Latency of " + file_name_prefix)

    if log_scale:
        ax.set_yscale('log', base=2)

    # Handle zero values with a -1 dummy value
    data = get_values_of_dict(latency_dict)  # get_values_of_dict(latency_of_stales_pl)
    for i in range(len(data)):
        if len(data[i]) == 0:
            data[i] = [0]

    # Create and save Violinplot
    bp = ax.violinplot(dataset=data, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

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


# "AdGuard_1", "AdGuard_2", "AdGuard_3", "CleanBrowsing_1", "CleanBrowsing_2", "CleanBrowsing_3", "Cloudflare_1",
# "Cloudflare_2", "Cloudflare_3", "Dyn_1", "Google_1", "Neustar_1", "Neustar_2", "Neustar_3", "Neustar_4",
# "Neustar_5", "OpenDNS_1", "OpenDNS_2", "OpenDNS_3", "Quad9_1", "Quad9_2", "Quad9_3", "Yandex_1", "Yandex_2",
# "Yandex_3", "Level3_1", "Level3_2", "Norton_1", "Norton_2", "Norton_3"
filtered_resolvers = []

# Name of the plot
name = "Test"

# Name of the directory that will be created for the plots
directory_name = name

# Create directory to store logs into it
if not os.path.exists(directory_name):
    os.makedirs(directory_name)

# Prefixes of the pcap file names
client_prefix = "client_stale_pl"
auth_prefix = "auth_stale_pl"

# read the pcap file
for current_pl_rate in packetloss_rates:
    print(f"Current packetloss rate: {current_pl_rate}")

    client_file_name = client_prefix + str(current_pl_rate) + ".pcap"
    # auth_file_name = auth_json_prefix + current_pl_rate + ".json"

    read_pcap(client_file_name, current_pl_rate, filtered_resolvers)

# create rate plot
# create_combined_plots(name, name)
