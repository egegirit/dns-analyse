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

all_query_names_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

all_queries_count_pl = {
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
                dst = packet[IP].dst
                src = packet[IP].src
                # Filter packet if source or destination IP is not valid
                if not is_src_or_dst_ip_valid(pcap_file_name, src, dst):
                    continue

                # Query name of packet
                query = packet[DNSQR].qname.decode("utf-8")
                if not is_query_name_valid(query):
                    continue

                # Query name: "8-8-8-8-0-pl0.packetloss.syssec-research.mmci.uni-saarland.de
                # Extract ip address and pl rate from query name, find the corresponding operator name
                splitted_query = query.split("-")
                ip_with_dashes = splitted_query[0] + "-" + splitted_query[1] + "-" + \
                                 splitted_query[2] + "-" + splitted_query[3]
                operator_name = get_operator_name_from_ip(ip_with_dashes)
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

                is_response = int(packet[DNS].qr)  # Packet is a query (0), or a response (1)

                # TODO: New script for missing query count
                # If its a client pcap, store the query names to calculate missing query count
                if "client" in pcap_file_name:
                    all_query_names_pl[str(current_pl_rate)].append(query)
                # If it's an auth pcap, delete query name from list if the query name of client is found in auth pcap
                elif "auth" in pcap_file_name:
                    if query in all_query_names_pl[str(current_pl_rate)]:
                        all_query_names_pl[str(current_pl_rate)].remove(query)

                # print(f"Query name: {query}")
                # print(f"  Query type: {rec_type}")
                # print(f"  Is response (0: Query, 1: Response): {is_response}")
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

            except Exception as e:
                print(f"  Error reading packet: {str(e)}")
                packet.show()

        # After deleting all the found query names, the remaining query count for the current packetloss rate
        # is the missing query count
        if "auth" in pcap_file_name:
            missing_query_count_pl[str(current_pl_rate)] = len(all_query_names_pl[str(current_pl_rate)])
        index += 1


# Create stacked bar chart (rates of: non_stale, stale, refused and servfail packets)
def create_missing_query_plots(file_name_prefix, directory_name, integer_dict_with_pl):
    n = 13  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10])  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    dict_values = get_values_of_dict(integer_dict_with_pl)
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


# Reset all the values (lists) of the given dictionary
def reset_values_of_dict_to_zero(dictionary, init_value):
    all_keys = list(dictionary.keys())
    for key in all_keys:
        dictionary[key] = init_value


def reset_for_next_plot():
    global all_queries_count_pl
    global missing_query_count_pl

    global all_query_names_pl

    reset_values_of_dict_to_zero(all_queries_count_pl, 0)
    reset_values_of_dict_to_zero(missing_query_count_pl, 0)

    reset_values_of_dict_to_zero(all_query_names_pl, [])

    print(f"Clean up for next plotting DONE")


def create_plot_for(file_name, selected_resolvers_to_plot):
    print(f"Plot name: {file_name}")
    print(f"Plotting for: {selected_resolvers_to_plot}")

    global all_resolvers
    to_filter = all_resolvers.copy()

    for selected in selected_resolvers_to_plot:
        if selected in all_resolvers:
            to_filter.remove(selected)

    print(f"Filtering: {to_filter}")

    missing_query_plots_directory_name = "MissingQueryPlots"

    if not os.path.exists(missing_query_plots_directory_name):
        os.makedirs(missing_query_plots_directory_name)

    # Prefixes of the pcap file names
    client_prefix = "tcpdump_log_client_bond0_"
    auth_prefix = "tcpdump_log_auth_bond0_"

    # read all the pcap files
    for current_pl_rate in packetloss_rates:
        print(f"  Current packetloss rate: {current_pl_rate}")

        client_file_name = client_prefix + str(current_pl_rate) + ".pcap"
        auth_file_name = auth_prefix + current_pl_rate + ".json"

        read_pcap(client_file_name, current_pl_rate, to_filter)
        read_pcap(auth_file_name, current_pl_rate, to_filter)

    # Create plot
    create_missing_query_plots(file_name, missing_query_plots_directory_name, missing_query_count_pl)

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
