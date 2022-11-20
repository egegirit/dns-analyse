import sys
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import json
import re
import os
import time
import statistics

# The packetloss rates that are simulated in the experiment
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100]

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


# Get the n-th element (list) of the given dictionary
def get_nth_value_of_dict(dictionary, n):
    all_keys = list(dictionary.keys())
    return dictionary[all_keys[n]]


# Append an item to the nth element (list) of the given dictionary
def append_item_to_nth_value_of_dict(dictionary, n, item):
    all_keys = list(dictionary.keys())
    dictionary[all_keys[n]].append(item)


# Set the nth element (list) of the given dictionary
def set_nth_value_of_dict(dictionary, n, item):
    all_keys = list(dictionary.keys())
    dictionary[all_keys[n]] = item


# Return all the values (lists) of the given dictionary
def get_values_of_dict(dictionary):
    all_values = list(dictionary.values())
    return all_values


# Reset all the values (lists) of the given dictionary
def reset_values_of_dict_to_empty_list(dictionary):
    all_keys = list(dictionary.keys())
    for key in all_keys:
        dictionary[key] = []


# Reset all the values (lists) of the given dictionary
def reset_values_of_dict_to_zero(dictionary):
    all_keys = list(dictionary.keys())
    for key in all_keys:
        dictionary[key] = 0


# Input: IP Address with dashes (e.g. "8-8-8-8")
# Output: Name of the operator (e.g. "Google1")
def get_operator_name_from_ip(ip_addr_with_dashes):
    for operator, ip_addr in operators.items():
        if ip_addr == ip_addr_with_dashes:
            return operator
    else:
        return "Not found!"


# Show all the contents of the given dictionary
def show_all_data_of_dict(dictionary):
    print(f"Printing the content of dictionary:")

    all_keys = list(dictionary.keys())
    all_values = list(dictionary.values())
    length = len(all_keys)

    for i in range(length):
        print(f"  {all_keys[i]}: {all_values[i]}")


# Get the packetloss string of the json packet
def get_packetloss_rate_of_packet(packet):
    query_name = extract_query_name_from_packet(packet)
    if query_name is not None:
        query_ab_pl_rate = query_name.split("-")[5]
        pl_rate = query_ab_pl_rate.split(".")[0]
        return pl_rate  # <ipnr>-<ipnr>-<ipnr>-<ipnr>-<counter>-pl*.
    else:
        return None


# Return the index of the operator list to access all the packets of an operator
def get_index_of_operator(operator_name):
    # DEBUG
    # print(f"get_index_of_operator({operator_name})")
    op_name_list = list(operators.keys())
    # print(f"operators.keys(): {op_name_list}")

    if operator_name in op_name_list:
        result = op_name_list.index(operator_name)
    else:
        result = -1
    # print(f"Index: {result }")
    return result


# Return the operator name from its dictionary index
def get_operator_name_from_index(index):
    if index < 0 or index > 18:
        print("Invalid Index for operator name")
        sys.exit()
    op_name_list = list(operators.keys())
    # print(f"operators.keys(): {op_name_list}")
    return op_name_list[index]


# Get the relative frame time of packet.
# The time since the first packet is sent.
def get_frame_time_relative_of_packet(packet):
    return float(packet['_source']['layers']["frame"]["frame.time_relative"])


def extract_query_name_from_packet(packet):
    if 'dns' in packet['_source']['layers']:
        # Every dns packet has "Queries" attribute, which contains the query name
        json_string = str(packet['_source']['layers']['dns']['Queries'])
        splitted_json1 = json_string.split("'dns.qry.name': ")
        splitted2 = str(splitted_json1[1])
        query_name = splitted2.split("'")[1]
        # print(f"Extracted query name: {query_name}")
        return query_name
    else:
        return None


# Out of all the packets, return only the responses
def find_the_response_packets(packet_list, file_name):
    responses = []

    for packet in packet_list:
        # Filter responses of client, response must have destination IP of client
        if file_name == "client":
            if not dst_ip_match(packet, client_only_dest_ips):
                # print(f"    SKIPPED  CLIENT PACKET BCS NO DST IP MATCH")
                continue

        response = packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response']
        # print(f"@@ Response: {response}")
        if response != "0":
            responses.append(packet)
    return responses


# Out of all the packets, return only the queries
def find_the_query_packets(packet_list, file_name):
    queries = []

    for packet in packet_list:
        # Filter queries of client, query must have source IP of client
        if file_name == "client":
            if not src_ip_match(packet, client_only_source_ips):
                continue

        if packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "0":
            queries.append(packet)
    return queries


# Check if the given packet has the given RCODE in its Response
# Returns None if packet has no RCODE at all
def has_given_rcode(packet, rcodes):
    # packet == jsonData[i]
    # Note: A packet might be a query, in that case, not all packets will have an RCODE
    if 'dns.flags.response' in packet['_source']['layers']['dns']['dns.flags_tree']:
        if packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "1":
            rcode = packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
            if rcode not in rcodes:
                return True
            else:
                return False
                # print(f"Skipping filtered RCODE: {rcode}")
                # continue
    return None


def find_operator_name_of_json_packet(packet):
    json_string = str(packet['_source']['layers']['dns']['Queries'])
    splitted_json1 = json_string.split("'dns.qry.name': ")
    splitted2 = str(splitted_json1[1])

    query_name = splitted2.split("'")[1]

    splitted_domain = query_name.split("-")
    ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                          splitted_domain[2] + "-" + splitted_domain[3]

    return get_operator_name_from_ip(ip_addr_with_dashes)


def src_ip_match(packet, ip_list):
    if len(ip_list) > 0:
        ip_src_of_packet = packet['_source']['layers']["ip"]["ip.src"]
        if ip_src_of_packet in ip_list:
            return True
    return False


def dst_ip_match(packet, ip_list):
    if len(ip_list) > 0:
        ip_dst_of_packet = packet['_source']['layers']["ip"]["ip.dst"]
        # print(f" DEST IP OF PACKET: {ip_dst_of_packet}")
        if ip_dst_of_packet in ip_list:
            return True
    return False


# Get RCODE of a single JSON packet
def get_rcode_of_packet(packet):
    if 'dns.flags.rcode' in packet['_source']['layers']['dns']['dns.flags_tree']:
        return packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']


# Input: "pl0" Output 0
def get_index_of_packetloss_rate(pl_rate):
    if pl_rate == "pl0":
        return 0
    if pl_rate == "pl10":
        return 1
    if pl_rate == "pl20":
        return 2
    if pl_rate == "pl30":
        return 3
    if pl_rate == "pl40":
        return 4
    if pl_rate == "pl50":
        return 5
    if pl_rate == "pl60":
        return 6
    if pl_rate == "pl70":
        return 7
    if pl_rate == "pl80":
        return 8
    if pl_rate == "pl85":
        return 9
    if pl_rate == "pl90":
        return 10
    if pl_rate == "pl95":
        return 11
    if pl_rate == "pl100":
        return 12
    return None


# File prefixes of JSON files
# file_names = ["auth1", "client"]

client_only_source_ips = ["139.19.117.1"]
client_only_dest_ips = ["139.19.117.1"]
auth_only_dest_ips = ["139.19.117.11"]

# Write text onto plots using this coordinates
x_axis_for_text = 0
y_axis_for_text = 0

# Filtering options
# rcodes_to_get = ["0", "2"]
# ["0", "2"] -> Calculate latencies of ONLY valid answers
# ["0"] -> Calculate latencies of valid answers AND ServFails
# ["2"] -> Calculate latencies of ONLY ServFails

client_bottom_limit = 0
client_upper_limit = 30
auth_bottom_limit = 0
auth_upper_limit = 30
overall_directory_name = "Overall-plot-results"
resolver_directory_name = "Resolver-plot-results"


# ---------------------------

def create_combined_plots(file_name_prefix, operator_name):
    n = 13
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10])

    fig = plt.figure()
    ax = fig.add_subplot(111)

    # Get failure rates
    values = list(failed_packet_pl_rate.values())
    # print(f"Failure ratio: {values}")

    failure_rate_vals = values.copy()
    for i in range(len(failure_rate_vals)):
        try:
            failure_rate_vals[i] = failed_packet_pl_rate[str(packetloss_rates[i])]
        except ZeroDivisionError:
            print("Zero division error!")
            failure_rate_vals[i] = 0
    failure_rects = ax.bar(arr + width, failure_rate_vals, width, bottom=0, color='red')


    ok_vals = list(norerror_pl_rate.values())
    ok_rate_vals = ok_vals.copy()
    for i in range(len(ok_rate_vals)):
        try:
            ok_rate_vals[i] = (ok_rate_vals[i])
        except ZeroDivisionError:
            print("Zero division error!")
            ok_rate_vals[i] = 0

    # Calculate stale record values
    stale_rate_vals = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    index = 0
    for i in packetloss_rates:
        try:
            stale_rate_vals[index] = (stale_count_of_pl[str(i)])
        except ZeroDivisionError:
            print("Zero division error!")
            stale_rate_vals[index] = 0
        finally:
            index += 1

    subtracted = list()
    for item1, item2 in zip(ok_rate_vals, stale_rate_vals):
        subtracted.append(item1 - item2)

    subtracted1 = list()
    for item1, item2 in zip(ok_rate_vals, subtracted):
        subtracted1.append(item1 - item2)

    ok_rects = ax.bar(arr, subtracted, width, bottom=0, color='green')
    stale_rects = ax.bar(arr, stale_rate_vals, width, bottom=subtracted, color='yellow')

    plot_title = f"Stale Record Experiment ({operator_name})"

    plt.xlabel("Packetloss rate")
    plt.ylabel("Results")
    # ax.set_ylabel('Results')
    plt.title(plot_title, x=0.5, y=1.1)
    plt.ylim(bottom=0)

    ax.set_xticks(arr + width/2)
    ax.set_xticklabels((0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100))
    ax.legend((failure_rects[0], ok_rects[0], stale_rects[0]), ('Failure', 'OK', 'Stale'), framealpha=0.5, bbox_to_anchor=(1, 1))

    def autolabel(rects):
        for rect in rects:
            h = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., h + 1, '%d' % int(h),
                    ha='center', va='bottom')

    def autolabel_ok(rects):
        for rect in rects:
            h = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., h - 1.5, '%d' % int(h),
                    ha='center', va='bottom')

    def autolabel_stale(rects, ok_rects):
        h_of_ok = []
        for rect in ok_rects:
            h = rect.get_height()
            h_of_ok.append(int(h))

        i = 0
        for rect in rects:
            h = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., (h + 1.5) + h_of_ok[i], '%d' % int(h),
                    ha='center', va='bottom')
            i += 1

    autolabel(failure_rects)
    autolabel_ok(ok_rects)
    autolabel_stale(stale_rects, ok_rects)
    # autolabel(refused_rects)

    plt.show()

    # save plot as png
    # plt.savefig((file_name_prefix + '_StaleRecordPlot.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create box plot for the calculated latencies
def create_overall_box_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, log_scale=False):
    print(f" Creating box plot: {file_name_prefix}")
    print(f"   Inside the folder: {directory_name}")
    print(f"   Limits: [{bottom_limit}, {upper_limit}]")
    # print(f"   Log-scale: {log_scale}")

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    ax.set_title(f"Response Latency of Stale Records")

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

    if log_scale:
        ax.set_yscale('log', base=2)
    # else: ax.set_yscale('linear')

    # Add the data counts onto the plot as text
    data_count_string = ""
    for i in range(len(get_values_of_dict(latency_of_stales_pl))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(get_values_of_dict(latency_of_stales_pl)[i])) + "\n"

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
    ax.boxplot(get_values_of_dict(latency_of_stales_pl), positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100],
               widths=4.4)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name_prefix + '_boxPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create violin plots of the calculated latencies
def create_overall_latency_violin_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, log_scale=False):
    print(f" Creating violin plot: {file_name_prefix}")
    print(f"   Inside the folder: {directory_name}")
    print(f"   Limits: [{bottom_limit}, {upper_limit}]")
    # print(f"   Log-scale: {log_scale}")

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    ax.set_title(f"Response Latency for Stale Records")

    if log_scale:
        ax.set_yscale('log', base=2)

    # Handle zero values with a -1 dummy value
    data = get_values_of_dict(latency_of_stales_pl)
    for i in range(len(data)):
        if len(data[i]) == 0:
            data[i] = -1

    # Create and save Violinplot
    bp = ax.violinplot(dataset=data, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(get_values_of_dict(latency_of_stales_pl))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(get_values_of_dict(latency_of_stales_pl)[i])) + "\n"

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
    plt.savefig(directory_name + "/" + (file_name_prefix + '_violinPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created violin plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


def create_overall_bar_plot_failure(directory_name, file_name):
    print(f" Creating failure bar plot: {file_name}")
    print(f"   Inside the folder: {directory_name}")

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)

    values = list(failed_packet_pl_rate.values())
    print(f"Failure ratio: {values}")

    ratio_value = values.copy()
    for i in range(len(ratio_value)):
        try:
            ratio_value[i] = (failed_packet_pl_rate[str(packetloss_rates[i])] / (
                    failed_packet_pl_rate[str(packetloss_rates[i])] + norerror_pl_rate[
                str(packetloss_rates[i])])) * 100
        except ZeroDivisionError:
            print("Zero division error!")
            ratio_value[i] = 0

    # adding text inside the plot
    data_count_string = ""
    for i in range(len(packetloss_rates)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            failed_packet_pl_rate[str(packetloss_rates[i])]) + "/" + str(
            failed_packet_pl_rate[str(packetloss_rates[i])] + norerror_pl_rate[str(packetloss_rates[i])]) + "\n"
    text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11,
                    color='r')
    text.set_alpha(0.5)

    print(f"Failure rate ratio_value: {ratio_value}")

    plt.figure(figsize=(10, 5))
    # fig = plt.figure(figsize=(10, 5))

    # creating the bar plot
    plt.bar(packetloss_rates, ratio_value, color='maroon', width=4)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Response Failure Rate")
    plt.title(f"Overall Response Failure Rate")
    plt.ylim(bottom=0, top=100)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name + '_barPlotResponseFailureRate.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created bar plot: {file_name}")
    # Clear plots
    plt.cla()
    plt.close()


def create_overall_bar_plot_stale(directory_name, file_name):
    print(f" Creating stale bar plot: {file_name}")
    print(f"   Inside the folder: {directory_name}")

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)

    ratio_value = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    index = 0
    for i in packetloss_rates:
        try:
            ratio_value[index] = (stale_count_of_pl[str(i)] / (
                    stale_count_of_pl[str(i)] + non_stale_count_of_pl[str(i)])) * 100
        except ZeroDivisionError:
            print("Zero division error!")
            ratio_value[index] = 0
        finally:
            index += 1

    print(f"Stale rates: {ratio_value}")

    plt.figure(figsize=(10, 5))
    # fig = plt.figure(figsize=(10, 5))

    # adding text inside the plot
    data_count_string = ""
    for i in range(len(packetloss_rates)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            stale_count_of_pl[str(packetloss_rates[i])]) + "\n"
    text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11,
                    color='r')
    text.set_alpha(0.5)

    # creating the bar plot
    plt.bar(packetloss_rates, ratio_value, color='orange', width=4)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("Stale Record Rate")
    plt.title(f"Stale Record Rate")
    plt.ylim(bottom=0, top=100)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name + '_barPlotStaleRecordRate.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created bar plot: {file_name}")
    # Clear plots
    plt.cla()
    plt.close()


operator_stale_packets = {
    "AdGuard1": [], "AdGuard2": [],
    "CleanBrowsing1": [], "CleanBrowsing2": [],
    "Cloudflare1": [], "Cloudflare2": [],
    "Dyn1": [], "Dyn2": [],
    "Google1": [], "Google2": [],
    "Neustar1": [], "Neustar2": [],
    "OpenDNS1": [], "OpenDNS2": [],
    "Quad91": [], "Quad92": [],
    "Yandex1": [], "Yandex2": []
}

responses_pl_rate = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

queries_pl_rate = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

norerror_pl_rate = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

# Failed stale phase packets
failed_packet_pl_rate = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

# refused stale phase packets
refused_packet_pl_rate = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

# For example if we are reading the pcap for 10 packetloss rate,
# but there are packets with other packetloss rates in their queries,
# filter and count them
non_matching_pl_rate = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

stale_count_of_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

non_stale_count_of_pl = {
    "0": 0, "10": 0, "20": 0, "30": 0,
    "40": 0, "50": 0, "60": 0, "70": 0,
    "80": 0, "85": 0, "90": 0, "95": 0,
    "100": 0,
}

# Latency of packets in the stale phase with rcode noerror
latency_of_stales_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

auth_json_prefix = "auth_stale_pl"
client_json_prefix = "client_stale_pl"

ttl_wait_time = 108
wait_packetloss_config = 595

# Debug
stale_phase_count = 0
prefetching_phase_count = 0
experiment_count = 0

all_query_names = set()


def read_json_file(filename, pl_rate, resolver_filter):
    global stale_phase_count
    global prefetching_phase_count
    global experiment_count
    print(f"Reading file: {filename}")
    if not os.path.exists("./" + filename):
        print(f"File not found: {filename}")
        exit()
    # Read the measured latencies from json file
    file = open(filename)
    json_data = json.load(file)
    packet_count = len(json_data)
    # print(f"  Number of packets in JSON file: {packet_count}")

    pcap_type = ""
    if "client" in filename:
        pcap_type = "client"
    elif "auth" in filename:
        pcap_type = "auth"
    else:
        pcap_type = "Unknown"

    frame_time_relative_of_previous = 0
    phases = ["Prefetching", "Stale"]
    phase_index = 0

    # Examine all the packets in the JSON file
    for i in range(0, packet_count):
        # print(f"----------------")
        # Check if the packet is a DNS packet
        if 'dns' in json_data[i]['_source']['layers']:

            json_string = str(json_data[i]['_source']['layers']['dns']['Queries'])
            splitted_json1 = json_string.split("'dns.qry.name': ")
            splitted2 = str(splitted_json1[1])
            query_name = splitted2.split("'")[1]
            # print(f"Pcap type: {pcap_type}")
            # print(f"Current query name: {query_name}")

            # Filter query names that doesn't belong to our experiment
            # Example query: stale-1-0-0-1-50-ENM-0.packetloss.syssec-research.mmci.uni-saarland.de
            query_name_lower = query_name.lower()
            if "ns1.packetloss.syssec-research.mmci.uni-saarland.de" in query_name_lower or "_.packetloss.syssec-research.mmci.uni-saarland.de" in query_name_lower \
                    or ".packetloss.syssec-research.mmci.uni-saarland.de" not in query_name_lower \
                    or "_" in query_name_lower:
                # print(f"Skipping invalid domain name: {query_name}")
                continue

            # Get frame number and frame time relative of packet
            if 'frame' in json_data[i]['_source']['layers']:
                if "frame.time_relative" in json_data[i]['_source']['layers']['frame']:
                    frame_time_relative = float(json_data[i]['_source']['layers']['frame']["frame.time_relative"])
                    # print(f"frame_time_relative: {frame_time_relative}")
                if "frame.number" in json_data[i]['_source']['layers']['frame']:
                    frame_number = int(json_data[i]['_source']['layers']['frame']["frame.number"])
                    # print(f"frame_number: {frame_number}")
                if "frame.time_epoch" in json_data[i]['_source']['layers']['frame']:
                    frame_time_epoch = float(json_data[i]['_source']['layers']['frame']["frame.time_epoch"])
                    # print(f"frame_time_epoch: {frame_time_epoch}")
                if "frame.time" in json_data[i]['_source']['layers']['frame']:
                    frame_time = json_data[i]['_source']['layers']['frame']["frame.time"]
                    # print(f"frame_time: {frame_time}")

            # Get source and destination IP of the DNS packet
            if 'ip' in json_data[i]['_source']['layers']:
                if "ip.src" in json_data[i]['_source']['layers']["ip"]:
                    ip_src = json_data[i]['_source']['layers']["ip"]["ip.src"]
                    # print(f"IP SRC: {ip_src}")
                if "ip.dst" in json_data[i]['_source']['layers']["ip"]:
                    ip_dst = json_data[i]['_source']['layers']["ip"]["ip.dst"]
                    # print(f"IP DST: {ip_dst}")

            # Filter specific resolver packets by the query's IP Address

            try:
                last_label = query_name.split(".")[0]
                splitted_domain = last_label.split("-")
                ip_addr_with_dashes = splitted_domain[1] + "-" + splitted_domain[2] + "-" + \
                                      splitted_domain[3] + "-" + splitted_domain[4]
            except Exception as e:
                print(f"Error")
                print(f"{e}")
                print(f"Current query name: {query_name}")
                print(f"frame_number: {frame_number}")

            operator = get_operator_name_from_ip(ip_addr_with_dashes)
            # print(f"Operator: {operator}")

            # Filter the given resolvers packets
            skip_packet = False
            if filtered_resolvers:
                for resolver in filtered_resolvers:
                    if resolver == operator:
                        skip_packet = True
                        break
            if skip_packet:
                continue

            # print(f"IP Address in query: {ip_addr_with_dashes}")
            pl_rate_of_query_name = splitted_domain[5]

            if str(pl_rate) != pl_rate_of_query_name:
                # print(f"  Different packetloss query detected!")
                # print(f"  Current PL: {str(pl_rate)}")
                # print(f"  Packet  PL: {pl_rate_of_query_name}")
                # print(f"  Skipping packet...")
                non_matching_pl_rate[str(pl_rate)] += 1
                # time.sleep(1)
                continue

            # print(f"Packetloss rate: {pl_rate_of_query_name}")
            random_token_of_query = splitted_domain[6]
            # print(f"random_token_of_query: {random_token_of_query}")
            counter_of_random_token = splitted_domain[7]
            # print(f"counter_of_random_token: {counter_of_random_token}")

            if "dns.id" in json_data[i]['_source']['layers']['dns']:
                dns_id = json_data[i]['_source']['layers']['dns']["dns.id"]
                # print(f"DNS ID: {dns_id}")

            if "dns.flags_tree" in json_data[i]['_source']['layers']['dns']:
                if "dns.flags.response" in json_data[i]['_source']['layers']['dns']["dns.flags_tree"]:
                    is_response = json_data[i]['_source']['layers']['dns']["dns.flags_tree"]["dns.flags.response"]
                    # print(f"Is response: {is_response}")
                    if is_response == "1":
                        rcode = json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
                        # print(f"RCODE: {rcode}")

                        if 'dns.time' in json_data[i]['_source']['layers']['dns']:
                            dns_time = float(json_data[i]['_source']['layers']['dns']['dns.time'])
                            # print(f"dns_time: {dns_time}")
                        if "dns.count.answers" in json_data[i]['_source']['layers']['dns']:
                            answer_count = json_data[i]['_source']['layers']['dns']["dns.count.answers"]
                            if int(answer_count) >= 1:
                                # print(f"Answer count: {answer_count}")
                                answer_string = str(json_data[i]['_source']['layers']['dns']["Answers"])
                                # print(f"answer_string: {answer_string}")
                                splitted1 = answer_string.split("'dns.a': ")
                                # print(f"splitted1: {splitted1}")
                                splitted2 = str(splitted1[1])
                                a_record = splitted2.split("'")[1]
                                # print(f"A record: {a_record}")

                                splitted3 = answer_string.split("'dns.resp.ttl': ")
                                splitted4 = str(splitted3[1])
                                ttl_of_answer = int(splitted4.split("'")[1])
                                # print(f"TTL: {ttl_of_answer}")

            is_a_new_query = query_name in all_query_names
            if is_a_new_query:
                pass
                # print(f"  Query is NEW ********")
            else:
                pass
                # print(f"  Query was sent before")
            # Add only query names of queries, not responses
            if is_response == "0":
                all_query_names.add(query_name)

            # Calculate the time difference to the previous packet and try to calculate, which phase the packet belongs to
            time_diff_to_previous_packet = frame_time_relative - frame_time_relative_of_previous
            # print(f"                               Time diff to previous packet: {time_diff_to_previous_packet}")
            time_diff_abs = abs(frame_time_relative - frame_time_relative_of_previous)
            if time_diff_abs < ttl_wait_time:
                pass
                # print(f"Same phase, add packet")
                # print(f"Adding packet to phase: {phases[phase_index]}")
            elif ttl_wait_time <= time_diff_abs <= wait_packetloss_config:
                # print(f"  @@@@@ Phase switching detected, first packet of the phase")
                phase_index = (phase_index + 1) % 2
                # print(f"  Adding packet to phase: {phases[phase_index]}")
                # Debug
                # print(f"Reading file: {filename}")
                # print(f"Current query name: {query_name}")
                # print(f"frame_number: {frame_number}")
                # print(f"Time diff to previous packet: {time_diff_abs}")
                pass
                if phases[phase_index] == "Stale":
                    stale_phase_count += 1
                elif phases[phase_index] == "Prefetching":
                    prefetching_phase_count += 1

            # Packet capture is terminated after 600 sec waiting phase
            # elif wait_packetloss_config < time_diff_abs < 700:
            #    # print(f"  @@@@@ First packet after cooldown phase")
            #    phase_index = 0
            #    # print(f"  Adding packet to phase: {phases[phase_index]}")

            elif time_diff_abs >= 700:  # 7200 = 12(pl araları) * 600(pl arası cooldown)
                # print(f"  @@@@@ NEW EXPERIMENT BEGIN?")
                phase_index = 0
                experiment_count += 1
                # Debug
                # print(f"Reading file: {filename}")
                # print(f"Current query name: {query_name}")
                # print(f"frame_number: {frame_number}")
                # print(f"Time diff to previous packet: {time_diff_abs}")

            frame_time_relative_of_previous = frame_time_relative

            global stale_count_of_pl
            global non_stale_count_of_pl
            global latency_of_stales_pl
            # Count if query was stale
            if is_response == "1" and phases[phase_index] == "Stale" and rcode == "0":
                latency_of_stales_pl[pl_rate_of_query_name].append(dns_time)
                expected_stale_a_record = ("139." + str(pl_rate) + "." + str(pl_rate) + "." + str(pl_rate))
                expected_noerror_a_record = (
                        "139." + str(int(pl_rate) + 1) + "." + str(int(pl_rate) + 1) + "." + str(int(pl_rate) + 1))

                # print(f"expected_stale_a_record: {expected_stale_a_record}")
                # print(f"expected_noerror_a_record: {expected_noerror_a_record}")

                # print(f"    Added latency")
                if expected_stale_a_record == a_record:
                    # print("1")
                    stale_count_of_pl[pl_rate_of_query_name] += 1
                    # print(f"    Marked as stale")
                elif expected_noerror_a_record == a_record:
                    # print("0")
                    non_stale_count_of_pl[pl_rate_of_query_name] += 1
                    # print(f"    Marked as Non-stale")

            # Calculate failure rate/refused/noerror rate of stale phase packets
            if is_response == "1" and phases[phase_index] == "Stale":
                if str(rcode) == "2":
                    failed_packet_pl_rate[str(pl_rate)] += 1
                elif str(rcode) == "0":
                    norerror_pl_rate[str(pl_rate)] += 1
                elif str(rcode) == "5":
                    refused_packet_pl_rate[str(pl_rate)] += 1

            # Get all response and queries count
            if phases[phase_index] == "Stale":
                if is_response == "1":
                    responses_pl_rate[str(pl_rate)] += 1
                elif is_response == "0":
                    queries_pl_rate[str(pl_rate)] += 1

            # Debug yandex latencies
            # if is_response == "1":
            #    if dns_time >= 40:
            #        print(f"dns_time: {dns_time}")
            #        print(f"qry name: {query_name}")
            #        print(f"frame no: {frame_number}")
            #        print(f"JSON PL rate: {pl_rate}")
            #        # time.sleep(20)

            # Store packet to operator list
            if is_response == "1" and phases[phase_index] == "Stale":
                operator_stale_packets[operator].append(json_data[i])


# "AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "Google1", "Google2", "Neustar1", "Neustar2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92", "Yandex1", "Yandex2"
filtered_resolvers = ["CleanBrowsing1", "CleanBrowsing2", "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "Google1", "Google2", "Neustar1", "Neustar2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92", "Yandex1", "Yandex2"]

# Stale record supporting resolvers
# "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92"

# No record support
# "AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Google1", "Google2", "Neustar1", "Neustar2", "Yandex1", "Yandex2"

for current_pl_rate in packetloss_rates:
    print(f"Current packetloss rate: {current_pl_rate}")

    client_json_file_name = client_json_prefix + str(current_pl_rate) + ".json"
    # auth_json_file_name = auth_json_prefix + current_pl_rate + ".json"

    read_json_file(client_json_file_name, current_pl_rate, filtered_resolvers)

name = "AdGuard"

directory_name = name

# Create directory to store logs into it
if not os.path.exists(directory_name):
    os.makedirs(directory_name)

file_name = name
bottom_limit = 0
upper_limit = 40
log_scale_y_axis = False

# create_overall_box_plot(directory_name, file_name, bottom_limit, upper_limit, log_scale_y_axis)
# create_overall_latency_violin_plot(directory_name, file_name, bottom_limit, upper_limit, log_scale_y_axis)
# create_overall_bar_plot_failure(directory_name, file_name)
# create_overall_bar_plot_stale(directory_name, file_name)

create_combined_plots(name, name)

# print(f"---------------")
#
# print(f"Non matching (filtered) pl rates:{non_matching_pl_rate}")
#
# print(f"Stale rates:")
# for i in packetloss_rates:
#     try:
#         print(
#             f"PL {i}: {stale_count_of_pl[str(i)]}/{stale_count_of_pl[str(i)] + non_stale_count_of_pl[str(i)]} = {stale_count_of_pl[str(i)] / (stale_count_of_pl[str(i)] + non_stale_count_of_pl[str(i)])}")
#     except ZeroDivisionError:
#         print("Zero division error!")
#
# print(f"\nResponse packet counts:{responses_pl_rate}")
# print(f"Query packet counts:{queries_pl_rate}")
#
# print(f"Failed stale packet counts:{failed_packet_pl_rate}")
# print(f"No error packet counts:{norerror_pl_rate}\n")
#
# print(f"Failure rates:")
# for i in packetloss_rates:
#     try:
#         print(
#             f"PL {i}: {failed_packet_pl_rate[str(i)]}/{failed_packet_pl_rate[str(i)] + norerror_pl_rate[str(i)]} = {failed_packet_pl_rate[str(i)] / (failed_packet_pl_rate[str(i)] + norerror_pl_rate[str(i)])}")
#     except ZeroDivisionError:
#         print("Zero division error!")
#
# print(f"\nLatencies of stale records:")
# for i in packetloss_rates:
#     try:
#         print(
#             f"PL {i}: mean: {statistics.mean(latency_of_stales_pl[str(i)])},  median: {statistics.median(latency_of_stales_pl[str(i)])}")
#     except Exception:
#         print("no data error")
#
# print(f"----------------")
# print(f"stale_phase_count: {stale_phase_count}")
# print(f"prefetching_phase_count: {prefetching_phase_count}")
# print(f"experiment_count: {experiment_count}")
