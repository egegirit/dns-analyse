import sys
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import json
import os

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


client_only_source_ips = ["139.19.117.1"]
client_only_dest_ips = ["139.19.117.1"]
auth_only_dest_ips = ["139.19.117.11"]


def create_combined_plots(file_name_prefix, operator_name, directory_name):
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
    failure_rate_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    for i in range(len(failure_rate_vals)):
        try:
            failure_rate_vals[i] = (failed_packet_pl_rate[str(packetloss_rates[i])] / (
                    failed_packet_pl_rate[str(packetloss_rates[i])] + norerror_pl_rate[
                str(packetloss_rates[i])])) * 100
            failure_rate_counts[i] = failed_packet_pl_rate[str(packetloss_rates[i])]
        except ZeroDivisionError:
            print("Zero division error!")
            failure_rate_vals[i] = 0
            failure_rate_counts[i] = 0

    ok_vals = list(norerror_pl_rate.values())
    ok_rate_vals = ok_vals.copy()
    ok_rate_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    index = 0
    for i in range(len(ok_rate_vals)):
        try:
            ok_rate_vals[i] = (ok_rate_vals[i] /
                               (failed_packet_pl_rate[str(packetloss_rates[i])] + norerror_pl_rate[
                                   str(packetloss_rates[i])])) * 100
            ok_rate_counts[index] = ok_rate_vals[i]
        except ZeroDivisionError:
            print("Zero division error!")
            ok_rate_vals[i] = 0
            ok_rate_counts[index] = 0
        index += 1

    # Calculate stale record values
    stale_rate_vals = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    stale_rate_counts = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    index = 0
    for i in packetloss_rates:
        try:
            stale_rate_vals[index] = (stale_count_of_pl[str(i)] / (
                    failed_packet_pl_rate[str(packetloss_rates[index])] + norerror_pl_rate[
                str(packetloss_rates[index])])) * 100
            stale_rate_counts[index] = (stale_count_of_pl[str(i)])
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

    stale_plus_subtracted = list()
    for item1, item2 in zip(stale_rate_vals, subtracted):
        stale_plus_subtracted.append(item1 + item2)

    ok_rects = ax.bar(arr + width/2, subtracted, width, bottom=0, color='green')
    stale_rects = ax.bar(arr + width/2, stale_rate_vals, width, bottom=subtracted, color='yellow')
    failure_rects = ax.bar(arr + width/2, failure_rate_vals, width, bottom=stale_plus_subtracted, color='red')

    plot_title = f"Stale Record Experiment ({operator_name})"

    plt.xlabel("Packetloss rate")
    plt.ylabel("Rate of results")
    # ax.set_ylabel('Results')
    plt.title(plot_title, x=0.5, y=1.1)
    plt.ylim(bottom=0)

    ax.set_xticks(arr + width/2)
    ax.set_xticklabels((0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100))
    ax.legend((failure_rects[0], ok_rects[0], stale_rects[0]), ('Failure', 'OK', 'Stale'), framealpha=0.5, bbox_to_anchor=(1, 1))

    def autolabel_fail(fail_rects, ok_rects, stale_rects):

        h_of_ok_plus_stale = []
        index = 0
        for rect in ok_rects:
            h = rect.get_height()
            h_of_ok_plus_stale.append(int(h))
            index += 1

        index = 0
        for rect in stale_rects:
            h = rect.get_height()
            h_of_ok_plus_stale[index] += int(h)
            index += 1

        index = 0
        for rect in fail_rects:
            if failure_rate_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + h_of_ok_plus_stale[index], f"F#{failure_rate_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    def autolabel_ok(rects):
        index = 0
        for rect in rects:
            if norerror_pl_rate[str(packetloss_rates[index])] - stale_rate_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2, f"OK#{norerror_pl_rate[str(packetloss_rates[index])] - stale_rate_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    def autolabel_stale(rects, ok_rects):
        h_of_ok = []
        index = 0
        for rect in ok_rects:
            h = rect.get_height()
            h_of_ok.append(int(h))
            index += 1

        i = 0
        for rect in rects:
            if stale_rate_counts[i] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + h_of_ok[i], f"S#{stale_rate_counts[i]}",
                        ha='center', va='bottom')
            i += 1

    autolabel_fail(failure_rects, ok_rects, stale_rects)
    autolabel_ok(ok_rects)
    autolabel_stale(stale_rects, ok_rects)

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
    plt.savefig(directory_name + "/" + operator_name + "/" + file_name_prefix + '_LatencyBoxPlot.png', bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create violin plots of the calculated latencies
def create_latency_violin_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, latency_dict, log_scale=False):
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
    plt.savefig(directory_name + "/" + operator_name + "/" + file_name_prefix + '_LatencyViolinPlot.png', bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created violin plot: {file_name_prefix}")
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

# Latency of stale record packets
latency_of_stales_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

# Latency of error packets in the stale phase
latency_of_errors_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

# Latency of non stale ok packets in the stale phase
latency_of_ok_nonstale_pl = {
    "0": [], "10": [], "20": [], "30": [],
    "40": [], "50": [], "60": [], "70": [],
    "80": [], "85": [], "90": [], "95": [],
    "100": [],
}

auth_json_prefix = "auth_stale_pl"
client_json_prefix = "client_stale_pl"

ttl_wait_time = 115
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

    # The time difference between the current packet and the previous packet in the PCAP
    # Used to determine phase switsches
    frame_time_relative_of_previous = 0
    # Phase index == 0 -> Prefetching, 1 -> Stale Phase
    phases = ["Prefetching", "Stale"]
    phase_index = 0

    # Examine all the packets in the JSON file
    for i in range(0, packet_count):
        # Only examine DNS packets
        if 'dns' in json_data[i]['_source']['layers']:
            # Examine the query part of the packet
            json_string = str(json_data[i]['_source']['layers']['dns']['Queries'])
            # Extract the query type to examine only A records
            splitted_type = json_string.split("'dns.qry.type': ")
            splitted_type2 = str(splitted_type[1])
            query_type = splitted_type2.split("'")[1]
            # print(f"QUERY TYPE: {query_type}")

            # If not an A record, skip
            if query_type != "1":
                # pkt = json_data[i]['_source']['layers']['dns']
                # print(pkt)
                continue

            # Extract query name
            splitted_json1 = json_string.split("'dns.qry.name': ")
            splitted2 = str(splitted_json1[1])
            query_name = splitted2.split("'")[1]
            # print(f"Current query name: {query_name}")

            # Filter query names that doesn't belong to our experiment
            # Example query: stale-1-0-0-1-50-ENM-0.packetloss.syssec-research.mmci.uni-saarland.de
            query_name_lower = query_name.lower()
            if "ns1.packetloss.syssec-research.mmci.uni-saarland.de" in query_name_lower \
                    or "_" in query_name_lower or ".packetloss.syssec-research.mmci.uni-saarland.de" not in query_name_lower \
                    or "stale-" not in query_name_lower:
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

            # If its a client pcap, destination IP must be 139.19.117.1, otherwise pass
            if "client" in filename:
                if ip_dst != "139.19.117.1":
                    continue
            # If its an auth pcap, source IP must be 139.19.117.11, otherwise pass
            elif "auth" in filename:
                if ip_src != "139.19.117.11":
                    continue

            # Extract IP Address from the query,
            # filter specific resolver packets using the query's IP Address
            try:
                last_label = query_name.split(".")[0]
                splitted_domain = last_label.split("-")
                ip_addr_with_dashes = splitted_domain[1] + "-" + splitted_domain[2] + "-" + \
                                      splitted_domain[3] + "-" + splitted_domain[4]
                # print(f"IP Address in query: {ip_addr_with_dashes}")
            except Exception as e:
                print(f"Error")
                print(f"{e}")
                print(f"Current query name: {query_name}")
                print(f"frame_number: {frame_number}")

            # Get operator name of the IP Address
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

            # Extract packetloss rate from the query name
            pl_rate_of_query_name = splitted_domain[5]
            # print(f"Packetloss rate: {pl_rate_of_query_name}")

            # If the packetloss rate of the query name does not match the packetloss rate of the PCAP, skip packet
            if str(pl_rate) != pl_rate_of_query_name:
                # print(f"  Different packetloss query detected!")
                # print(f"  Current PL: {str(pl_rate)}")
                # print(f"  Packet  PL: {pl_rate_of_query_name}")
                # print(f"  Skipping packet...")
                non_matching_pl_rate[str(pl_rate)] += 1
                # time.sleep(1)
                continue

            # Extract random token from query name
            random_token_of_query = splitted_domain[6]
            # print(f"random_token_of_query: {random_token_of_query}")
            # Extract the counter of the random token from query name
            counter_of_random_token = splitted_domain[7]
            # print(f"counter_of_random_token: {counter_of_random_token}")

            # Get DNS ID of the packet
            if "dns.id" in json_data[i]['_source']['layers']['dns']:
                dns_id = json_data[i]['_source']['layers']['dns']["dns.id"]
                # print(f"DNS ID: {dns_id}")

            has_answer = False
            if "Answers" in json_data[i]['_source']['layers']['dns']:
                # Possible NS Answer or error packet or query
                has_answer = True

            # Check if it is a response packet, how many answers does the packet have, type of response
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
                                splitted_resp_type = answer_string.split("'dns.resp.type': ")
                                splitted_resp_type2 = str(splitted_resp_type[1])
                                resp_type = splitted_resp_type2.split("'")[1]

                                # print(f"RESPONSE TYPE: {resp_type}")
                                if resp_type != "1":
                                    if pl_rate_of_query_name == "100":
                                        print(f"RESP TYPE: {resp_type} , {query_name_lower} , {frame_number}")
                                    continue

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

            # Check if the query name was already observed before
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

            # Calculate the time difference to the previous packet and try to calculate,
            # which phase the packet belongs to
            time_diff_to_previous_packet = frame_time_relative - frame_time_relative_of_previous
            # print(f"                               Time diff to previous packet: {time_diff_to_previous_packet}")
            time_diff_abs = abs(frame_time_relative - frame_time_relative_of_previous)
            # If the time difference is not too much, it should be in the same phase as previous packet
            if time_diff_abs < ttl_wait_time:
                pass
                # print(f"Same phase, add packet")
                # print(f"Adding packet to phase: {phases[phase_index]}")
            # If there is at least TTL time between packets, phase switching must have occurred
            elif ttl_wait_time <= time_diff_abs <= wait_packetloss_config:
                # print(f"  @@@@@ Phase switching detected, first packet of the phase")
                phase_index = (phase_index + 1) % 2
                # Debug
                # print(f"  Adding packet to phase: {phases[phase_index]}")
                # print(f"Reading file: {filename}")
                # print(f"Current query name: {query_name}")
                # print(f"frame_number: {frame_number}")
                # print(f"Time diff to previous packet: {time_diff_abs}")
                pass
                if phases[phase_index] == "Stale":
                    stale_phase_count += 1
                elif phases[phase_index] == "Prefetching":
                    prefetching_phase_count += 1
            # If more than 5 mins passed, packetloss cooldown is occurred
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
            # If packet is response and in stale phase
            if phases[phase_index] == "Stale":
                # Packet is a response packet
                if is_response == "1":
                    # The response was OK and there was at least 1 A record as answer, check if its stale or not
                    if rcode == "0" and int(answer_count) >= 1:
                        norerror_pl_rate[str(pl_rate)] += 1
                        responses_pl_rate[str(pl_rate)] += 1
                        expected_stale_a_record = ("139." + str(pl_rate) + "." + str(pl_rate) + "." + str(pl_rate))
                        expected_noerror_a_record = (
                                "139." + str(int(pl_rate) + 1) + "." + str(int(pl_rate) + 1) + "." + str(int(pl_rate) + 1))

                        # The record was stale
                        if expected_stale_a_record == a_record:
                            stale_count_of_pl[pl_rate_of_query_name] += 1
                            latency_of_stales_pl[pl_rate_of_query_name].append(dns_time)
                            operator_stale_packets[operator].append(json_data[i])
                            # print(f"    Marked as stale")
                        # The record was non stale
                        elif expected_noerror_a_record == a_record:
                            latency_of_ok_nonstale_pl[pl_rate_of_query_name].append(dns_time)
                            non_stale_count_of_pl[pl_rate_of_query_name] += 1
                            # print(f"    Marked as Non-stale")
                    # If the response was SERVFAIL
                    if rcode == "2":
                        failed_packet_pl_rate[str(pl_rate)] += 1
                        latency_of_errors_pl[pl_rate_of_query_name].append(dns_time)
                    # If response was REFUSED
                    if str(rcode) == "5":
                        refused_packet_pl_rate[str(pl_rate)] += 1
                # Packet is a query
                elif is_response == "0":
                    queries_pl_rate[str(pl_rate)] += 1


# Stale record supporting resolvers
# "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "OpenDNS1",

# No record support
# "AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Google1", "Google2", "Neustar1", "Neustar2", "Yandex1", "Yandex2", "Quad91", "Quad92", "OpenDNS2"

# "AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "Google1", "Google2", "Neustar1", "Neustar2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92", "Yandex1", "Yandex2"
filtered_resolvers = ["AdGuard1", "AdGuard2", "CleanBrowsing1", "CleanBrowsing2", "Google1", "Google2", "Neustar1", "Neustar2", "Yandex1", "Yandex2", "Quad91", "Quad92", "OpenDNS2"]

file_name = "Stale Supported Resolver Only"

for current_pl_rate in packetloss_rates:
    print(f"Current packetloss rate: {current_pl_rate}")

    client_json_file_name = client_json_prefix + str(current_pl_rate) + ".json"
    # auth_json_file_name = auth_json_prefix + current_pl_rate + ".json"

    read_json_file(client_json_file_name, current_pl_rate, filtered_resolvers)

latency_directory_name = "LatencyPlots"
rate_plots_directory_name = "RatePlots"
# Create directory to store logs into it
if not os.path.exists(latency_directory_name):
    os.makedirs(latency_directory_name)
if not os.path.exists(rate_plots_directory_name):
    os.makedirs(rate_plots_directory_name)

latency_upper_limit = 10

create_combined_plots(file_name, file_name, rate_plots_directory_name)

create_latency_violin_plot(latency_directory_name, file_name + "_Error", 0, latency_upper_limit, latency_of_errors_pl, log_scale=False)
create_latency_box_plot(latency_directory_name, file_name + "_Error", 0, latency_upper_limit, latency_of_errors_pl, log_scale=False)

create_latency_violin_plot(latency_directory_name, file_name + "_OK", 0, latency_upper_limit, latency_of_ok_nonstale_pl, log_scale=False)
create_latency_box_plot(latency_directory_name, file_name + "_OK", 0, latency_upper_limit, latency_of_ok_nonstale_pl, log_scale=False)

create_latency_violin_plot(latency_directory_name, file_name + "_Stale", 0, latency_upper_limit, latency_of_stales_pl, log_scale=False)
create_latency_box_plot(latency_directory_name, file_name + "_Stale", 0, latency_upper_limit, latency_of_stales_pl, log_scale=False)
