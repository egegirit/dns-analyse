import sys
import time

import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import re
import os
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import ast

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

directory_of_client_datas = "ClientData"
directory_of_auth_datas = "AuthData"

client_plots_directory_name = "ClientPlots"
auth_plots_directory_name = "AuthPlots"
latency_directory_name = "LatencyPlots"
rate_plots_directory_name = "RatePlots"
unanswered_query_plots_directory_name = "UnansweredQueryPlots"
missing_query_plots_directory_name = "MissingQueryPlots"
retransmission_plots_directory_name = "RetransmissionPlots"
client_latency_upper_limit = 1
auth_latency_upper_limit = 1

# File names of the text files that we will extract data from
all_queries_file = "All_Queries_(PacketLoss_QueryName_Protocol)_Count.txt"
all_responses_file = "All_Responses_(PacketLoss_QueryName_Protocol)_Count.txt"
all_latencies_file = "Latencies_(PacketLoss_RCODE)_[Latencies].txt"
all_rcode_counts_file = "RCODE_Counts_(PacketLoss_RCODE)_Count.txt"
tcp_counterpart_of_udp_query_file = "Tcp_Counterpart_Of_Udp_Query_(PacketLoss)_Count.txt"
responses_with_no_query_file = "Responses_With_No_Query_Count_(PacketLoss)_Count.txt"
unanswered_query_count_file = "Unanswered_Query_Count_(PacketLoss)_Count.txt"
query_names_with_no_ok_response_counts_file = "Query_Names_With_No_OK_Response_Count_(PacketLoss)_[Counts].txt"
response_rcode_0_udp_count_file = "Response_Rcode_0_UDP_Count_(PacketLoss)_Count.txt"
response_rcode_0_tcp_count_file = "Response_Rcode_0_TCP_Count_(PacketLoss)_Count.txt"
missing_query_names_on_auth_file = "Missing_Query_Names_On_Auth_(PacketLoss)_[QueryNames].txt"
all_responses_of_of_counts_file = "All_Responses_(PacketLoss)_Count.txt"
latencies_first_query_first_ok_resp_file = "Latencies_First_Q_First_OKResp_(PacketLoss)_[Latencies].txt"
query_names_with_no_ok_response_file = "Query_Names_With_No_OK_Response_(QueryName_IsResponse)_[Counts].txt"
retransmitted_query_names_and_retr_counts_file = "Retr_Query_Names_and_Counts_Pl_(PL_QueryName)_[Counts].txt"


# Create a folder with the given name
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Folder {folder_name} created")
    else:
        print(f"Folder {folder_name} already exists")


# Read a file and return the string representation of it
def read_dict_from_file(file_name):
    f = open(file_name, "r")
    content = str(f.read())
    return content


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


# Convert a string (read from a text file) to python dictionary
def convert_string_to_dict(string_obj):
    return ast.literal_eval(string_obj)


# Create stacked bar chart (rates of: non_stale, stale, refused and servfail packets)
def create_rate_plot(file_name, root_plot_directory_name, root_data_directory):
    print(f"  Creating rate plot for {file_name} inside folder {root_plot_directory_name}")

    n = len(packetloss_rates)  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr_to_use = [0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5]
    if n == 13:
        arr_to_use = [0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10]
    arr = np.array(arr_to_use)  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    # Create the subfolder inside root folder for the current plotting
    # ClientPlots/AdGuard-1/RatePlots
    save_path = f"{root_plot_directory_name}/{file_name}/{rate_plots_directory_name}"
    create_folder(save_path)

    # (pl-rate): integer
    all_responses_of_pl_count_dict = convert_string_to_dict(
        read_dict_from_file(root_data_directory + "/" + file_name + "/" + all_responses_of_of_counts_file))
    # (pl-rate, query-name, protocol-number): integer
    all_responses_dict = convert_string_to_dict(
        read_dict_from_file(root_data_directory + "/" + file_name + "/" + all_responses_file))
    # (pl, rcode): count
    all_rcode_counts_dict = convert_string_to_dict(
        read_dict_from_file(root_data_directory + "/" + file_name + "/" + all_rcode_counts_file))
    # (pl-rate): count
    tcp_counterpart_of_udp_query_dict = convert_string_to_dict(
        read_dict_from_file(root_data_directory + "/" + file_name + "/" + tcp_counterpart_of_udp_query_file))
    # (pl-rate): count
    responses_with_no_query_dict = convert_string_to_dict(
        read_dict_from_file(root_data_directory + "/" + file_name + "/" + responses_with_no_query_file))
    # (pl-rate): count
    response_rcode_0_udp_count_dict = convert_string_to_dict(
        read_dict_from_file(root_data_directory + "/" + file_name + "/" + response_rcode_0_udp_count_file))
    # (pl-rate): count
    response_rcode_0_tcp_count_dict = convert_string_to_dict(
        read_dict_from_file(root_data_directory + "/" + file_name + "/" + response_rcode_0_tcp_count_file))

    # Calculate Responses
    response_counts_of_pl = [0] * len(packetloss_rates)
    udp_response_counts_of_pl = [0] * len(packetloss_rates)
    tcp_response_counts_of_pl = [0] * len(packetloss_rates)
    # (pl-rate, query-name, protocol-number): integer
    for key, value in all_responses_dict.items():
        # Count all of the response packets of a pl rate
        response_counts_of_pl[get_index_of_packetloss_rate(key[0])] += value
        # Response was sent with UDP
        if key[2] == 17:
            udp_response_counts_of_pl[get_index_of_packetloss_rate(key[0])] += value
        # Response was sent with TCP
        if key[2] == 6:
            tcp_response_counts_of_pl[get_index_of_packetloss_rate(key[0])] += value

    # Response RCODE count arrays
    rcode_0_counts = [0] * len(packetloss_rates)
    rcode_2_counts = [0] * len(packetloss_rates)
    rcode_5_counts = [0] * len(packetloss_rates)
    rcode_other_counts = [0] * len(packetloss_rates)

    # RCODE counts
    for key, value in all_rcode_counts_dict.items():
        # RCODE = 0
        if key[1] == 0:
            rcode_0_counts[get_index_of_packetloss_rate(key[0])] += value
        # RCODE = 2
        elif key[1] == 2:
            rcode_2_counts[get_index_of_packetloss_rate(key[0])] += value
        # RCODE = 5
        elif key[1] == 5:
            rcode_5_counts[get_index_of_packetloss_rate(key[0])] += value
        # Other RCODES
        else:
            rcode_other_counts[get_index_of_packetloss_rate(key[0])] += value

    # print(f"response_counts_of_pl: {response_counts_of_pl}")
    # print(f"udp_response_counts_of_pl: {udp_response_counts_of_pl}")
    # print(f"tcp_response_counts_of_pl: {tcp_response_counts_of_pl}")

    rcode_0_rates = [0] * len(packetloss_rates)
    rcode_0_udp_rates = [0] * len(packetloss_rates)
    rcode_0_tcp_rates = [0] * len(packetloss_rates)
    rcode_2_rates = [0] * len(packetloss_rates)
    rcode_5_rates = [0] * len(packetloss_rates)
    other_rcode_rates = [0] * len(packetloss_rates)

    # Calculate the rates from their counts divided by the response count
    for index in range(len(packetloss_rates)):
        try:
            rcode_0_rates[index] = (rcode_0_counts[index] /
                                    all_responses_of_pl_count_dict[packetloss_rates[index]]) * 100
        except ZeroDivisionError:
            rcode_0_rates[index] = 0
        try:
            rcode_2_rates[index] = (rcode_2_counts[index] /
                                    all_responses_of_pl_count_dict[packetloss_rates[index]]) * 100
        except ZeroDivisionError:
            rcode_2_rates[index] = 0
        try:
            rcode_5_rates[index] = (rcode_5_counts[index] /
                                    all_responses_of_pl_count_dict[packetloss_rates[index]]) * 100
        except ZeroDivisionError:
            rcode_5_rates[index] = 0
        try:
            other_rcode_rates[index] = (rcode_other_counts[index] /
                                        all_responses_of_pl_count_dict[packetloss_rates[index]]) * 100
        except ZeroDivisionError:
            other_rcode_rates[index] = 0
        try:
            rcode_0_udp_rates[index] = (response_rcode_0_udp_count_dict[packetloss_rates[index]] /
                                        all_responses_of_pl_count_dict[packetloss_rates[index]]) * 100
        except ZeroDivisionError:
            rcode_0_udp_rates[index] = 0
        try:
            rcode_0_tcp_rates[index] = (response_rcode_0_tcp_count_dict[packetloss_rates[index]] /
                                        all_responses_of_pl_count_dict[packetloss_rates[index]]) * 100
        except ZeroDivisionError:
            rcode_0_tcp_rates[index] = 0

    # Calculate bottoms of bars
    bottom_of_refused = [i + j for i, j in zip(rcode_0_udp_rates, rcode_0_tcp_rates)]
    bottom_of_failure = [i + j for i, j in zip(bottom_of_refused, rcode_5_rates)]
    bottom_of_others = [i + j for i, j in zip(bottom_of_failure, other_rcode_rates)]

    rcode_0_udp_rects = ax.bar(bar_pos, rcode_0_udp_rates, width, bottom=0, color='limegreen')
    rcode_0_tcp_rects = ax.bar(bar_pos, rcode_0_tcp_rates, width, bottom=rcode_0_udp_rates, color='green')
    refused_rects = ax.bar(bar_pos, rcode_5_rates, width, bottom=bottom_of_refused, color='orange')
    failure_rects = ax.bar(bar_pos, rcode_2_rates, width, bottom=bottom_of_failure, color='red')
    others_rects = ax.bar(bar_pos, other_rcode_rates, width, bottom=bottom_of_others, color='dodgerblue')

    # Title of the graph, x and y label
    plot_title = f"Packetloss Experiment ({file_name})"
    plt.xlabel("Packetloss rate")
    plt.ylabel("Rate of results")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0, top=100)

    ax.set_xticks(bar_pos)
    ax.set_xticklabels(tuple(packetloss_rates))

    # Create legend at the top left of the plot
    ax.legend((others_rects[0], failure_rects[0], refused_rects[0], rcode_0_tcp_rects[0],
               rcode_0_udp_rects[0]),
              ('Other RCODE', 'Failure', 'Refused', 'OK (TCP)', 'OK (UDP)'), framealpha=0.5,
              bbox_to_anchor=(0.1, 1.1))  # 'Unanswered queries', unanswered_rects[0]

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_rcode_0_udp_rects(rects):
        index = 0
        for rect in rects:
            if response_rcode_0_udp_count_dict[packetloss_rates[index]] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"U#{response_rcode_0_udp_count_dict[packetloss_rates[index]]}",
                        # /{all_queries_count_pl[packetloss_rates[index]]}
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
            if response_rcode_0_tcp_count_dict[packetloss_rates[index]] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_stale_plus_stale[index],
                        f"T#{response_rcode_0_tcp_count_dict[packetloss_rates[index]]}",
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
            if rcode_other_counts[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., (h / 2) + hight_of_non_failed[index],
                        f"-#{rcode_other_counts[index]}",
                        ha='center', va='bottom')
            index += 1

    autolabel_rcode_0_udp_rects(rcode_0_udp_rects)
    autolabel_rcode_0_tcp_rects(rcode_0_udp_rects, rcode_0_tcp_rects)
    autolabel_refused(rcode_0_udp_rects, rcode_0_tcp_rects, refused_rects)
    autolabel_fail(rcode_0_udp_rects, rcode_0_tcp_rects, refused_rects, failure_rects)
    autolabel_other(rcode_0_udp_rects, rcode_0_tcp_rects, refused_rects, failure_rects, others_rects)

    # plt.show()

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    # save plot as png
    plt.savefig(f"{save_path}/{file_name}_RatePlot.png", dpi=100, bbox_inches='tight')
    print(f"      Created rate plot")

    # Clear plots
    plt.cla()
    plt.close()


# Create stacked bar chart (rates of: non_stale, stale, refused and servfail packets)
def create_bar_plot(file_name_prefix, directory_name, data_list, root_directory_name, plot_title, y_label):
    print(f"    Creating unanswered bar plot")
    n = len(packetloss_rates)  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr_to_use = [0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5]
    if n == 13:
        arr_to_use = [0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10]
    arr = np.array(arr_to_use)  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    save_path = f"{root_directory_name}/{file_name_prefix}/{directory_name}"
    create_folder(save_path)

    rects = ax.bar(bar_pos, data_list, width, bottom=0, color='dodgerblue')

    # Title of the graph, x and y label
    plot_title = f"{plot_title} ({file_name_prefix})"
    plt.xlabel("Packetloss rate")
    plt.ylabel(f"{y_label}")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0)

    ax.set_xticks(bar_pos)
    ax.set_xticklabels(tuple(packetloss_rates))

    # Create legend at the top left of the plot
    # ax.legend((non_stale_rects[0]), ('OK'), framealpha=0.5, bbox_to_anchor=(0.1, 1.25))

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel(rects):
        index = 0
        for rect in rects:
            if data_list[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"#{data_list[index]}",
                        ha='center', va='bottom')
            index += 1

    autolabel(rects)

    # plt.show()

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    title_without_whitespace = plot_title.replace(' ', '')

    plt.savefig(f"{save_path}/{file_name_prefix}_{title_without_whitespace}Plot.png", dpi=100, bbox_inches='tight')

    # save plot as png
    # plt.savefig((file_name + '_StaleRecordPlot.png'))
    print(f"      Created box plot: {save_path}")
    # Clear plots
    plt.cla()
    plt.close()


# Multi/Grouped bar plot for UDP and TCP retransmissions together
def create_multi_bar_plot(file_name, root_directory_of_plots, plot_title, y_label,
                          udp_list, tcp_list):
    print(f"    Creating multi bar plot")
    n = len(packetloss_rates)  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr_to_use = [0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5]
    if n == 13:
        arr_to_use = [0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10]
    arr = np.array(arr_to_use)  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr + width / 2  # Position of the bar (middle of the x-axis tick/packetloss rate)

    # Create the subfolder inside root folder for the current plotting
    # ClientPlots/AdGuard-1/RatePlots
    save_path = f"{root_directory_of_plots}/{file_name}/{retransmission_plots_directory_name}"
    create_folder(save_path)

    udp_rects = ax.bar(arr, udp_list, width, bottom=0, color='dodgerblue')
    tcp_rects = ax.bar(arr + width, tcp_list, width, bottom=0, color='red')

    # Title of the graph, x and y label
    plot_title = f"{plot_title} ({file_name})"
    plt.xlabel("Packetloss rate")
    plt.ylabel(f"{y_label}")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0)

    ax.set_xticks(bar_pos)
    ax.set_xticklabels(tuple(packetloss_rates))

    # Create legend at the top left of the plot
    ax.legend((udp_rects[0], tcp_rects[0]), ('UDP', 'TCP'), framealpha=0.5, bbox_to_anchor=(0.1, 1.25))

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_udp(udp_rects):
        index = 0
        for rect in udp_rects:
            if udp_list[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"{udp_list[index]}",
                        ha='center', va='bottom')
            index += 1

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel_tcp(tcp_rects):
        index = 0
        for rect in tcp_rects:
            if tcp_list[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"{tcp_list[index]}",
                        ha='center', va='bottom')
            index += 1

    autolabel_udp(udp_rects)
    autolabel_tcp(tcp_rects)

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    title_without_whitespace = plot_title.replace(' ', '')

    plt.savefig(f"{save_path}/{file_name}_{title_without_whitespace}Plot.png", dpi=100, bbox_inches='tight')

    print(f"      Created grouped retransmission bar plot")
    # Clear plots
    plt.cla()
    plt.close()


# Create box plot for the calculated latencies
def create_latency_box_plot(root_directory_name, file_name_prefix, bottom_limit, upper_limit, latency_list,
                            log_scale=False):
    print(f"    Creating box plot: {file_name_prefix}")

    # Filter the _OK or _SERVFAIL
    operator_name = file_name_prefix.split("_")[0]

    save_path = f"{root_directory_name}/{operator_name}/{latency_directory_name}"
    create_folder(save_path)

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')
    ax.set_title(f"Response Latency of " + file_name_prefix)

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks(packetloss_rates)
    ax.set_xticklabels(packetloss_rates)

    if log_scale:
        ax.set_yscale('log', base=2)
    # else: ax.set_yscale('linear')

    # Add the data counts onto the plot as text
    data_count_string = ""
    for i in range(len(latency_list)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(latency_list[i])) + "\n"

    left, width = .25, .5
    bottom, height = .25, .5
    right = left + width
    top = bottom + height
    ax.text(0.5 * (left + right), .80 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    for lst in latency_list:
        for latency in lst:
            if latency > upper_limit:
                upper_limit = latency

    plt.ylim(bottom=bottom_limit, top=upper_limit + 1)

    # Creating plot
    ax.boxplot(latency_list, positions=packetloss_rates,
               widths=4.4)

    plt.savefig(f"{save_path}/{file_name_prefix}_LatencyBoxPlot.png", bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created latency box plot")
    # Clear plots
    plt.cla()
    plt.close()


# Create violin plots of the calculated latencies
def create_latency_violin_plot(root_directory_name, file_name_prefix, bottom_limit, upper_limit, latencies,
                               log_scale=False):
    # Workaround for preventing parameter variable overwrite outside the scope of this function
    latency_list = latencies.copy()

    print(f"    Creating violin plot: {file_name_prefix}")
    # print(f"   Inside the folder: {root_directory_name}")
    # print(f"   Log-scale: {log_scale}")

    # Split the _OK or _Error part from the resolver name
    operator_name = file_name_prefix.split("_")[0]

    save_path = f"{root_directory_name}/{operator_name}/{latency_directory_name}"
    create_folder(save_path)

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks(packetloss_rates)
    ax.set_xticklabels(packetloss_rates)

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')
    ax.set_title(f"Response Latency of " + file_name_prefix)

    for lst in latency_list:
        for latency in lst:
            if latency > upper_limit:
                upper_limit = latency

    plt.ylim(bottom=bottom_limit, top=upper_limit + 1)

    # Handle zero values with a -1 dummy value
    empty_list_indexes = []
    for i in range(len(latency_list)):
        if len(latency_list[i]) == 0:
            latency_list[i] = [-1]
            empty_list_indexes.append(i)

    print(f"  empty_list_indexes: {empty_list_indexes}")

    # list_indexes_with_non_empty_values = []
    # for i in range(len(latency_list)):
    #     if len(latency_list[i]) != 0:
    #         list_indexes_with_non_empty_values.append(packetloss_rates[i])
    #         # latency_list[i] = [0]
    #     # else:
    #     #     list_indexes_with_no_values[i].append(-1)
    #
    # print(f"list_indexes_with_no_values: {list_indexes_with_non_empty_values}")
    #
    # new_latency_list_with_reduced_index = []
    # for lst in latency_list:
    #     if len(lst) != 0:
    #         new_latency_list_with_reduced_index.append(lst)
    #
    # print(f"new_latency_list_with_reduced_index: {new_latency_list_with_reduced_index}")

    # Create and save Violinplot
    bp = ax.violinplot(dataset=latency_list, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=packetloss_rates)

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(latency_list)):
        length_of_list_index = len(latency_list[i])
        if i in empty_list_indexes:
            length_of_list_index -= 1
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            length_of_list_index) + "\n"

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

    # save plot as png
    plt.savefig(f"{save_path}/{file_name_prefix}_LatencyViolinPlot.png", bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created latency violin plot")
    # Clear plots
    plt.cla()
    plt.close()


# Create retransmission plot
def create_violin_plot(root_directory_name, file_name_prefix, data_param, plot_title, y_label):
    data_list = data_param.copy()

    print(f"    Creating violin plot: {file_name_prefix}")
    # print(f"   Inside the folder: {root_directory_name}")
    # print(f"   Log-scale: {log_scale}")

    # Split the _OK or _Error part from the resolver name
    operator_name = file_name_prefix.split("_")[0]

    save_path = f"{root_directory_name}/{operator_name}/{retransmission_plots_directory_name}"
    create_folder(save_path)

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks(packetloss_rates)
    ax.set_xticklabels(packetloss_rates)

    ax.set_ylabel(f'{y_label}')
    ax.set_xlabel('Packetloss in percentage')
    ax.set_title(f"{plot_title} " + file_name_prefix)

    # Handle zero values with a -1 dummy value
    empty_list_indexes = []
    plot_upper_limit = 1
    for i in range(len(data_list)):
        if len(data_list[i]) == 0:
            data_list[i] = [-1]
            empty_list_indexes.append(i)
        else:
            # Find maximum count for top limit of plot
            for number in data_list[i]:
                if number > plot_upper_limit:
                    plot_upper_limit = number

    # print(f"Data of {plot_title}: {data}")
    # print(f" plot_upper_limit: {plot_upper_limit}")

    plt.ylim(bottom=0, top=plot_upper_limit + 1)

    # Create and save Violinplot
    bp = ax.violinplot(dataset=data_list, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=packetloss_rates)

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(data_list)):
        length_of_list_index = len(data_list[i])
        if i in empty_list_indexes:
            length_of_list_index -= 1
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            length_of_list_index) + "\n"

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

    title_without_whitespace = plot_title.replace(' ', '')
    plt.savefig(f"{save_path}/{file_name_prefix}_{title_without_whitespace}Plot.png", bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created retransmission violin plot")
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


def create_latency_plots(file_name, root_directory_of_plots):
    # Extract latency data and split into OK and ServFail latencies
    # (pl-rate, rcode): [latencies]

    directory_to_read = ""
    if "client" in root_directory_of_plots.lower():
        directory_to_read = directory_of_client_datas
    elif "auth" in root_directory_of_plots.lower():
        directory_to_read = directory_of_auth_datas

    all_latencies_dict = convert_string_to_dict(
        read_dict_from_file(directory_to_read + "/" + file_name + "/" + all_latencies_file))
    rcode_0_resp_latencies = []  # [[]] * len(packetloss_rates)
    rcode_2_resp_latencies = []  # [[]] * len(packetloss_rates)
    for key, value in all_latencies_dict.items():
        # OK latency
        if key[1] == 0:
            rcode_0_resp_latencies.append(value)  # [get_index_of_packetloss_rate(key[0])]
        # ServFail latency
        elif key[1] == 2:
            rcode_2_resp_latencies.append(value)  # rcode_2_resp_latencies.append(value)

    print(f"rcode_0_resp_latencies: {rcode_0_resp_latencies}")

    # for i in range(len(rcode_0_resp_latencies)):
    #     print(f"Length rcode_0_resp_latencies[{i}]: {len(rcode_0_resp_latencies[i])}")

    print(f"rcode_2_resp_latencies: {rcode_2_resp_latencies}")

    # for i in range(len(rcode_2_resp_latencies)):
    #     print(f"Length rcode_0_resp_latencies[{i}]: {len(rcode_2_resp_latencies[i])}")

    # Set plot y-axis limit
    upper_limit = 20
    if "auth" in root_directory_of_plots.lower():
        upper_limit = auth_latency_upper_limit
    elif "client" in root_directory_of_plots.lower():
        upper_limit = client_latency_upper_limit

    # create OK latency plots
    create_latency_violin_plot(root_directory_of_plots, file_name + "_OK", 0, upper_limit,
                               rcode_0_resp_latencies, log_scale=False)
    create_latency_box_plot(root_directory_of_plots, file_name + "_OK", 0, upper_limit,
                            rcode_0_resp_latencies, log_scale=False)

    # create ServFail latency plots
    create_latency_violin_plot(root_directory_of_plots, file_name + "_Error", 0, upper_limit,
                               rcode_2_resp_latencies, log_scale=False)
    create_latency_box_plot(root_directory_of_plots, file_name + "_Error", 0, upper_limit,
                            rcode_2_resp_latencies, log_scale=False)

    # Create latency between first query first OK response plot
    first_latencies_dict = convert_string_to_dict(
        read_dict_from_file(directory_to_read + "/" + file_name + "/" + latencies_first_query_first_ok_resp_file))

    first_latency_values_as_list = list(first_latencies_dict.values())

    create_latency_violin_plot(root_directory_of_plots, file_name + "_1st-Query-1st-OK-Response", 0, upper_limit,
                               first_latency_values_as_list, log_scale=False)
    create_latency_box_plot(root_directory_of_plots, file_name + "_1st-Query-1st-OK-Response", 0, upper_limit,
                            first_latency_values_as_list, log_scale=False)


def create_unanswered_plot(file_name, root_directory_of_plots):
    # Extract unanswered data
    directory_to_read = ""
    if "client" in root_directory_of_plots.lower():
        directory_to_read = directory_of_client_datas
    elif "auth" in root_directory_of_plots.lower():
        directory_to_read = directory_of_auth_datas

    # (pl-rate): count
    unanswered_query_count_dict = convert_string_to_dict(
        read_dict_from_file(directory_to_read + "/" + file_name + "/" + unanswered_query_count_file))

    # Create unanswered query plot
    create_bar_plot(file_name, unanswered_query_plots_directory_name, list(unanswered_query_count_dict.values()),
                    root_directory_of_plots, "Unanswered Queries", "Unanswered Query Count")

    query_names_with_no_ok_response_counts_dict = convert_string_to_dict(
        read_dict_from_file(directory_to_read + "/" + file_name + "/" + query_names_with_no_ok_response_counts_file))

    create_bar_plot(file_name, unanswered_query_plots_directory_name,
                    list(query_names_with_no_ok_response_counts_dict.values()),
                    root_directory_of_plots, "Queries With No OK Responses", "Query With No OK Responses Count")


def create_retransmission_plots(file_name, root_directory_of_plots):
    directory_to_read = ""
    if "client" in root_directory_of_plots.lower():
        directory_to_read = directory_of_client_datas
    elif "auth" in root_directory_of_plots.lower():
        directory_to_read = directory_of_auth_datas

    # All_Queries_(PacketLoss_QueryName_Protocol)_Count
    all_queries_dict = convert_string_to_dict(
        read_dict_from_file(directory_to_read + "/" + file_name + "/" + all_queries_file))

    udp_query_retransmission_count_list = [0] * len(packetloss_rates)
    tcp_query_retransmission_count_list = [0] * len(packetloss_rates)

    for key, value in all_queries_dict.items():
        # Check if there was really a retransmission
        # (count should be > 1 bcs first one is the original, not the duplicate)
        if value > 0:
            # TCP
            if key[2] == 6:
                tcp_query_retransmission_count_list[get_index_of_packetloss_rate(key[0])] += value
            # UDP
            elif key[2] == 17:
                udp_query_retransmission_count_list[get_index_of_packetloss_rate(key[0])] += value

    create_multi_bar_plot(file_name, root_directory_of_plots, "Query Retransmission", "Query Retransmission Count",
                          udp_query_retransmission_count_list, tcp_query_retransmission_count_list)

    # All_Queries_(PacketLoss_QueryName_Protocol)_Count
    all_response_dict = convert_string_to_dict(
        read_dict_from_file(directory_to_read + "/" + file_name + "/" + all_responses_file))

    udp_response_retransmission_count_list = [0] * len(packetloss_rates)
    tcp_response_retransmission_count_list = [0] * len(packetloss_rates)

    for key, value in all_response_dict.items():
        # Check if there was really a retransmission
        # (count should be > 1 bcs first one is the original, not the duplicate)
        if value > 1:
            # TCP
            if key[2] == 6:
                tcp_response_retransmission_count_list[get_index_of_packetloss_rate(key[0])] += (value - 1)
            # UDP
            elif key[2] == 17:
                udp_response_retransmission_count_list[get_index_of_packetloss_rate(key[0])] += (value - 1)

    create_multi_bar_plot(file_name, root_directory_of_plots, "Response Retransmission",
                          "Response Retransmission Count",
                          udp_response_retransmission_count_list, tcp_response_retransmission_count_list)

    # Create violin plot for Query retransmission ranges
    udp_query_counts_of_pl = []
    tcp_query_counts_of_pl = []
    for pl in packetloss_rates:
        udp_query_counts_of_pl.append([])
        tcp_query_counts_of_pl.append([])

    # (pl-rate, query-name, protocol-number): integer
    for key in list(all_queries_dict.keys()):
        # Retransmission occurs when a query is seen more than 1 times,
        # If a query is seen 2 times, the retransmission count is 2 - 1, because the first query was the original one
        value = all_queries_dict[key]
        if value > 0:
            # Query was sent with UDP
            if key[2] == 17:
                udp_query_counts_of_pl[get_index_of_packetloss_rate(key[0])].append(value)
            # Query was sent with TCP
            if key[2] == 6:
                tcp_query_counts_of_pl[get_index_of_packetloss_rate(key[0])].append(value)

    # print(f"Query retransmission ranges:")
    # print(f"udp_query_counts_of_pl: {udp_query_counts_of_pl}")
    # print(f"tcp_query_counts_of_pl: {tcp_query_counts_of_pl}")

    create_violin_plot(root_directory_of_plots, file_name, udp_query_counts_of_pl,
                       "DNS UDP Query Retransmissions", "UDP Query Retransmission Counts")
    create_violin_plot(root_directory_of_plots, file_name, tcp_query_counts_of_pl,
                       "DNS TCP Query Retransmissions", "TCP Query Retransmission Counts")

    # Create violin plot for Response retransmission ranges
    udp_response_counts_of_pl = []
    tcp_response_counts_of_pl = []
    for pl in packetloss_rates:
        udp_response_counts_of_pl.append([])
        tcp_response_counts_of_pl.append([])

    # (pl-rate, query-name, protocol-number): integer
    for key, value in all_response_dict.items():
        # Retransmission occurs when a query is seen more than 1 times,
        # If a query is seen 2 times, the retransmission count is 2 - 1, because the first query was the original one
        if value > 1:
            # Query was sent with UDP
            if key[2] == 17:
                udp_response_counts_of_pl[get_index_of_packetloss_rate(key[0])].append(value - 1)
            # Query was sent with TCP
            if key[2] == 6:
                tcp_response_counts_of_pl[get_index_of_packetloss_rate(key[0])].append(value - 1)

    # print(f"udp_query_counts_of_pl: {udp_response_counts_of_pl}")
    # print(f"tcp_query_counts_of_pl: {tcp_response_counts_of_pl}")

    create_violin_plot(root_directory_of_plots, file_name, udp_response_counts_of_pl,
                       "DNS UDP Response Retransmissions", "UDP Response Retransmission Counts")
    create_violin_plot(root_directory_of_plots, file_name, tcp_response_counts_of_pl,
                       "DNS TCP Response Retransmissions", "TCP Response Retransmission Counts")


def create_plots_of_type(file_name, root_directory_of_plots, directory_of_datas_to_read):
    # Create rate plot
    create_rate_plot(file_name, root_directory_of_plots, directory_of_datas_to_read)

    # Create latency plots
    create_latency_plots(file_name, root_directory_of_plots)

    # Create unanswered plot
    create_unanswered_plot(file_name, root_directory_of_plots)

    # Create retransmission plots
    create_retransmission_plots(file_name, root_directory_of_plots)


def create_plots_for(file_name):
    print(f"Creating plot with name: {file_name}")

    # Create root folder for client plots
    client_root_plot_folder_name = "ClientPlots"
    create_folder(client_root_plot_folder_name)

    # Create client plots
    create_plots_of_type(file_name, client_root_plot_folder_name, directory_of_client_datas)

    # Create root folder for auth plots
    auth_root_plot_folder_name = "AuthPlots"
    create_folder(auth_root_plot_folder_name)

    # Create auth plots
    create_plots_of_type(file_name, auth_root_plot_folder_name, directory_of_auth_datas)

    # Create missing query plots for auth
    # (pl-rate): [query-names]
    all_responses_dict = convert_string_to_dict(
        read_dict_from_file(directory_of_auth_datas + "/" + file_name + "/" + missing_query_names_on_auth_file))

    missing_query_on_auth_count_list = [0] * len(packetloss_rates)
    for key, value in all_responses_dict.items():
        missing_query_on_auth_count_list[get_index_of_packetloss_rate(key)] = len(value)

    create_bar_plot(file_name, missing_query_plots_directory_name, missing_query_on_auth_count_list,
                    auth_root_plot_folder_name, "Missing Queries", "Missing Query Count")

    # Create plots to show how retransmissions resolved queries
    q_dict = convert_string_to_dict(
        read_dict_from_file(directory_of_client_datas + "/" + file_name + "/" + query_names_with_no_ok_response_file))

    retr_dict = convert_string_to_dict(
        read_dict_from_file(
            directory_of_auth_datas + "/" + file_name + "/" + retransmitted_query_names_and_retr_counts_file))

    all_query_names_with_no_ok_responses = []
    for key, value in q_dict.items():
        if key[0] not in all_query_names_with_no_ok_responses:
            all_query_names_with_no_ok_responses.append(key[0])

    # (PL) = [List of 0s and 1s] 0: failed retransmissions, 1s: success
    retransmission_success = {}

    for key, value in retr_dict.items():
        # Retransmission did not resolve te query
        if key[1] in all_query_names_with_no_ok_responses:
            if (key[0]) not in retransmission_success:
                retransmission_success[key[0]] = []
            retransmission_success[key[0]].append(0)
        # Retransmission resolved te query
        else:
            if (key[0]) not in retransmission_success:
                retransmission_success[key[0]] = []
            retransmission_success[key[0]].append(1)

    create_bar_plot_for_retransmission_success_rate(file_name, retransmission_plots_directory_name, retransmission_success,
                                                   auth_root_plot_folder_name, "Retransmission Success Rates",
                                                   "Retransmission Success Rates")


# Create stacked bar chart (rates of: non_stale, stale, refused and servfail packets)
def create_bar_plot_for_retransmission_success_rate(file_name_prefix, directory_name, retransmission_success, root_directory_name, plot_title, y_label):

    success_ratios = {}
    for key, value in retransmission_success.items():
        success_count = 0
        fail_count = 0
        for i in value:
            if i == 0:
                fail_count += 1
            elif i == 1:
                success_count += 1
        try:
            success_ratios[key] = success_count / (success_count + fail_count) * 100
        except ZeroDivisionError:
            print(f"Division Error")
            success_ratios[key] = 0

    print(f" ### retransmission_success: {retransmission_success}")
    print(f" ### success_ratios: {success_ratios}")

    x_axis = list(success_ratios.keys())
    data_list = list(success_ratios.values())

    print(f"    Creating bar plot")
    n = len(x_axis)  # Amount of bars in the chart
    ind = np.arange(n)  # the x locations for the groups
    width = 1  # the width of the bars
    arr = np.array(ind)  # Positions of the bars
    fig = plt.figure()
    ax = fig.add_subplot(111)
    bar_pos = arr  # Position of the bar (middle of the x-axis tick/packetloss rate)

    save_path = f"{root_directory_name}/{file_name_prefix}/{directory_name}"
    create_folder(save_path)

    rects = ax.bar(x_axis, data_list, width, bottom=0, color='dodgerblue')

    # Title of the graph, x and y label
    plot_title = f"{plot_title} ({file_name_prefix})"
    plt.xlabel("Packetloss rate")
    plt.ylabel(f"{y_label}")

    # Title position
    plt.title(plot_title, x=0.5, y=1.1)

    # Limits of the X and Y axis
    plt.ylim(bottom=0, top=100)

    # ax.set_xticks(bar_pos)
    # ax.set_xticklabels(tuple(x_axis))

    # Create legend at the top left of the plot
    # ax.legend((non_stale_rects[0]), ('OK'), framealpha=0.5, bbox_to_anchor=(0.1, 1.25))

    # Write the exact count of the non-stale packets in the middle of non-stale bars
    def autolabel(rects):
        index = 0
        for rect in rects:
            if data_list[index] != 0:
                h = rect.get_height()
                ax.text(rect.get_x() + rect.get_width() / 2., h / 2,
                        f"{int(data_list[index])}",
                        ha='center', va='bottom')
            index += 1

    autolabel(rects)

    # plt.show()

    figure = plt.gcf()  # get current figure
    figure.set_size_inches(16, 6)  # set figure's size manually to your full screen (32x18)

    title_without_whitespace = plot_title.replace(' ', '')

    plt.savefig(f"{save_path}/{file_name_prefix}_{title_without_whitespace}Plot.png", dpi=100, bbox_inches='tight')

    # save plot as png
    # plt.savefig((file_name + '_StaleRecordPlot.png'))
    print(f"      Created box plot: {save_path}")
    # Clear plots
    plt.cla()
    plt.close()


all_resolvers = list(operators.keys())

# Create separate plots for all resolver IPs
for resolver in all_resolvers:
    # try:
    create_plots_for(resolver)
    # except Exception as e:
    #     print(f"Error creating plots for: {resolver}")
    #     print(f"{str(e)}")

create_plots_for("OverallBehaviour")
