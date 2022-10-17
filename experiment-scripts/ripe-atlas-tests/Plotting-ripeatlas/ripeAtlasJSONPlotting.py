import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import json
import re
import os
import time
import base64
import dns.message
from collections import deque


# The packetloss rates that are simulated in the experiment
packetloss_rates = [40, 60, 70, 80, 90, 95]


latencies_with_pl = {
    "latency_40": [],
    "latency_60": [],
    "latency_70": [],
    "latency_80": [],
    "latency_90": [],
    "latency_95": [],
}


def get_packetloss_index(pl_rate):
    if pl_rate == "40":
        return 0
    if pl_rate == "60":
        return 1
    if pl_rate == "70":
        return 2
    if pl_rate == "80":
        return 3
    if pl_rate == "90":
        return 4
    if pl_rate == "95":
        return 5
    return None

def get_pl_rate_of_index(index):
    if index == 0:
        return "40"
    if index == 1:
        return "60"
    if index == 2:
        return "70"
    if index == 3:
        return "80"
    if index == 4:
        return "90"
    if index == 5:
        return "95"
    return None

def get_desired_attribute(string_to_search, attribute_string):
    if attribute_string in string_to_search:
        return string_to_search.split(attribute_string)[1].split(",")[0]


def getIndex(s, i):
    # If input is invalid.
    if s[i] != '{':
        return -1

    # Create a deque to use it as a stack.
    d = deque()

    # Traverse through all elements
    # starting from i.
    for k in range(i, len(s)):

        # Pop a starting bracket
        # for every closing bracket
        if s[k] == '}':
            d.popleft()

        # Push all starting brackets
        elif s[k] == '{':
            d.append(s[i])

        # If deque becomes empty
        if not d:
            return k

    return -1


# Create box plot for the calculated latencies
def create_overall_box_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, log_scale=False):
    print(f" Creating box plot: {file_name_prefix}")
    print(f"   Inside the folder: {directory_name}")
    # print(f"   Limits: [{bottom_limit}, {upper_limit}]")
    # print(f"   Log-scale: {log_scale}")

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    # Print on the plot if the plot is for client or auth (user variable)
    user = file_name_prefix.split("_")[0]
    ax.set_title(f"Response Failure Rate for {user}")

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks([40, 60, 70, 80, 90, 95])
    ax.set_xticklabels([40, 60, 70, 80, 90, 95])

    if log_scale:
        ax.set_yscale('log', base=2)
    # else: ax.set_yscale('linear')

    # Add the data counts onto the plot as text
    # TODO: do this as a second bar in the plot
    data_count_string = ""
    for i in range(len(latencies_with_pl)):
        pl_rate = get_pl_rate_of_index(i)
        current_key = "latency_" + pl_rate
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(len(latencies_with_pl[current_key])) + "\n"
    text = ax.annotate(data_count_string, xy=(.5, .5), xytext=(x_axis_for_text, y_axis_for_text), color='red')

    left, width = .25, .5
    bottom, height = .25, .5
    right = left + width
    top = bottom + height
    ax.text(0.5 * (left + right), .75 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    # print(f"Annotate text box plot: {data_count_string}")

    # Make it transparent
    text.set_alpha(.4)
    # plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Creating plot
    ax.boxplot(latencies_with_pl.values(), positions=[40, 60, 70, 80, 90, 95], widths=4.4)

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
    # print(f"   Limits: [{bottom_limit}, {upper_limit}]")
    # print(f"   Log-scale: {log_scale}")

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([40, 60, 70, 80, 90, 95])
    ax.set_xticklabels([40, 60, 70, 80, 90, 95])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    # Print on the plot if the plot is for client or auth (user variable)
    user = file_name_prefix.split("_")[0]
    ax.set_title(f"Response Failure Rate for {user}")

    if log_scale:
        ax.set_yscale('log', base=2)

    # Create and save Violinplot
    bp = ax.violinplot(dataset=latencies_with_pl.values(), showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[40, 60, 70, 80, 90, 95])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(list(latencies_with_pl.values()))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(len(list(latencies_with_pl.values())[i])) + "\n"

    # print(f"Annotate text violin plot: {data_count_string}")

    text = ax.annotate(data_count_string, xy=(.5, .5), xytext=(x_axis_for_text, y_axis_for_text), color='red')
    # Make it transparent
    text.set_alpha(.5)

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
    blue_line = mlines.Line2D([], [], color='blue', marker='',
                              markersize=15, label='mean')
    red_line = mlines.Line2D([], [], color='red', marker='',
                             markersize=15, label='median')
    ax.legend(handles=[blue_line, red_line], loc='upper left')

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name_prefix + '_violinPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created violin plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Write text onto plots using this coordinates
x_axis_for_text = 1
y_axis_for_text = 1

bottom_limit = 0
upper_limit = 20

directory_name_of_plots = "ripe-probes-plot-results"

if not os.path.exists(directory_name_of_plots):
    os.makedirs(directory_name_of_plots)

for pl_rate in packetloss_rates:
    print(f"**** Current packetloss rate: {pl_rate} ****")
    file_name_to_read_jsons = "ripeAtlasJSON-pl" + str(pl_rate) + ".txt"
    file = open(file_name_to_read_jsons, "r")
    print(f"Reading file: {file_name_to_read_jsons}")

    line_count = 1
    for line in file:
        # print(f"=================")
        # print(f"Result ({line_count}):")
        stripped_line = line.rstrip()

        list_of_reports = []

        json_count = 0
        stop = False
        while not stop:
            # count_brackets(stripped_line)
            first_bracket_index = stripped_line.find("{")
            # print(first_bracket_index)
            matching_bracket_index = getIndex(stripped_line, first_bracket_index)
            # print(matching_bracket_index)
            # print(f"Stripped: {stripped_line[first_bracket_index:matching_bracket_index]}")

            list_of_reports.append(stripped_line[first_bracket_index:matching_bracket_index])
            # print(f"Added to list")
            json_count += 1

            stripped_line = stripped_line[matching_bracket_index + 1:]
            # print(f"Remaining: {stripped_line}")
            next_bracket_index = stripped_line.find("{")
            # print(next_bracket_index)
            if next_bracket_index == -1:
                stop = True
                # print(f"Stopping with {json_count}")

        # print(f"  Total report count: {len(list_of_reports)}")

        report_count = 1
        for report in list_of_reports:

            # print(f"\n  Report ({report_count}):")

            epoch_time = int(get_desired_attribute(report, "'time': "))
            epoch_to_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_time))
            # print(f"Time: {epoch_time} -> {epoch_to_date}")
            src_ip = get_desired_attribute(report, "'src_addr': ")
            # print(f"Source IP: {src_ip}")
            dst_ip = get_desired_attribute(report, "'dst_addr': ")
            # print(f"Source IP: {dst_ip}")
            ttl = get_desired_attribute(report, "'ttl': ")
            # print(f"TTL: {ttl}")
            protocol = get_desired_attribute(report, "'proto': ")
            # print(f"Protocol: {protocol}")

            qbuf = get_desired_attribute(report, "'qbuf': ")
            if qbuf is not None:
                qbuf_decoded = dns.message.from_wire(base64.b64decode(qbuf))
                # print(f"\nQBUF:\n{qbuf_decoded}")

            if "'result':" in report:
                # print(f"Packet has result")
                result_json = report.split("'result':")[1]
                # print(f"result_json: {result_json}")
                response_time = float(get_desired_attribute(report, "'rt': "))
                # print(f"Response time: {response_time} (ms) -> {response_time/1000.0} (s)")

                latencies_with_pl["latency_" + str(pl_rate)].append(response_time/1000.0)

                abuf = get_desired_attribute(report, "'abuf': ")
                if abuf is not None:
                    abuf_decoded = dns.message.from_wire(base64.b64decode(abuf))
                    # print(f"\nABUF:\n{abuf_decoded}")
            report_count += 1

        # print(f"\n")
        line_count += 1

    file.close()

index = 0
for latencies_of_pl in latencies_with_pl:
    pl_rate = get_pl_rate_of_index(index)
    print(f"Length of {pl_rate} Packetloss rate latencies: {len(latencies_of_pl)}")
    index += 1

create_overall_latency_violin_plot(directory_name_of_plots, "ripe-atlas", bottom_limit, upper_limit, False)
create_overall_box_plot(directory_name_of_plots, "ripe-atlas", bottom_limit, upper_limit, False)
