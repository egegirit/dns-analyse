import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import json
import re
import os
import time
import base64
import dns.message
from collections import deque

latencies_with_pl = {
    "latency_0": []
}

query_names_with_pl = {
    "query_names_0": []
}

answer_names_with_pl = {
    "answer_names_0": []
}

global duplicate_query_count_with_pl
duplicate_query_count_with_pl = {
    "duplicate_query_count_0": 0
}
global duplicate_answer_count_with_pl
duplicate_answer_count_with_pl = {
    "duplicate_answer_count_0": 0
}

global servfail_count_with_pl
servfail_count_with_pl = {
    "servfail_count_0": 0
}

global count_of_answers_with_pl
count_of_answers_with_pl = {
    "count_of_answers_0": 0

}


def get_desired_attribute(string_to_search, attribute_string):
    if attribute_string in string_to_search:
        return string_to_search.split(attribute_string)[1].split(",")[0]


def extract_attribute_from_buf(attr, buf):
    if attr in buf:
        return buf.split(attr)[1].split("\n")[0]


def extract_field_from_buf(attr, buf):
    if attr in buf:
        return buf.split(attr)[1].split("\n")[1]
    else:
        print(f"{attr} not in the string")


def extract_query_name(string):
    if string == "" or string is None:
        return ""
    try:
        last_index_of_dot = string.rindex(".")
    except ValueError:
        return ""
    result = string[0:last_index_of_dot]
    return result


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
    ax.set_title(f"Response latency for {user} probes")

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

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
    ax.boxplot(latencies_with_pl.values(), positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95], widths=4.4)

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
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    # Print on the plot if the plot is for client or auth (user variable)
    user = file_name_prefix.split("_")[0]
    ax.set_title(f"Response latency for {user} probes")

    if log_scale:
        ax.set_yscale('log', base=2)

    # Create and save Violinplot
    bp = ax.violinplot(dataset=latencies_with_pl.values(), showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(list(latencies_with_pl.values()))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(list(latencies_with_pl.values())[i])) + "\n"

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


# Create bar plot to show failure rates
# failure_rate_data is already filled when looping the packets
def create_overall_bar_plot_failure(directory_name, file_name):
    print(f" Creating bar plot: {file_name}")
    print(f"   Inside the folder: {directory_name}")

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    failure_rate_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                              '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # Write the failure count on the plot
    # TODO: As dictionary
    fail_1 = []
    fail_2 = []
    fail_3 = []
    fail_4 = []
    fail_5 = []
    fail_6 = []
    fail_7 = []
    fail_8 = []
    fail_9 = []
    fail_10 = []
    fail_11 = []
    fail_12 = []
    failure_counts = [fail_1, fail_2,
                      fail_3,
                      fail_4,
                      fail_5,
                      fail_6,
                      fail_7,
                      fail_8,
                      fail_9,
                      fail_10,
                      fail_11,
                      fail_12]

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary
    index = 0
    for current_packetloss_rate in packetloss_rates:

        current_servfail_count = servfail_count_with_pl["servfail_count_" + str(current_packetloss_rate)]

        if current_servfail_count != 0:
            # Divide by 900 because we send 900 queries from client pro packetloss config (18 Resolver * 50 counter),
            # when you filter by an IP, you need to adjust the query_count_per_pl_rate like so:
            query_count_per_pl_rate = count_of_answers_with_pl["count_of_answers_" + str(current_packetloss_rate)]
            failure_counts[index] = current_servfail_count
            failure_rate_data_dict[str(current_packetloss_rate)] = (current_servfail_count / query_count_per_pl_rate) * 100
        else:
            failure_counts[index] = 0
            failure_rate_data_dict[str(current_packetloss_rate)] = 0
        index = index + 1

    keys = list(failure_rate_data_dict.keys())
    values = list(failure_rate_data_dict.values())

    print(f"Failure rates: {keys}")
    print(f"Failure ratio: {values}")

    plt.figure(figsize=(10, 5))
    # fig = plt.figure(figsize=(10, 5))

    # creating the bar plot
    plt.bar(failure_rates, values, color='maroon', width=4)

    # adding text inside the plot
    data_count_string = ""
    for i in range(len(servfail_count_with_pl)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            failure_counts[i]) + "\n"
    text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')
    text.set_alpha(0.5)

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


# Write text onto plots using this coordinates
x_axis_for_text = 1
y_axis_for_text = 1

bottom_limit = 0
upper_limit = 30

directory_name_of_plots = "ripe-probes-plot-results"

if not os.path.exists(directory_name_of_plots):
    os.makedirs(directory_name_of_plots)

file_to_write = open("JsonDecoded.txt", "w")

file_name_to_read_jsons = "ripeAtlasAllJSONs.txt"
file = open(file_name_to_read_jsons, "r")
print(f"Reading file: {file_name_to_read_jsons}")

line_count = 1
for line in file:

    print(f"\n ===== Line ({line_count}) =====")
    file_to_write.write(f"\n ===== Line ({line_count}) =====\n")

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

        print(f"\n     == Report ({report_count}) ==")
        file_to_write.write(f"\n     == Report ({report_count}) ==\n")

        epoch_time = int(get_desired_attribute(report, "'time': "))
        epoch_to_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_time))
        print(f"Time: {epoch_time} -> {epoch_to_date}")
        file_to_write.write(f"Time: {epoch_time} -> {epoch_to_date}\n")

        src_ip = get_desired_attribute(report, "'src_addr': ")
        print(f"Source IP: {src_ip}")
        file_to_write.write(f"Source IP: {src_ip}\n")

        dst_ip = get_desired_attribute(report, "'dst_addr': ")
        print(f"Destination IP: {dst_ip}")
        file_to_write.write(f"Destination IP: {dst_ip}\n")

        ttl = get_desired_attribute(report, "'ttl': ")
        print(f"TTL: {ttl}")
        file_to_write.write(f"TTL: {ttl}\n")

        protocol = get_desired_attribute(report, "'proto': ")
        print(f"Protocol: {protocol}")
        file_to_write.write(f"Protocol: {protocol}\n")

        qbuf = get_desired_attribute(report, "'qbuf': ")
        if qbuf is not None:
            qbuf_decoded = ""
            try:
                qbuf_decoded = str(dns.message.from_wire(base64.b64decode(qbuf)))
            except Exception:
                print(f"Qbuf error: {qbuf}")
                file_to_write.write(f"Qbuf error: {qbuf}\n")
                print(f"Skipping packet")
                continue

            print(f"\nQBUF:\n{qbuf_decoded}")
            file_to_write.write(f"\nQBUF:\n{qbuf_decoded}\n")
            qbuf_rcode = extract_attribute_from_buf("rcode ", qbuf_decoded)
            qbuf_opcode = extract_attribute_from_buf("opcode ", qbuf_decoded)
            qbuf_question = extract_field_from_buf(';QUESTION', qbuf_decoded)
            # print(f"qbuf_question: {qbuf_question}")

            qbuf_query_name = extract_query_name(qbuf_question).lower()
            # print(f"qbuf_query_name: {qbuf_query_name}")

            # Count duplicates
            if qbuf_query_name in query_names_with_pl["query_names_0"]:
                print("  Duplicate query name")
                file_to_write.write("  Duplicate query name\n")
                duplicate_query_count_with_pl["duplicate_query_count_0"] += 1

            if qbuf_query_name != "" and qbuf_query_name not in query_names_with_pl["query_names_0"]:
                query_names_with_pl["query_names_0"].append(qbuf_query_name)

        if "'result':" in report:

            count_of_answers_with_pl["count_of_answers_0"] += 1

            # print(f"Packet has result")
            result_json = report.split("'result':")[1]
            # print(f"result_json: {result_json}")
            response_time = float(get_desired_attribute(report, "'rt': "))
            print(f"Response time: {response_time} (ms) -> {response_time/1000.0} (s)")
            file_to_write.write(f"Response time: {response_time} (ms) -> {response_time/1000.0} (s)\n")

            latencies_with_pl["latency_0"].append(response_time / 1000.0)

            abuf = get_desired_attribute(report, "'abuf': ")
            if abuf is not None:
                abuf_decoded = ""
                try:
                    abuf_decoded = str(dns.message.from_wire(base64.b64decode(abuf)))
                except Exception:
                    print(f"Abuf error: {abuf}")
                    file_to_write.write(f"Abuf error: {abuf}\n")
                    print(f"Skipping packet")
                    continue
                print(f"\nABUF:\n{abuf_decoded}")
                file_to_write.write(f"\nABUF:\n{abuf_decoded}\n")
                abuf_opcode = extract_attribute_from_buf("opcode ", abuf_decoded)
                abuf_rcode = extract_attribute_from_buf("rcode ", abuf_decoded)

                if abuf_rcode == "SERVFAIL":
                    servfail_count_with_pl["servfail_count_0"] += 1

                abuf_question = extract_field_from_buf(';QUESTION', abuf_decoded)
                # print(f"abuf_question: {abuf_question}")

                abuf_answer = extract_field_from_buf(';ANSWER', abuf_decoded)
                # print(f"abuf_question: {abuf_question}")

                abuf_query_name = extract_query_name(abuf_question).lower()

                # Count duplicates
                if abuf_query_name in answer_names_with_pl["answer_names_0"]:
                    print("  Duplicate Answer")
                    file_to_write.write("  Duplicate Answer\n")
                    duplicate_answer_count_with_pl["duplicate_answer_count_0"] += 1

                # print(f"abuf_query_name: {abuf_query_name}")
                if abuf_query_name != "" and abuf_query_name not in answer_names_with_pl[
                    "answer_names_0"]:
                    answer_names_with_pl["answer_names_0"].append(abuf_query_name)

        report_count += 1

    # print(f"\n")
    line_count += 1

file.close()
file_to_write.close()
#
# index = 0
# for latencies_of_pl in latencies_with_pl:
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of {pl_rate} Packetloss rate latencies: {len(latencies_of_pl)}")
#     index += 1
#
# print(f"\n")
#
# index = 0
# for answer_names_of_pl in answer_names_with_pl:
#     values = list(answer_names_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of answer_names_of_pl {pl_rate}: {len(values)}")
#     # index2 = 0
#     # for query in values:
#     #     print(f"  {index2}. Query: {query}")
#     #     index2 += 1
#     index += 1
#
# index = 0
# for query_names_of_pl in query_names_with_pl:
#     values = list(query_names_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of query_names_of_pl {pl_rate}: {len(values)}")
#     # index2 = 0
#     # for query in values:
#     #     print(f"  {index2}. Query: {query}")
#     #     index2 += 1
#     index += 1
#
# print(f"\n")
#
# index = 0
# for elem in duplicate_answer_count_with_pl:
#     value = list(duplicate_answer_count_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of duplicate answer count for PL {pl_rate}: {value}")
#     index += 1
#
# print(f"\n")
#
# index = 0
# for elem in duplicate_query_count_with_pl:
#     value = list(duplicate_query_count_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of duplicate query count for PL {pl_rate}: {value}")
#     index += 1
#
# index = 0
# for elem in servfail_count_with_pl:
#     value = list(servfail_count_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of servfail_count_with_pl for PL {pl_rate}: {value}")
#     index += 1
#
# index = 0
# for elem in count_of_answers_with_pl:
#     value = list(count_of_answers_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of count_of_answers_with_pl for PL {pl_rate}: {value}")
#     index += 1

# create_overall_latency_violin_plot(directory_name_of_plots, "ripe-atlas", bottom_limit, upper_limit, False)
# create_overall_box_plot(directory_name_of_plots, "ripe-atlas", bottom_limit, upper_limit, False)
# create_overall_bar_plot_failure(directory_name_of_plots, "ripe-atlas")
