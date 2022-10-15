import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import json
import re
import os

# The packetloss rates that are simulated in the experiment
packetloss_rates = [40, 60, 70, 80, 90, 95]

# Create the dictionary to store latency measurements for each packetloss rate.  latency_0
latencyData = {"latencies_pl40": [], "latencies_pl60": [], "latencies_pl70": [],
               "latencies_pl80": [], "latencies_pl90": [], "latencies_pl95": []}

# The prefix of the keys in latencyData
latencyDataString = "latencies"

# Count the failure rates for each packetloss configuration
failureData = {"failures_pl40": [], "failures_pl60": [], "failures_pl70": [],
               "failures_pl80": [], "failures_pl90": [], "failures_pl95": []}

# The prefix of the keys in failureData
failureDataString = "failures"

# Answer == "1" -> DNS Response message
# Answer == "0" -> DNS Query
answerCountData = {"answers_pl40": [], "answers_pl60": [], "answers_pl70": [],
                   "answers_pl80": [], "answers_pl90": [], "answers_pl95": []}

# The prefix of the keys in answerCountData
answerCountDataString = "answers"

# Old retransmission_data
retransmissionData = {"retransmissions_pl40": 0,
                      "retransmissions_pl60": 0, "retransmissions_pl70": 0, "retransmissions_pl80": 0,
                      "retransmissions_pl90": 0, "retransmissions_pl95": 0}

# The prefix of the keys in retransmissionData
retransmissionDataString = "retransmissions"

# all_packets_pl,  packet_pl0
allPacketsOfPL = {"packets_pl40": [],
                  "packets_pl60": [], "packets_pl70": [], "packets_pl80": [],
                  "packets_pl90": [], "packets_pl95": []}

# The prefix of the keys in allPacketsOfPL
allPacketsOfPLString = "packets"

# All the packets in all of the JSON files
all_packets = []
allPacketsOfClient = []  # client  # all_packets_1
allPacketsOfAuth = []  # auth  # all_packets_2

failure_rate_data = {"failure_rate_pl40": [],
                     "failure_rate_pl60": [], "failure_rate_pl70": [], "failure_rate_pl80": [],
                     "failure_rate_pl90": [], "failure_rate_pl95": []}

# The prefix of the keys in allPacketsOfPL
failure_rate_dataString = "failure_rate"

retransmission_counts_for_all_pl = {
    "retransmissions_40": [],
    "retransmissions_60": [], "retransmissions_70": [], "retransmissions_80": [],
    "retransmissions_90": [], "retransmissions_95": [],
}

# If you already calculated the latency/retransmission/failure for a query name and
# there were multiple duplicate queries and maybe duplicate answers for that exact
# query name, you should only calculate the latency once, to avoid calculating it
# multiple times, store the query names you calculated here to mark them
calculated_queries = []
calculated_latency_queries = []
calculated_retransmission_queries = []
calculated_failure_queries = []


# Returns the key string of the given data from the index
# data_string can be: latencyDataString, failureDataString, answerCountDataString,
# retransmissionDataString or allPacketsOfPLString.
# Example: Input = latencyDataString, 0 -> Output = "packetloss_pl0"
# Example: Input = failureDataString, 11 -> Output = "failures_pl95"
def get_data_key_from_index(data_string, index):
    packetloss_rate = str(packetloss_rates[index])
    return data_string + "_pl" + packetloss_rate


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


# Set the nth element (list) of the given dictionary
def reset_multi_dict_to_item(dictionary, item):
    max_op_index = 18
    max_pl_index = 12
    all_keys = list(dictionary.keys())
    for x in range(max_op_index):
        for y in range(max_pl_index):
            pl_rate_key = list(dictionary[all_keys[x]].keys())[y]
            dictionary[all_keys[x]][pl_rate_key] = item


# Reset all the values (lists) of the given dictionary
def reset_values_of_dict_to_zero(dictionary):
    all_keys = list(dictionary.keys())
    for key in all_keys:
        dictionary[key] = 0


# Show all the contents of the given dictionary
def show_all_data_of_dict(dictionary):
    print(f"Printing the content of dictionary:")

    all_keys = list(dictionary.keys())
    all_values = list(dictionary.values())
    length = len(all_keys)

    for i in range(length):
        print(f"  {all_keys[i]}: {all_values[i]}")


# If a list of the dictionary is empty, fill it with dummy value
def add_dummy_value_to_empty_dictionary_list_value(dictionary, dummy_value):
    # If a list of a dictionary is empty (because all the packets were dropped and
    # there were no packets with latency), plotting gives an error
    # Spot the empty lists, add a dummy value

    length_of_lists = len(get_values_of_dict(dictionary))
    # print(f"Length of lists = {length_of_lists}")

    for i in range(length_of_lists):
        i_th_value_of_dict = get_nth_value_of_dict(dictionary, i)
        if type(i_th_value_of_dict) is list:
            # print("is a list")
            if len(i_th_value_of_dict) == 0:
                print(f"0 Length found at index : {i}")
                set_nth_value_of_dict(dictionary, i, [dummy_value])
        else:
            # print("not a list")
            # TODO: Wrong, sets the normal integer values to 0
            set_nth_value_of_dict(dictionary, i, dummy_value)


# Get the packetloss string of the json packet
def get_packetloss_rate_of_packet(packet):
    query_name = extract_query_name_from_packet(packet)
    if query_name is not None:
        query_ab_pl_rate = query_name.split("-")[5]
        pl_rate = query_ab_pl_rate.split(".")[0]
        return pl_rate  # <ipnr>-<ipnr>-<ipnr>-<ipnr>-<counter>-pl*.
    else:
        return None


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

    # Print on the plot if the plot is for client or auth (user variable)
    user = file_name_prefix.split("_")[0]
    ax.set_title(f"Response Failure Rate for {user}")

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
    for i in range(len(get_values_of_dict(latencyData))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(get_values_of_dict(latencyData)[i])) + "\n"
    text = ax.annotate(data_count_string, xy=(.5, .5), xytext=(x_axis_for_text, y_axis_for_text), color='red')
    # Make it transparent
    text.set_alpha(.4)
    # plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Creating plot
    ax.boxplot(get_values_of_dict(latencyData), positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95], widths=4.4)

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
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    # Print on the plot if the plot is for client or auth (user variable)
    user = file_name_prefix.split("_")[0]
    ax.set_title(f"Response Failure Rate for {user}")

    # IF a packetloss latency list is empty, add negative dummy value so that violinplot doesn't crash
    # Since the plots bottom limit is, it won't be visible in graph
    # But when you add this, you need to subtract it from the count on the plot text
    global latencyData
    all_pl_packets = get_values_of_dict(latencyData)
    index_of_dummy = 0
    dummy_indexes = []
    for packets_with_pl in all_pl_packets:
        # print(f"  packet: {packet}")
        if len(packets_with_pl) == 0:
            append_item_to_nth_value_of_dict(latencyData, index_of_dummy, 0)
            # packets_with_pl.append(float(-0.2))
            dummy_indexes.append(index_of_dummy)
        index_of_dummy += 1

    if log_scale:
        ax.set_yscale('log', base=2)

    # Create and save Violinplot
    bp = ax.violinplot(dataset=get_values_of_dict(latencyData), showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    if len(dummy_indexes) > 0:
        for i in range(len(get_values_of_dict(latencyData))):
            # if the index length was 0 so that we added a dummy value, subtract it from the count
            if i in dummy_indexes:
                data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
                    len(get_values_of_dict(latencyData)[i]) - 1) + "\n"
            # Index was not 0, write the actual length
            else:
                data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
                    len(get_values_of_dict(latencyData)[i])) + "\n"
    else:
        for i in range(len(get_values_of_dict(latencyData))):
            data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
                len(get_values_of_dict(latencyData)[i])) + "\n"
    text = ax.annotate(data_count_string, xy=(.5, .5), xytext=(x_axis_for_text, y_axis_for_text), color='red')
    # Make it transparent
    text.set_alpha(.5)
    # plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')

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
def create_overall_bar_plot_failure(directory_name, file_name, bottom_limit, upper_limit):
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
        # print(f"index: {index}")
        # print(f"Data: {failure_rate_data[index]}")
        fail_count = 0
        # Loop all the rcodes of the current packetloss rate
        for x in range(len(get_values_of_dict(failure_rate_data)[index])):
            if get_values_of_dict(failure_rate_data)[index][x] is not None and \
                    get_values_of_dict(failure_rate_data)[index][x] != "0":
                fail_count += 1
        # print(f"Fail count: {fail_count}")
        if fail_count != 0:
            # Divide by 900 because we send 900 queries from client pro packetloss config (18 Resolver * 50 counter),
            # when you filter by an IP, you need to adjust the query_count_per_pl_rate like so:
            query_count_per_pl_rate = 900 - (0 * 50)
            # print(f"query_count_per_pl_rate: {query_count_per_pl_rate}")
            # Label auf plot
            failure_counts[index] = fail_count

            failure_rate_data_dict[str(current_packetloss_rate)] = (fail_count / query_count_per_pl_rate) * 100
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
    for i in range(len(get_values_of_dict(latencyData))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            failure_counts[i]) + "\n"
    text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')
    text.set_alpha(0.5)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Response Failure Rate")
    plt.title(f"Overall Response Failure Rate")
    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name + '_barPlotResponseFailureRate.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created bar plot: {file_name}")
    # Clear plots
    plt.cla()
    plt.close()


# Create bar plot to show the DNS restransmission counts
def create_overall_bar_plot_total_retransmission(directory_name, file_name, bottom_limit, upper_limit,
                                                 use_limits=False):
    print(f" Creating total retransmission plot: {file_name}")
    print(f"   Inside the folder: {directory_name}")

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    failure_rate_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                              '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    retransmis_values = get_values_of_dict(retransmissionData)
    print(f"  retransmissionData values= {retransmis_values}")

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary
    max_transmission_count_for_upper_limit = 0
    index = 0
    for current_packetloss_rate in packetloss_rates:
        current_retransmission_data = get_values_of_dict(retransmissionData)[index]
        if current_retransmission_data != 0:
            failure_rate_data_dict[str(current_packetloss_rate)] = current_retransmission_data
            if max_transmission_count_for_upper_limit < current_retransmission_data:
                max_transmission_count_for_upper_limit = current_retransmission_data
        else:
            failure_rate_data_dict[str(current_packetloss_rate)] = 0
        index = index + 1

    keys = list(failure_rate_data_dict.keys())
    values = list(failure_rate_data_dict.values())
    print(f"Retransmission rates: {keys}")
    # f.write(f"Failure rates: {keys}\n")
    print(f"Retransmission counts: {values}")
    # f.write(f"Failure ratio: {values}\n")

    plt.figure(figsize=(10, 5))
    # fig = plt.figure(figsize=(10, 5))

    # creating the bar plot
    plt.bar(failure_rates, values, color='blue', width=4)

    # Adding text inside the plot
    data_count_string = ""
    for i in range(len(get_values_of_dict(latencyData))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            failure_rate_data_dict[str(packetloss_rates[i])]) + "\n"
    text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')
    text.set_alpha(0.5)

    # Set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("Total DNS Retransmission Count")
    plt.title(f"Overall Retransmission Count")

    # If there is no data to plot, the y-axis will show the negative values
    if max_transmission_count_for_upper_limit != 0:
        plt.ylim(bottom=0, top=max_transmission_count_for_upper_limit)
    else:
        plt.ylim(bottom=0)

    # Save plot as png
    plt.savefig(directory_name + "/" + (file_name + '_barPlotTotalRetransmissionCount.png'), bbox_inches='tight')
    # Show plot
    # plt.show()
    print(f" Created total retransmission plot: {file_name}")
    # f.write(f" Created retransmission plot: {file_name}\n")
    # Clear plots
    plt.cla()
    plt.close()


# Create bar plot to show the DNS restransmission counts
def create_overall_violin_plot_retransmission(directory_name, file_name):
    print(f" Creating retransmission violin plot: {file_name}")
    print(f"   Inside the folder: {directory_name}")

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    # Set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Retransmissions for each query")
    user = file_name.split("_")[0]
    plt.title(f"DNS Retransmission for {user}")

    # IF a packetloss latency list is empty, add negative dummy value so that violinplot doesn't crash
    # Since the plots bottom limit is, it won't be visible in graph
    # But when you add this, you need to subtract it from the count on the plot text

    global retransmission_counts_for_all_pl
    all_retransmission_counts_lists = get_values_of_dict(retransmission_counts_for_all_pl)
    # add_dummy_value_to_empty_dictionary_list_value(retransmissionData, 0)

    # Add dummy value if a list is empty
    index_of_dummy = 0
    dummy_indexes = []

    # Fill empty lists with dummy value 0
    for pl_list_with_retransmission_counts in all_retransmission_counts_lists:
        # print(f"  packet: {packet}")
        if len(pl_list_with_retransmission_counts) == 0:
            append_item_to_nth_value_of_dict(retransmission_counts_for_all_pl, index_of_dummy, 0)
            # packets_with_pl.append(float(-0.2))
            dummy_indexes.append(index_of_dummy)
        index_of_dummy += 1

    # Debug
    # retransmission_values = get_values_of_dict(retransmission_counts_for_all_pl)
    # print(f"Retransmission values = {str(retransmission_values)}")

    # Create and save Violinplot
    bp = ax.violinplot(dataset=get_values_of_dict(retransmission_counts_for_all_pl), showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    if len(dummy_indexes) > 0:
        for i in range(len(get_values_of_dict(retransmission_counts_for_all_pl))):
            # if the index length was 0 so that we added a dummy value, subtract it from the count
            if i in dummy_indexes:
                data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
                    len(get_values_of_dict(retransmission_counts_for_all_pl)[i]) - 1) + "\n"
            # Index was not 0, write the actual length
            else:
                data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
                    len(get_values_of_dict(retransmission_counts_for_all_pl)[i])) + "\n"
    else:
        for i in range(len(get_values_of_dict(retransmission_counts_for_all_pl))):
            data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
                len(get_values_of_dict(retransmission_counts_for_all_pl)[i])) + "\n"
    text = ax.annotate(data_count_string, xy=(.5, .5), xytext=(x_axis_for_text, y_axis_for_text), color='red')
    # Make it transparent
    text.set_alpha(.5)
    # plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')

    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')

    plt.ylim(bottom=0)

    # Add legend for mean and median
    blue_line = mlines.Line2D([], [], color='blue', marker='',
                              markersize=15, label='mean')
    red_line = mlines.Line2D([], [], color='red', marker='',
                             markersize=15, label='median')
    ax.legend(handles=[blue_line, red_line], loc='upper left')

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name + '_violinPlotRetransmission.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created retransmission violin plot: {file_name}")
    # Clear plots
    plt.cla()
    plt.close()


# New functions from each resolver script
# Find and return the packet with the specified frame number
def get_packet_by_frame_no(frame_no):
    for packet in all_packets:
        if packet.frame_no == frame_no:
            return packet
    # If the frame number doesn't exist, return None
    return None


# Get the relative frame time of packet.
# The time since the first packet is sent.
def get_frame_time_relative_of_packet(packet):
    return float(packet['_source']['layers']["frame"]["frame.time_relative"])


# Warning: Slow run time
def find_all_packets_with_query_name(query_name):
    # print(f"    find_all(): Returning all packets with query name: {query_name}")
    # Check the packetloss rate of the query name
    list_to_search = []
    global allPacketsOfPL
    if "pl0" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 0)
    elif "pl10" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 1)
    elif "pl20" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 2)
    elif "pl30" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 3)
    elif "pl40" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 4)
    elif "pl50" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 5)
    elif "pl60" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 6)
    elif "pl70" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 7)
    elif "pl80" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 8)
    elif "pl85" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 9)
    elif "pl90" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 10)
    elif "pl95" in query_name:
        list_to_search = get_nth_value_of_dict(allPacketsOfPL, 11)

    packets_with_query_name = []
    for packet in list_to_search:
        if extract_query_name_from_packet(packet) == query_name:
            # print(f"      Match: {query_name}")
            # print(f"      Frame time of Match: {get_frame_time_relative_of_packet(packet)}")
            # print(f"        Added to list")
            packets_with_query_name.append(packet)

    return packets_with_query_name


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


# Used to find the original (first) query among the duplicate queries
def find_lowest_relative_frame_time_of_packets(packet_list):
    frame_time_list = []
    for packet in packet_list:
        frame_time_list.append(float(get_frame_time_relative_of_packet(packet)))
    return min(frame_time_list)


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


# Find and return the packet with the specified frame number
def get_packet_by_frame_no_from_list(frame_no, packet_list):
    for packet in packet_list:
        if int(packet["_source"]["layers"]["frame"]["frame.number"]) == int(frame_no):
            return packet
    # If the frame number doesn't exist, return None
    print(f"Frame number {frame_no} doesn't exits!")
    return None


def find_lowest_frame_no(packet_list):
    frame_numbers = []
    for packet in packet_list:
        number = int(packet["_source"]["layers"]["frame"]["frame.number"])
        frame_numbers.append(number)
    return min(frame_numbers)


# Latency (between first query and answer) algorithm 2
# "Zeit bis zur ersten Antwort (unabhängig von RCODE)"
# if packet has dns.time, get the packets query name, if there are more than 2 (query + answer) queries with that query name,
# than you have duplicates, find the first query (using frame relative time of all of the queries),
# calculate the new latency with: dns.time + (time between first query and last query) = dns.time + (rel(last)-rel(first))
def calculate_latency_of_packet(current_packet, file_name, rcode_filter):
    query_name_of_packet = extract_query_name_from_packet(current_packet)

    debug = False

    # If already calculated, skip
    if query_name_of_packet is not None:
        if query_name_of_packet in calculated_queries:
            if debug:
                print(f"    !! You already calculated latency for: {query_name_of_packet}")
                # f.write(f"    !! You already calculated latency for: {query_name_of_packet}\n")
            return None

    packets = find_all_packets_with_query_name(query_name_of_packet)
    responses = find_the_response_packets(packets, file_name)

    # Only valid answer latency calculation -> ignore servfails
    if "valid" == rcode_filter:
        # If all the responses to the query has RCODE 2, ignore the packet
        responses_with_rcode_0 = []
        responses_with_rcode_2 = []
        for response in responses:
            if get_rcode_of_packet(response) == "0":
                responses_with_rcode_0.append(response)
            if get_rcode_of_packet(response) == "2":
                responses_with_rcode_2.append(response)
        # Ignore if no Response with RCODE 0, and response(s) with RCODE 2
        if len(responses_with_rcode_0) == 0 and len(responses_with_rcode_2) != 0:
            calculated_queries.append(query_name_of_packet)
            return None
    # Only servfail latency calculation -> ignore normal valid responses
    elif "servfails" == rcode_filter:
        # If any response to the query has a rcode 0, ignore this packet
        # print(f" SERVFAIL AS FILTER SELECTED FOR: {query_name_of_packet}")
        responses_with_rcode_0 = []
        for response in responses:
            if get_rcode_of_packet(response) == "0":
                responses_with_rcode_0.append(response)
        if len(responses_with_rcode_0) > 0:
            calculated_queries.append(query_name_of_packet)
            # print(f"   BUT THERE WAS A VALID PACKET FOR: {query_name_of_packet}")
            return None
        # print(f"   NO VALID RESPONSE FOR: {query_name_of_packet}")
        # print(f"   CONTINUE CALCULATION OF: {query_name_of_packet}")
    # Get both valid responses and servfails in the latency plots
    # Continue with the calculation because we filtered others
    elif "valid+servfails" == rcode_filter:
        pass

    # Filter the source and destination Addresses for client
    if file_name == "client":
        # debug = True
        src_match = src_ip_match(current_packet, client_only_source_ips)
        dst_match = dst_ip_match(current_packet, client_only_dest_ips)
        if not src_match and not dst_match:  # if src_match or dst_match -> Calculate latency of packet
            # print(" Source-Destination Ip not match: None!")
            return None

    latency = 0

    # Get the dns.time if it exists, packets with dns.time are Responses with either No error or Servfail
    # All query packets are ignored after here
    if 'dns.time' in current_packet['_source']['layers']['dns']:
        # and "Answers" in current_packet['_source']['layers']['dns']:  # New and condition
        dns_time = float(current_packet['_source']['layers']['dns']['dns.time'])
        latency = dns_time
        # print(f"   DNS.TIME SET: {latency}")

    packets = find_all_packets_with_query_name(query_name_of_packet)
    # print(f"   LENGTH OF ALL PACKETS WITH QUERYNAME: {len(packets)}")

    # for p in packets:
    #     print(f"Frame times of packets: {get_frame_time_relative_of_packet(p)}")

    responses = find_the_response_packets(packets, file_name)
    # print(f"   LENGTH OF ALL RESPONSES: {len(responses)}")
    queries = find_the_query_packets(packets, file_name)
    # print(f"   LENGTH OF ALL QUERIES: {len(queries)}")

    # latency = first_term(answer packet's relate frame time) - last_term(query packet's relate frame time)
    first_term = 0
    last_term = 0
    # latency = -999

    # Find the first ever query that was sent for this query name
    lowest_frame_no_of_queries = find_lowest_frame_no(queries)
    query_packet_with_lowest_frame_no = get_packet_by_frame_no_from_list(lowest_frame_no_of_queries, queries)
    # get the relative frame time of packet
    rel_fr_time_of_first_query = get_frame_time_relative_of_packet(query_packet_with_lowest_frame_no)

    last_term = rel_fr_time_of_first_query

    # Cases where latency is undefined
    # There was no response
    # Note: code shouldn't reach here bcs queries can't have dns.time
    if len(responses) == 0:
        calculated_queries.append(query_name_of_packet)
        # print(f"   NOT A SINGLE RESPONSE FOR: {query_name_of_packet}")
        if debug:
            print(f"    Query has no answers: {query_name_of_packet}")
            print(f"      (No latency calculation)")
        return None
    # There exist response to the query packet
    elif len(responses) > 0:
        # print(f"   THERE WERE RESPONSES FOR: {query_name_of_packet}")
        # Check if responses are sent with multiple source IP's, but no handling for this situation
        response_src_ips = get_unique_src_ips_of_packets(responses)
        response_ip_count = len(response_src_ips)
        if response_ip_count > 1:
            print(f"    Responses are sent from different source IP's ({response_ip_count})")
            print(f"      Query: {query_name_of_packet}")
            index = 0
            for ip in response_src_ips:
                print(f"        {index}. IP: {ip}")
                index += 1

        # Split responses by their RCODES
        responses_with_rcode_0 = []
        responses_with_rcode_2 = []
        for response in responses:
            if get_rcode_of_packet(response) == "0":
                responses_with_rcode_0.append(response)
            if get_rcode_of_packet(response) == "2":
                responses_with_rcode_2.append(response)
        # Responses are only ServFails
        # Get the latency between first query and first ServFail
        if len(responses_with_rcode_0) == 0 and len(responses_with_rcode_2) != 0:
            # print(f"   ALL RESPONSES WERE SERVFAILS FOR: {query_name_of_packet}")
            lowest_frame_no_of_responses_with_2 = find_lowest_frame_no(responses_with_rcode_2)
            response_packet_2_with_lowest_frame_no = get_packet_by_frame_no_from_list(
                lowest_frame_no_of_responses_with_2,
                responses_with_rcode_2)
            # get the relative frame time of packet
            rel_fr_time_of_first_response = get_frame_time_relative_of_packet(
                response_packet_2_with_lowest_frame_no)

            first_term = rel_fr_time_of_first_response
            latency = first_term - last_term

            # Mark the query name as calculated (Calculated time between first servfail and first query)
            calculated_queries.append(query_name_of_packet)

            if latency <= 0:
                print(f"  !! Negative Latency for:{query_name_of_packet}")
                print(f"    !! Latency calculation: {first_term} - {last_term}")
            # print(f"   RETURNED LATENCY {latency} FOR: {query_name_of_packet}")
            return latency

        # All Responses are valid (No Errors)
        # Get the latency between first query and first (valid) answer
        elif len(responses_with_rcode_0) != 0 and len(responses_with_rcode_2) == 0:
            # print(f"   ALL RESPONSES WERE VALID FOR: {query_name_of_packet}")
            lowest_frame_no_of_responses_with_0 = find_lowest_frame_no(responses_with_rcode_0)
            response_packet_0_with_lowest_frame_no = get_packet_by_frame_no_from_list(
                lowest_frame_no_of_responses_with_0,
                responses_with_rcode_0)
            # get the relative frame time of packet
            rel_fr_time_of_first_response = get_frame_time_relative_of_packet(
                response_packet_0_with_lowest_frame_no)

            first_term = rel_fr_time_of_first_response
            latency = first_term - last_term

            calculated_queries.append(query_name_of_packet)

            if latency <= 0:
                print(f"  !! Negative Latency for:{query_name_of_packet}")
                print(f"    !! Latency calculation: {first_term} - {last_term}")
                print(f"    !! Latency = {latency}")
                print(f"    lowest_frame_no_of_responses_with_0 = {lowest_frame_no_of_responses_with_0}")
                print(f"    lowest_frame_no_of_queries: {lowest_frame_no_of_queries}")
                print(f"    rel_fr_time_of_first_query: {rel_fr_time_of_first_query}")
                print(f"    query_packet_with_lowest_frame_no: {query_packet_with_lowest_frame_no}")
                print(f"    response_packet_0_with_lowest_frame_no = {response_packet_0_with_lowest_frame_no}")
                print(f"    Responses: {responses}")
            # print(f"   RETURNED LATENCY {latency} FOR: {query_name_of_packet}")
            return latency
        # There are ServFails and also valid answers
        # Get the latency between first query and first valid answer
        elif len(responses_with_rcode_0) != 0 and len(responses_with_rcode_2) != 0:
            # print(f"   THERE ARE BOTH SERVFAIL AND VALID RESPONSES FOR: {query_name_of_packet}")
            # examine all the response's RCODES, get the ones with RCODE = 0, get the first of them.
            responses_with_rcode_0 = []
            for response in responses:
                if get_rcode_of_packet(response) == "0":
                    responses_with_rcode_0.append(response)
            if len(responses_with_rcode_0) > 0:
                lowest_frame_no_of_responses_with_0 = find_lowest_frame_no(responses_with_rcode_0)
                response_packet_0_with_lowest_frame_no = get_packet_by_frame_no_from_list(
                    lowest_frame_no_of_responses_with_0,
                    responses)
                # get the relative frame time of packet
                rel_fr_time_of_first_response = get_frame_time_relative_of_packet(
                    response_packet_0_with_lowest_frame_no)

                first_term = rel_fr_time_of_first_response

            calculated_queries.append(query_name_of_packet)
            latency = first_term - last_term

            if latency <= 0:
                print(f"  !! Negative Latency for:{query_name_of_packet}")
                print(f"    !! Latency calculation: {first_term} - {last_term}")
            # print(f"   RETURNED LATENCY {latency} FOR: {query_name_of_packet}")
            return latency


# Failure rate of client: Count of rcode != 0 for each query name + unanswered unique query count
# Count as fail if no answer with RCODE != 0
def calculate_failure_rate_of_packet(current_packet, packetloss_index, file_name, rcode_filter):
    # If already calculated, skip
    query_name_of_packet = extract_query_name_from_packet(current_packet)

    if query_name_of_packet is not None:
        if query_name_of_packet in calculated_failure_queries:
            # if debug:
            #     print(f"  Already calculated: {query_name_of_packet}")
            return

    packets = find_all_packets_with_query_name(query_name_of_packet)
    responses = find_the_response_packets(packets, file_name)

    # Count unanswered query AND servfails as fail
    if "valid+servfails" == rcode_filter:
        # No need to filter, continue calculating
        pass
    # Count only servfails as fail
    elif "valid" == rcode_filter:
        # No response packet was found -> Query unanswered but dont calculate this as failure
        if len(responses) == 0:
            calculated_failure_queries.append(query_name_of_packet)
            return
        # If any response to the query has a rcode 0, ignore this packet
        responses_with_rcode_0 = []
        for response in responses:
            if get_rcode_of_packet(response) == "0":
                responses_with_rcode_0.append(response)
        if len(responses_with_rcode_0) > 0:
            calculated_failure_queries.append(query_name_of_packet)
            return
    # Count only unanswered queries as fails (and not servfails)
    elif "servfails" == rcode_filter:
        # There was a response to the packet, ignore it
        if len(responses) != 0:
            calculated_failure_queries.append(query_name_of_packet)
            return

    # Filter the source and destination Addresses for client
    if file_name == "client":
        src_match = src_ip_match(current_packet, client_only_source_ips)
        dst_match = dst_ip_match(current_packet, client_only_dest_ips)
        if not src_match and not dst_match:  # if src_match or dst_match -> Calculate latency of packet
            return

    rcode_is_error = False
    current_rcode = "-"

    # If the packet is a response with no error, don't examine it, count as success
    if 'dns.flags.rcode' in current_packet['_source']['layers']['dns']['dns.flags_tree']:
        current_rcode = current_packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
        if current_rcode == "0":
            calculated_failure_queries.append(query_name_of_packet)

            # get_values_of_dict(failure_rate_data)[packetloss_index].append("0")
            append_item_to_nth_value_of_dict(failure_rate_data, packetloss_index, "0")
            return
        # If there is a response with error, count as failure
        else:  # current_rcode != "0"
            # if debug:
            #     print(f"    RCODE was not 0; set rcode_is_error to True: {query_name_of_packet}")
            #     print(f"    -> RCODE was {current_rcode} for {query_name_of_packet}")
            rcode_is_error = True
            # If this is the only answer, which has an error code, count as fail (below)
    # The packet is a query
    # Check if that packet is not answered
    packets = find_all_packets_with_query_name(query_name_of_packet)

    # DEBUG
    # for pac in packets:
    #     print(f"Query name: {extract_query_name_from_packet(pac)}")

    responses = find_the_response_packets(packets, file_name)
    responses_count = len(responses)
    # DEBUG
    # for resp in responses:
    #     print(f"Query name of responses: {extract_query_name_from_packet(resp)}")

    queries = find_the_query_packets(packets, file_name)
    queries_count = len(queries)

    # There was no response at all to the query, count as failure
    if responses_count == 0:
        # List of RCODES, an unanswered query results in appending a new error code
        # failure_rate_data[packetloss_index].append("2")
        append_item_to_nth_value_of_dict(failure_rate_data, packetloss_index, "2")

        # print(f"Incremented bcs no answer to {query_name_of_packet}")
        calculated_failure_queries.append(query_name_of_packet)

        # if debug:
        #     print(f"  Append 2 bcs not a single response found for: {query_name_of_packet}")
    # If this is the only answer, which has an error code, count as fail
    # But what if multiple error responses and not only one: Count as one
    elif responses_count >= 1:  # and rcode_is_error
        # examine all the response's RCODES, get the ones with RCODE = 0, get the first of them.
        responses_with_rcode_0 = []
        for response in responses:
            if get_rcode_of_packet(response) == "0":
                responses_with_rcode_0.append(response)

        # If there are successes among the responses, count the query as success
        if len(responses_with_rcode_0) > 0:
            # failure_rate_data[packetloss_index].append("0")
            append_item_to_nth_value_of_dict(failure_rate_data, packetloss_index, "0")
        # No success among responses -> failure
        else:
            # failure_rate_data[packetloss_index].append("2")
            append_item_to_nth_value_of_dict(failure_rate_data, packetloss_index, "2")

        # print(f"Incremented bcs only answer with error")
        calculated_failure_queries.append(query_name_of_packet)
        # if debug:
        #     print(f"  Append 2; rcode was error, response count >= 1: {query_name_of_packet}")
        #     print(f"      RCODE: {current_rcode} for {query_name_of_packet} (2)")
    else:
        # print(f"   Unknown branch for {query_name_of_packet}, rcode: {current_rcode}, response count: {
        # responses_count}, rcode_error = {rcode_is_error}")
        return


# Set the global list of retransmission data
def calculate_retransmission_of_query_overall(current_packet, packetloss_index, file_name):
    # print("Calculating retransmission of query")
    # Filter the source and destination Addresses for client
    if file_name == "client":
        src_match = src_ip_match(current_packet, client_only_source_ips)
        dst_match = dst_ip_match(current_packet, client_only_dest_ips)
        if not src_match and not dst_match:  # if src_match or dst_match -> Calculate latency of packet
            return

    # If already calculated, skip
    query_name_of_packet = extract_query_name_from_packet(current_packet)
    if query_name_of_packet is not None:
        if query_name_of_packet in calculated_retransmission_queries:
            return

    # Get all json packets that have the same query name
    # Slow runtime
    packets = find_all_packets_with_query_name(query_name_of_packet)

    # For the client, after getting all the packets with the query name
    # Filter again by the source IP
    packets_with_client_src_ip = []
    if file_name == "client":
        for packet in packets:
            if src_ip_match(packet, client_only_source_ips):
                packets_with_client_src_ip.append(packet)
        packets = packets_with_client_src_ip

    packets_with_auth_dst_ip = []
    # For auth, get all the queries, that has a destination IP of our auth server
    if file_name == "auth1":
        for packet in packets:
            if dst_ip_match(packet, auth_only_dest_ips):
                packets_with_auth_dst_ip.append(packet)
        packets = packets_with_auth_dst_ip

    responses = find_the_response_packets(packets, file_name)
    responses_count = len(responses)

    # Find all queries with that query name
    queries = find_the_query_packets(packets, file_name)
    queries_count = len(queries)

    global retransmissionData

    # When more than one query with same query name, they count as duplicate
    if queries_count > 1:

        calculated_retransmission_queries.append(query_name_of_packet)
        # -1 Because the original (first) query doesn't count as duplicate
        duplicate_query_count = queries_count - 1

        total_duplicate_result_to_set = get_values_of_dict(retransmissionData)[packetloss_index] + duplicate_query_count
        set_nth_value_of_dict(retransmissionData, packetloss_index, total_duplicate_result_to_set)

        return duplicate_query_count
    else:
        # queries_count == 1 or 0 -> No duplicate
        return


# Set the global list of retransmission data
def calculate_retransmission_of_query_resolver(current_packet, packetloss_index, file_name):
    # For client, get all the queries with source IP of client
    if file_name == "client":
        src_match = src_ip_match(current_packet, client_only_source_ips)
        # No need to filter for destination for client since each resolver has different IP
        # dst_match = dst_ip_match(current_packet, client_only_dest_ips)
        if not src_match:  # and not dst_match:  # if src_match or dst_match -> Calculate latency of packet
            return

    # For auth, get all the queries, that has a destination IP of our auth server
    if file_name == "auth":
        # No need to filter for source for auth since each resolver has different IP
        # src_match = src_ip_match(current_packet, client_only_source_ips)
        dst_match = dst_ip_match(current_packet, auth_only_dest_ips)
        if not dst_match:  # and not dst_match:  # if src_match or dst_match -> Calculate latency of packet
            return

    # If already calculated, skip
    query_name_of_packet = extract_query_name_from_packet(current_packet)
    debug = False
    if file_name == "client":
        debug = True

    if query_name_of_packet is not None:
        if query_name_of_packet in calculated_retransmission_queries:
            if debug:
                print(f"  Already calculated (skipping): {query_name_of_packet}")
            # f.write(f"  Already calculated (skipping): {query_name_of_packet}\n")
            return

    # Get all json packets that have the same query name
    # Slow runtime
    packets = find_all_packets_with_query_name(query_name_of_packet)

    # For the client, after getting all the packets with the query name
    # Filter again by the source IP
    packets_with_client_src_ip = []
    if file_name == "client":
        for packet in packets:
            if src_ip_match(packet, client_only_source_ips):
                packets_with_client_src_ip.append(packet)
        packets = packets_with_client_src_ip

    packets_with_auth_dst_ip = []
    # For auth, get all the queries, that has a destination IP of our auth server
    if file_name == "auth1":
        for packet in packets:
            if dst_ip_match(packet, auth_only_dest_ips):
                packets_with_auth_dst_ip.append(packet)
        packets = packets_with_auth_dst_ip

    responses = find_the_response_packets(packets, file_name)
    responses_count = len(responses)

    # Find all queries with that query name
    queries = find_the_query_packets(packets, file_name)
    queries_count = len(queries)

    global retransmissionData

    # When more than one query with same query name, they count as duplicate
    if queries_count > 1:
        if debug:
            print(f"  {file_name}: Multiple ({queries_count}) queries for: {query_name_of_packet}\n  "
                  f"Response count of it: {responses_count}\n  Packetloss index of it: {packetloss_index}")
            for query in queries:
                print(f"    Found query names: {extract_query_name_from_packet(query)}")
            for resp in responses:
                print(f"    Found response names: {extract_query_name_from_packet(resp)}")

        calculated_retransmission_queries.append(query_name_of_packet)
        # -1 Because the original (first) query doesn't count as duplicate
        duplicate_query_count = queries_count - 1

        total_duplicate_result_to_set = get_values_of_dict(retransmissionData)[packetloss_index] + duplicate_query_count
        set_nth_value_of_dict(retransmissionData, packetloss_index, total_duplicate_result_to_set)

        return duplicate_query_count
    else:
        # queries_count == 1 or 0 -> No duplicate
        return


# Read the JSON files for each captured packet and store all the dns packets
# into the global lists
# Filter the source and destination IP's of client for only the client packet capture
def initialize_packet_lists(file_prefix):
    index = 0
    # There are 12 packetloss rates and 12 JSON files for each packetloss rate
    for current_packetloss_rate in packetloss_rates:
        filename = file_prefix + "_" + str(current_packetloss_rate) + ".json"
        print(f"Reading file: {filename}")
        if not os.path.exists("./" + filename):
            print(f"File not found: {filename}")
            exit()
        # Read the measured latencies from json file
        file = open(filename)
        json_data = json.load(file)
        packet_count = len(json_data)
        print(f"  Number of packets in JSON file: {packet_count}")
        # print(f"  Current packetloss rate: {current_packetloss_rate}")

        # Examine all the packets in the JSON file
        for i in range(0, packet_count):

            # Check if the packet is a DNS packet
            if 'dns' in json_data[i]['_source']['layers']:
                # Check if the dns packet is generated by our experiment
                # by checking query syntax, filter dns packets that is not related to the experiment
                json_string = str(json_data[i]['_source']['layers']['dns']['Queries'])
                splitted_json1 = json_string.split("'dns.qry.name': ")
                splitted2 = str(splitted_json1[1])
                query_name = splitted2.split("'")[1]
                # print(f"Current query name: {query_name}")

                # DNS is case-insensitive, some resolvers might send queries with different cases,
                # use case insensitivity with re.IGNORECASE
                query_match = re.search(".*-.*-.*-.*-.*-pl.*.packetloss.syssec-research.mmci.uni-saarland.de",
                                        query_name, re.IGNORECASE)
                # Query doesn't match our experiment stucture, ignore it and
                # continue with the next packet
                if query_match is None:
                    # print(f"Skipping invalid domain name: {query_name}")
                    continue

                # Filter specific resolver packets by the query's IP Address
                splitted_domain = query_name.split("-")
                ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                                      splitted_domain[2] + "-" + splitted_domain[3]

                # Store the packet in various lists
                global allPacketsOfPL
                global all_packets
                append_item_to_nth_value_of_dict(allPacketsOfPL, index, json_data[i])
                all_packets.append(json_data[i])

                global allPacketsOfClient
                global allPacketsOfAuth
                if file_prefix == "client":
                    allPacketsOfClient.append(json_data[i])
                elif file_prefix == "auth1":
                    # print(f"Added: {query_name}")
                    allPacketsOfAuth.append(json_data[i])

        # Continue reading packets with the next packetloss rate JSON file
        index = index + 1


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


# Loop all the JSON packets and calculate their latencies/failure rate/retransmissions
def loop_all_packets_latencies_failures_retransmissions_overall(file_name, rcode_filter):
    print("Looping all packets to calculate latency/failure rate/retransmission count")
    print(f"  Filter: {rcode_filter}")
    global retransmission_counts_for_all_pl
    global allPacketsOfPL
    packets_list = get_values_of_dict(allPacketsOfPL)
    index = 0
    for packets in packets_list:
        print(f"  INDEX/Packetloss rate: {index}")
        for packet in packets:
            latency = calculate_latency_of_packet(packet, file_name, rcode_filter)
            calculate_failure_rate_of_packet(packet, index, file_name, rcode_filter)
            if latency is not None:
                append_item_to_nth_value_of_dict(latencyData, index, latency)

            current_retransmission_count = calculate_retransmission_of_query_overall(packet, index, file_name)
            # current_max = get_nth_value_of_dict(max_retransmission_count_for_all_pl, index)
            # if current_retransmission_count > current_max:
            #     set_nth_value_of_dict(max_retransmission_count_for_all_pl, index, current_retransmission_count)
            if current_retransmission_count is not None:
                # Store retransmission count in the global dictionary with all packetloss rates
                append_item_to_nth_value_of_dict(retransmission_counts_for_all_pl, index, current_retransmission_count)

        index += 1


# Clear all the global lists for the next JSON file
def clear_lists():
    global latencyData
    global allPacketsOfPL
    global all_packets

    reset_values_of_dict_to_empty_list(allPacketsOfPL)
    reset_values_of_dict_to_empty_list(latencyData)
    all_packets.clear()


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


# Clears all the lists etc. so that the next plotting
# doesn't read info from the previous json files
def prepare_for_next_iteration():
    global retransmission_counts_of_resolver_pl
    reset_multi_dict_to_item(retransmission_counts_of_resolver_pl, [])

    global retransmission_counts_for_all_pl
    reset_values_of_dict_to_empty_list(retransmission_counts_for_all_pl)

    global latencyData
    reset_values_of_dict_to_empty_list(latencyData)

    # Clear failure rate data:
    global failure_rate_data
    reset_values_of_dict_to_empty_list(failure_rate_data)

    # Reset the retransmissionData
    global retransmissionData
    reset_values_of_dict_to_zero(retransmissionData)

    calculated_retransmission_queries.clear()

    # Clear the calculated queries, latency queries, failure queries
    # so that they can be count for the next iteration
    global calculated_queries
    global calculated_latency_queries
    global calculated_failure_queries

    calculated_queries.clear()
    calculated_latency_queries.clear()
    calculated_failure_queries.clear()

    # Clear all the read JSON packets so that the next iteration can
    # store its packets in these global lists
    global allPacketsOfPL
    reset_values_of_dict_to_empty_list(allPacketsOfPL)

    global all_packets
    all_packets.clear()


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
    return None


def loop_all_packets_get_all_query_names(file_name):
    global client_query_names
    global auth_query_names
    global all_packets
    global allPacketsOfClient
    global allPacketsOfAuth

    if file_name == "client":
        print(f"       Filling client_query_names")
        for packet in allPacketsOfClient:
            qry_name = extract_query_name_from_packet(packet)
            pl_rate_of_pkt = get_packetloss_rate_of_packet(packet)
            pl_index = get_index_of_packetloss_rate(pl_rate_of_pkt)
            list_of_client_query_names_with_pl = get_nth_value_of_dict(client_query_names, pl_index)
            if qry_name not in list_of_client_query_names_with_pl:
                append_item_to_nth_value_of_dict(client_query_names, pl_index, qry_name)
    elif file_name == "auth1":
        print(f"       Filling auth_query_names")
        for packet in allPacketsOfAuth:
            qry_name = extract_query_name_from_packet(packet)
            pl_rate_of_pkt = get_packetloss_rate_of_packet(packet)
            pl_index = get_index_of_packetloss_rate(pl_rate_of_pkt)
            list_of_auth_query_names_with_pl = get_nth_value_of_dict(auth_query_names, pl_index)
            if qry_name not in list_of_auth_query_names_with_pl:
                append_item_to_nth_value_of_dict(auth_query_names, pl_index, qry_name)


# Create a bar plot showing how many queries are not sent to the auth server
def create_missing_query_bar_plot_for_auth(filter_name, directory_name):
    print(f" Creating missing query bar plot: {filter_name}")

    global client_query_names
    global auth_query_names

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    missing_query_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                               '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary
    index = 0
    for current_packetloss_rate in packetloss_rates:
        client_query_name_count_pl = len(get_nth_value_of_dict(client_query_names, index))
        auth_query_name_count_pl = len(get_nth_value_of_dict(auth_query_names, index))
        missing_query_count_on_auth_pl = client_query_name_count_pl - auth_query_name_count_pl
        missing_query_data_dict[str(current_packetloss_rate)] = missing_query_count_on_auth_pl

        index = index + 1

    keys = list(missing_query_data_dict.keys())
    values = list(missing_query_data_dict.values())

    print(f"Failure rates: {keys}")
    print(f"Missing data counts: {values}")

    plt.figure(figsize=(10, 5))

    # Adding text inside the plot
    # data_count_string = ""
    # for i in range(len(latencyData)):
    #    data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(?) + "\n"
    # text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')
    # text.set_alpha(0.5)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("Missing Query Count")
    plt.title(f"Missing Query Count For Authoritative Server")

    # creating the bar plot
    plt.bar(failure_rates, values, color='green', width=4)

    # save plot as png
    plt.savefig(directory_name + "/" + (filter_name + '_barPlotAuthMissingQuery.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created missing query bar plot: {filter_name}")
    # Clear plots
    plt.cla()
    plt.close()


# Clear the missing transmission lists for the next filtering option
def clear_missing_query_lists():
    global client_query_names
    reset_values_of_dict_to_empty_list(client_query_names)

    global auth_query_names
    reset_values_of_dict_to_empty_list(auth_query_names)


def get_unique_src_ips_of_packets(packet_list):
    src_ips_of_packets = []
    for packet in packet_list:
        ip_src_of_packet = packet['_source']['layers']["ip"]["ip.src"]
        if ip_src_of_packet not in src_ips_of_packets:
            src_ips_of_packets.append(ip_src_of_packet)
            # ip_dst_of_packet = packet['_source']['layers']["ip"]["ip.dst"]
    return src_ips_of_packets


def create_overall_plots_for_one_filter(rcode, bottom_limit_client, upper_limit_client,
                                        bottom_limit_auth, upper_limit_auth, directory_name):
    # Directory name to be created
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

    print(f" @@@@ Creating Resolver plots with Filter: {rcode} @@@@")
    x = 0
    for file_name in file_names:

        # Read and store all the matching JSON packets
        # with the applied filters
        initialize_packet_lists(file_name)

        # Loop all packets of client, get all the unique query names of the queries, store in
        # client_query_names, and also get all the unique query names of responses,
        # store in client_responses_query_names
        loop_all_packets_get_all_query_names(file_name)

        # file_name as argument because latency calculation needs to know if its client or auth capture
        # RCODE Filtering is here
        loop_all_packets_latencies_failures_retransmissions_overall(file_name, rcode)

        # Add the filtering options to the file name of the plots
        filter_names_on_filename = "_"

        # Set the lower-upper limits of the plots
        # Since the client and authoritative plots are very different,
        # set different limits for each

        if file_name != "client":
            bottom_limit = bottom_limit_auth
            upper_limit = upper_limit_auth
        else:
            bottom_limit = bottom_limit_client
            upper_limit = upper_limit_client

        # If rcode is applied, add the filter to the file name
        filter_names_on_filename += "_"
        filter_names_on_filename += str(rcode)

        if log_scale_y_axis:
            filter_names_on_filename += "_LogScaledY-"

        filter_names_on_filename += "Lim[" + str(bottom_limit) + "," + str(upper_limit) + "]"

        if file_name == "client":
            if len(client_only_source_ips) > 0:
                filter_names_on_filename += "_Src-IP"
                filter_names_on_filename += str(client_only_source_ips) + ""
                # for ip in client_only_source_ips:
                #     filter_names_on_filename += ip + "_"
            if len(client_only_dest_ips) > 0:
                filter_names_on_filename += "_Dst-IP"
                filter_names_on_filename += str(client_only_dest_ips) + ""
                # for ip in client_only_dest_ips:
                #     filter_names_on_filename += ip + "_"

        file_name += filter_names_on_filename

        # Create plots
        create_overall_box_plot(directory_name, file_name, bottom_limit, upper_limit,
                                log_scale_y_axis)
        create_overall_latency_violin_plot(directory_name, file_name, bottom_limit, upper_limit,
                                           log_scale_y_axis)
        create_overall_bar_plot_failure(directory_name, file_name, bottom_limit, 100)
        create_overall_bar_plot_total_retransmission(directory_name, file_name, bottom_limit, upper_limit,
                                                     use_limits=False)

        create_overall_violin_plot_retransmission(directory_name, file_name)

        prepare_for_next_iteration()
        x += 1

    filters = ""

    filters += ("_" + str(rcode))

    if filters == "":
        filters = "NoFilter"

    # Calculate, how many client queries are not redirected to the auth server
    # by the resolver suing client_query_names and auth_query_names
    # Create the plot only after client and auth packet initializations are done
    if x == 2:
        create_missing_query_bar_plot_for_auth(filters, directory_name)
        clear_missing_query_lists()


# List that store unique query names for each packetloss rate
# to find not redirected queries for auth server
client_query_names = {"client_query_names_pl40": [],
                      "client_query_names_pl60": [], "client_query_names_pl70": [], "client_query_names_pl80": [],
                      "client_query_names_pl90": [], "client_query_names_pl95": []}

auth_query_names = {"auth_query_names_pl40": [],
                    "auth_query_names_pl60": [], "auth_query_names_pl70": [], "auth_query_names_pl80": [],
                    "auth_query_names_pl90": [], "auth_query_names_pl95": []}

# File prefixes of JSON files
file_names = ["auth1"]

client_only_source_ips = []
client_only_dest_ips = []
auth_only_dest_ips = []

log_scale_y_axis = False

# Write text onto plots using this coordinates
x_axis_for_text = 0
y_axis_for_text = 0

# rcode, bottom_limit_client, upper_limit_client,
#                                         bottom_limit_auth, upper_limit_auth, filtered_resolvers, directory_name

# Filtering options
# rcodes_to_get = ["0", "2"]
# ["0", "2"] -> Calculate latencies of ONLY valid answers
# ["0"] -> Calculate latencies of valid answers AND ServFails
# ["2"] -> Calculate latencies of ONLY ServFails

rcodes_to_get = "valid+servfails"
# "valid" -> Calculate latencies of ONLY valid answers
# "valid+servfails" -> Calculate latencies of valid answers AND ServFails
# "servfails"" -> Calculate latencies of ONLY ServFails

client_bottom_limit = 0
client_upper_limit = 30
auth_bottom_limit = 0
auth_upper_limit = 30
overall_directory_name = "Overall-plot-results"
resolver_directory_name = "Resolver-plot-results"

create_overall_plots_for_one_filter(rcodes_to_get, client_bottom_limit, client_upper_limit,
                                    auth_bottom_limit, auth_upper_limit, overall_directory_name)

