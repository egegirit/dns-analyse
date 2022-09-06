import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import json
import re
import os

# Create the lists to store latency measurements
packetloss_0 = []
packetloss_10 = []
packetloss_20 = []
packetloss_30 = []
packetloss_40 = []
packetloss_50 = []
packetloss_60 = []
packetloss_70 = []
packetloss_80 = []
packetloss_85 = []
packetloss_90 = []
packetloss_95 = []

packetlossData = [packetloss_0, packetloss_10, packetloss_20, packetloss_30, packetloss_40, packetloss_50,
                  packetloss_60, packetloss_70, packetloss_80, packetloss_85, packetloss_90, packetloss_95]

# Count the failure rates for each packetloss configuration
failure_rate_0 = []
failure_rate_10 = []
failure_rate_20 = []
failure_rate_30 = []
failure_rate_40 = []
failure_rate_50 = []
failure_rate_60 = []
failure_rate_70 = []
failure_rate_80 = []
failure_rate_85 = []
failure_rate_90 = []
failure_rate_95 = []

failure_rate_data = [failure_rate_0, failure_rate_10, failure_rate_20, failure_rate_30, failure_rate_40,
                     failure_rate_50, failure_rate_60, failure_rate_70, failure_rate_80, failure_rate_85,
                     failure_rate_90, failure_rate_95]

# Answer == "1" -> DNS Response message
# Answer == "0" -> DNS Query
answer_count_0 = []
answer_count_10 = []
answer_count_20 = []
answer_count_30 = []
answer_count_40 = []
answer_count_50 = []
answer_count_60 = []
answer_count_70 = []
answer_count_80 = []
answer_count_85 = []
answer_count_90 = []
answer_count_95 = []

answer_count_data = [answer_count_0, answer_count_10, answer_count_20, answer_count_30, answer_count_40,
                     answer_count_50, answer_count_60, answer_count_70, answer_count_80, answer_count_85,
                     answer_count_90, answer_count_95]

retransmission_0 = 0
retransmission_10 = 0
retransmission_20 = 0
retransmission_30 = 0
retransmission_40 = 0
retransmission_50 = 0
retransmission_60 = 0
retransmission_70 = 0
retransmission_80 = 0
retransmission_85 = 0
retransmission_90 = 0
retransmission_95 = 0

retransmission_data = [retransmission_0, retransmission_10, retransmission_20, retransmission_30, retransmission_40,
                       retransmission_50, retransmission_60, retransmission_70, retransmission_80, retransmission_85,
                       retransmission_90, retransmission_95]

# Store all packets by their packetloss rates
packet_pl0 = []
packet_pl10 = []
packet_pl20 = []
packet_pl30 = []
packet_pl40 = []
packet_pl50 = []
packet_pl60 = []
packet_pl70 = []
packet_pl80 = []
packet_pl85 = []
packet_pl90 = []
packet_pl95 = []
all_packets_pl = [packet_pl0, packet_pl10, packet_pl20, packet_pl30, packet_pl40, packet_pl50,
                  packet_pl60, packet_pl70, packet_pl80, packet_pl85, packet_pl90, packet_pl95
                  ]

# All the packets in all of the JSON files
all_packets = []

# Store all the latencies by their packetloss rates
latency_0 = []
latency_10 = []
latency_20 = []
latency_30 = []
latency_40 = []
latency_50 = []
latency_60 = []
latency_70 = []
latency_80 = []
latency_85 = []
latency_90 = []
latency_95 = []

latencyData = [latency_0, latency_10, latency_20, latency_30, latency_40, latency_50,
               latency_60, latency_70, latency_80, latency_85, latency_90, latency_95]

# If you already calculated the latency for a query name and there were multiple duplicate queries and
# maybe duplicate answers for that exact query name, you should only calculate the latency once,
# to avoid calculating it multiple times, store the query names you calculated here to mark them
calculated_queries = []

calculated_retransmission_queries = []

calculated_latency_queries = []

calculated_failure_queries = []

packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

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


# operators[""Google1"] == "8-8-8-8"
# operator_names = list(operators.keys())  # "AdGuard1", "AdGuard2" ...
# operator_ip_addresses = list(operators.values())

# print(get_operator_name_from_ip("77-88-8-8"))
# print(operator_names)
# print(operator_ip_addresses)

dns_packets_in_pl = []
pl0 = []
pl10 = []
pl20 = []
pl30 = []
pl40 = []
pl50 = []
pl60 = []
pl70 = []
pl80 = []
pl85 = []
pl90 = []
pl95 = []
all_packetloss_packets = [pl0, pl10, pl20, pl30, pl40, pl50, pl60, pl70,
                          pl80, pl85, pl90, pl95]


adguard1 = []
adguard2 = []
cleanBrowsing1 = []
cleanBrowsing2 = []
cloudflare1 = []
cloudflare2 = []
dyn1 = []
dyn2 = []
google1 = []
google2 = []
neustar1 = []
neustar2 = []
openDNS1 = []
openDNS2 = []
quad91 = []
quad92 = []
yandex1 = []
yandex2 = []

list_of_operators = [
    adguard1,
    adguard2,
    cleanBrowsing1,
    cleanBrowsing2,
    cloudflare1,
    cloudflare2,
    dyn1,
    dyn2,
    google1,
    google2,
    neustar1,
    neustar2,
    openDNS1,
    openDNS2,
    quad91,
    quad92,
    yandex1,
    yandex2,
]


def get_operator_name_from_ip(ip_addr_with_dashes):
    for operator, ip_addr in operators.items():
        if ip_addr == ip_addr_with_dashes:
            return operator
    else:
        return "Not found!"


def classify_packets_by_operators():
    print("Classifying packets by operator name")
    global list_of_operators
    global all_packetloss_packets

    for packet_pl in all_packetloss_packets:
        for packet in packet_pl:
            if packet.operator == "AdGuard1":
                list_of_operators[0].append(packet)
            if packet.operator == "AdGuard2":
                list_of_operators[1].append(packet)
            if packet.operator == "CleanBrowsing1":
                list_of_operators[2].append(packet)
            if packet.operator == "CleanBrowsing2":
                list_of_operators[3].append(packet)
            if packet.operator == "Cloudflare1":
                list_of_operators[4].append(packet)
            if packet.operator == "Cloudflare2":
                list_of_operators[5].append(packet)
            if packet.operator == "Dyn1":
                list_of_operators[6].append(packet)
            if packet.operator == "Dyn2":
                list_of_operators[7].append(packet)
            if packet.operator == "Google1":
                list_of_operators[8].append(packet)
            if packet.operator == "Google2":
                list_of_operators[9].append(packet)
            if packet.operator == "Neustar1":
                list_of_operators[10].append(packet)
            if packet.operator == "Neustar2":
                list_of_operators[11].append(packet)
            if packet.operator == "OpenDNS1":
                list_of_operators[12].append(packet)
            if packet.operator == "OpenDNS2":
                list_of_operators[13].append(packet)
            if packet.operator == "Quad91":
                list_of_operators[14].append(packet)
            if packet.operator == "Quad92":
                list_of_operators[15].append(packet)
            if packet.operator == "Yandex1":
                list_of_operators[16].append(packet)
            if packet.operator == "Yandex2":
                list_of_operators[17].append(packet)


def show_latencies(packetloss_data):
    # Check the latencies of all the packetloss configs
    i = 0
    for t in packetloss_data:
        print(f"{i}: {t}")
        i += 1


def show_answer_query_count(query_list):
    pl_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]
    answer_count = 0
    query_count = 0
    index = 0
    for lst in query_list:
        for answer in lst:
            if answer == "0":
                query_count += 1
            else:
                answer_count += 1
        print(f"Packetloss rate: {pl_rates[index]}")
        print(f"  Query count: {query_count}")
        print(f"  Answer count: {answer_count}")
        answer_count = 0
        query_count = 0
        index += 1


def show_restransmission_data(retransmission_list):
    pl_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]
    index = 0
    for number in retransmission_list:
        print(f"Packetloss rate: {pl_rates[index]}")
        print(f"Retransmission count: {number}")
        index += 1


def show_failure_count():
    global failure_rate_data

    pl_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]
    index = 0
    fail_count = 0
    for failure_data in failure_rate_data:
        for rcode in failure_data:
            # print(f"RCODE: {rcode}")
            if rcode != 0:
                fail_count += 1
        print(f"Packetloss rate: {pl_rates[index]}")
        print(f"Failed packet count: {fail_count}")
        fail_count = 0
        index += 1


# Reset the retransmission_data
def clear_retransmission_data():
    print(f"Clearing restransmission data")
    global retransmission_data
    for i in range(0, 12):
        retransmission_data[i] = 0


# Reset the retransmission_data
def clear_answers():
    print(f"Clearing answer count data")
    global answer_count_data
    for lst in answer_count_data:
        lst.clear()


# Clear failure rate data: done in bar plot
def clear_packetloss_data():
    print(f"Clearing packetloss data")
    global packetlossData
    for p in packetlossData:
        p.clear()
        # print(f"packetlossData packet: {p}")
        # for i in p:
        #     i.clear()
        # print(f"packetlossData packet inside: {i}")


def clear_failure_rate_data():
    print(f"Clearing failure rate data")
    global failure_rate_data
    for lst in failure_rate_data:
        lst.clear()


# packetlossData is filled here
def create_box_plot(directory_name, file_name, operator_specific_packet_list, rcodes, bottom_limit, upper_limit, log_scale=False):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0] is not None:
        operator_name = find_operator_name_of_json_packet(operator_specific_packet_list[0])

    print(f"Creating box plot for {operator_name}")

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percantage')
    ax.set_title(f'Packetloss-Latency for {operator_name}')

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    if log_scale:
        ax.set_yscale('log', base=2)
    # else: ax.set_yscale('linear')

    # Add the data counts onto plot
    data_count_string = ""
    for i in range(len(latencyData)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(len(latencyData[i])) + "\n"
    text = ax.annotate(data_count_string, xy=(.5, .5), xytext=(x_axis_for_text, y_axis_for_text), color='red')
    # Make it transparent
    text.set_alpha(.4)
    # plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Creating plot
    # bp = ax.boxplot(packetlossData)
    # ax.boxplot(packetlossData)  # Old
    ax.boxplot(latencyData, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95], widths=4.4)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name + "_" + operator_name + '_boxPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name}")
    # Clear plots
    plt.cla()
    plt.close()


def create_violin_plot(directory_name, file_name, operator_specific_packet_list, bottom_limit, upper_limit, log_scale=False):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0] is not None:
        operator_name = find_operator_name_of_json_packet(operator_specific_packet_list[0])

    print(f"Creating violin plot for {operator_name}")

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percantage')
    ax.set_title(f'Packetloss-Latency for {operator_name}')

    # IF a packetloss latency list is empty, add negative dummy value so that violinplot doesnt crash
    # Since the plots bottom limit is, it wont be visible in graph
    # But when you add this, you need to subtract it from the count on the plot text
    global latencyData
    index_of_dummy = 0
    dummy_indexes = []
    for packet in latencyData:
        # print(f"  packet: {packet}")
        if len(packet) == 0:
            packet.append(float(-0.2))
            dummy_indexes.append(index_of_dummy)
        index_of_dummy += 1

    # Create and save Violinplot
    # bp = ax.violinplot(packetlossData)
    # bp = ax.violinplot(dataset=packetlossData, showmeans=True, showmedians=True,
    #                   showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    if log_scale:
        ax.set_yscale('log', base=2)

    bp = ax.violinplot(dataset=latencyData, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    if len(dummy_indexes) > 0:
        for i in range(len(latencyData)):
            # if the index length was 0 so that we added a dummy value, subtract it from the count
            if i in dummy_indexes:
                data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(len(latencyData[i])-1) + "\n"
            # Index was not 0, write the actual length
            else:
                data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(len(latencyData[i])) + "\n"
    else:
        for i in range(len(latencyData)):
            data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(len(latencyData[i])) + "\n"
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
    plt.savefig(directory_name + "/" + (file_name + "_" + operator_name + '_violinPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created violin plot: {file_name}")
    # Clear plots
    plt.cla()
    plt.close()

def create_bar_plot_failure(directory_name, file_name, operator_specific_packet_list, bottom_limit, upper_limit):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0] is not None:
        operator_name = find_operator_name_of_json_packet(operator_specific_packet_list[0])

    print(f"Creating failure bar plot for {operator_name}")

    global failure_rate_data
    # Clear failure rate counts of the global list
    # Because we will fill it here after filtering all the packets by packetloss rate
    for lst in failure_rate_data:
        lst.clear()

    # Get the index of the operator to access the list with all operator packets
    op_index = get_index_of_operator(operator_name)

    # Failure rate for client is the count of rcode != 0 + unanswered packets
    # Failure count for authoritative is the count of unanswered packets because
    # in auth1 there is no packet with dns.flags.rcode != 0

    if "client" in file_name:
        # Separate packets by  their packetloss rates
        for packet in list_of_operators[op_index]:  # OLD: all_responses_of_operator:
            # print(f"  get_packetloss_rate_of_packet(packet): {get_packetloss_rate_of_packet(packet)}")
            if get_packetloss_rate_of_packet(packet) == "pl0":
                # TODO: replace with calculate_failure_rate_of_packet(packet, 0)
                calculate_failure_rate_of_packet(packet, 0, file_name)
                # TODO: and make the calculate_failure_rate_of_packet() function also append the rcode 0 to failure_rate_data[]
                #failure_rate_data[0].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl10":
                calculate_failure_rate_of_packet(packet, 1, file_name)
                #failure_rate_data[1].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl20":
                calculate_failure_rate_of_packet(packet, 2, file_name)
                #failure_rate_data[2].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl30":
                calculate_failure_rate_of_packet(packet, 3, file_name)
                #failure_rate_data[3].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl40":
                calculate_failure_rate_of_packet(packet, 4, file_name)
                #failure_rate_data[4].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl50":
                calculate_failure_rate_of_packet(packet, 5, file_name)
                #failure_rate_data[5].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl60":
                calculate_failure_rate_of_packet(packet, 6, file_name)
                #failure_rate_data[6].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl70":
                calculate_failure_rate_of_packet(packet, 7, file_name)
                #failure_rate_data[7].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl80":
                calculate_failure_rate_of_packet(packet, 8, file_name)
                #failure_rate_data[8].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl85":
                calculate_failure_rate_of_packet(packet, 9, file_name)
                #failure_rate_data[9].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl90":
                calculate_failure_rate_of_packet(packet, 10, file_name)
                #failure_rate_data[10].append(get_response_code_of_packet(packet))
            if get_packetloss_rate_of_packet(packet) == "pl95":
                calculate_failure_rate_of_packet(packet, 11, file_name)
                #failure_rate_data[11].append(get_response_code_of_packet(packet))
    elif "auth" in file_name:
        # Separate packets by  their packetloss rates
        for packet in list_of_operators[op_index]:
            # print(f"  get_packetloss_rate_of_packet(packet): {get_packetloss_rate_of_packet(packet)}")
            if get_packetloss_rate_of_packet(packet) == "pl0":
                calculate_failure_rate_of_packet(packet, 0, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl10":
                calculate_failure_rate_of_packet(packet, 1, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl20":
                calculate_failure_rate_of_packet(packet, 2, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl30":
                calculate_failure_rate_of_packet(packet, 3, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl40":
                calculate_failure_rate_of_packet(packet, 4, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl50":
                calculate_failure_rate_of_packet(packet, 5, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl60":
                calculate_failure_rate_of_packet(packet, 6, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl70":
                calculate_failure_rate_of_packet(packet, 7, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl80":
                calculate_failure_rate_of_packet(packet, 8, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl85":
                calculate_failure_rate_of_packet(packet, 9, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl90":
                calculate_failure_rate_of_packet(packet, 10, file_name)
            if get_packetloss_rate_of_packet(packet) == "pl95":
                calculate_failure_rate_of_packet(packet, 11, file_name)

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    failure_rate_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                              '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # DEBUG
    # for packet in failure_rate_data:
    #     print(f"packet in failure_rate_data: {packet}")
    #     for pac in packet:
    #         print(f"pac.response_code: {pac}")

    # Write the failure count on the plot
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
        for x in range(len(failure_rate_data[index])):
            if failure_rate_data[index][x] != "0" and failure_rate_data[index][x] is not None:
                fail_count += 1
        # print(f"Fail count: {fail_count}")
        if fail_count != 0:
            # divide by 180 bcs every resolver sends 50 queries for a pl rate, multiply by 100 to get the percentage of the failure rate
            # TODO: change 50 by the query count of the resolver
            # Wrong, this is all the packetloss configs queries
            # Divide by 12?
            # all_queryname_of_resolver = len(find_the_query_packets(operator_specific_packet_list, file_name))

            queries_of_pl_rate_of_resolver = []
            all_queries_of_resolver = find_the_query_packets(operator_specific_packet_list, file_name)
            current_pl = "pl" + str(packetloss_rates[index])
            for packet in all_queries_of_resolver:
                query_name = extract_query_name_from_packet(packet)
                if current_pl in query_name:
                    queries_of_pl_rate_of_resolver.append(packet)

            divide_by = len(queries_of_pl_rate_of_resolver)
            # print(f"all_queryname_of_resolver: {all_queryname_of_resolver}")

            failure_counts[index] = fail_count

            failure_rate_data_dict[str(current_packetloss_rate)] = (fail_count / divide_by) * 100
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

    # adding text inside the plot
    data_count_string = ""
    for i in range(len(latencyData)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            failure_counts[i]) + "\n"
    text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')
    text.set_alpha(0.5)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Response Failure Rate")
    plt.title(f"Response Failure Rate for {operator_name}")
    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # creating the bar plot
    plt.bar(failure_rates, values, color='maroon', width=4)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name + "_" + operator_name + '_barPlotResponseFailureRate.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created bar plot: {file_name}")
    # Clear plots
    plt.cla()
    plt.close()


# failure_rate_data is already filled when looping the packets
def create_bar_plot_retransmission(directory_name, file_name, bottom_limit, upper_limit, operator_specific_packet_list, use_limits=False):
    print(f" Creating retransmission bar plot: {file_name}")

    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0] is not None:
        operator_name = find_operator_name_of_json_packet(operator_specific_packet_list[0])

    print(f"Creating retransmission  bar plot for {operator_name}")

    # f.write(f" Creating retransmission plot: {file_name}\n")

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    failure_rate_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                              '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # DEBUG
    # for packet in failure_rate_data:
    #     print(f"packet in failure_rate_data: {packet}")
    #     for pac in packet:
    #         print(f"pac.response_code: {pac}")

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary
    index = 0
    for current_packetloss_rate in packetloss_rates:
        # print(f"index: {index}")
        # print(f"Data: {failure_rate_data[index]}")
        if retransmission_data[index] != 0:
            failure_rate_data_dict[str(current_packetloss_rate)] = retransmission_data[index]
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

    # adding text inside the plot
    data_count_string = ""
    for i in range(len(latencyData)):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            failure_rate_data_dict[str(packetloss_rates[i])]) + "\n"
    text = plt.text(x_axis_for_text, y_axis_for_text, data_count_string, family="sans-serif", fontsize=11, color='r')
    text.set_alpha(0.5)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Retransmission Count")
    plt.title(f"Retransmission Count")

    if use_limits:
        plt.ylim(bottom=bottom_limit, top=upper_limit)

    # creating the bar plot
    plt.bar(failure_rates, values, color='blue', width=4)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name + "_" + operator_name + '_barPlotRetransmissionCount.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created retransmission plot: {file_name}")
    # f.write(f" Created retransmission plot: {file_name}\n")
    # Clear plots
    plt.cla()
    plt.close()


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


def find_all_packets_with_query_name(query_name):
    # Check the packetloss rate of the query name
    list_to_search = []
    global all_packets_pl
    if "pl0" in query_name:
        list_to_search = all_packets_pl[0]
    if "pl10" in query_name:
        list_to_search = all_packets_pl[1]
    if "pl20" in query_name:
        list_to_search = all_packets_pl[2]
    if "pl30" in query_name:
        list_to_search = all_packets_pl[3]
    if "pl40" in query_name:
        list_to_search = all_packets_pl[4]
    if "pl50" in query_name:
        list_to_search = all_packets_pl[5]
    if "pl60" in query_name:
        list_to_search = all_packets_pl[6]
    if "pl70" in query_name:
        list_to_search = all_packets_pl[7]
    if "pl80" in query_name:
        list_to_search = all_packets_pl[8]
    if "pl85" in query_name:
        list_to_search = all_packets_pl[9]
    if "pl90" in query_name:
        list_to_search = all_packets_pl[10]
    if "pl95" in query_name:
        list_to_search = all_packets_pl[11]

    packets_with_query_name = []
    for packet in list_to_search:
        if extract_query_name_from_packet(packet) == query_name:
            packets_with_query_name.append(packet)
    return packets_with_query_name


def extract_query_name_from_packet(packet):
    if 'dns' in packet['_source']['layers']:
        # Every dns packet has "Queries" attribute, which contains the query name
        json_string = str(packet['_source']['layers']['dns']['Queries'])
        splitted_json1 = json_string.split("'dns.qry.name': ")
        splitted2 = str(splitted_json1[1])
        return splitted2.split("'")[1]
    else:
        return None


# Get the packetloss string of the json packet
def get_packetloss_rate_of_packet(packet):
    query_name = extract_query_name_from_packet(packet)
    if query_name is not None:
        query_ab_pl_rate = query_name.split("-")[5]
        pl_rate = query_ab_pl_rate.split(".")[0]
        return pl_rate   # <ipnr>-<ipnr>-<ipnr>-<ipnr>-<counter>-pl*.
    else:
        return None

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
        # Filter responses of client, reponse must have destination IP of client
        if file_name == "client":
            if not dst_ip_match(packet, client_only_dest_ips):
                continue

        # New
        # For auth, get only reponses that is really sent from our auth server -> filter by auth IP as source IP
        if file_name == "auth":
            if not src_ip_match(packet, auth_only_dest_ips):
                continue

        # New condition to filter NS record answers of anycast
        # and get only responses with A records
        if "Answers" in packet['_source']['layers']['dns']:
            response = packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response']
            # print(f"Response: {response}")
            if response == "1":
                responses.append(packet)
    return responses


# Get response code of JSON
def get_response_code_of_packet(packet):
    if 'dns.flags.rcode' in packet['_source']['layers']['dns']['dns.flags_tree']:
        current_rcode = packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
        return current_rcode
    else:
        return None

# No need?
def find_the_first_response_from_packets(packet_list):
    first_response_packet = None
    return first_response_packet


# Out of all the packets, return only the queries
def find_the_query_packets(packet_list, file_name):
    queries = []
    # opt_type = ""

    for packet in packet_list:
        # Filter queries of client, query must have source IP of client
        if file_name == "client":
            if not src_ip_match(packet, client_only_source_ips):
                continue

        # Dont examine OPT packets (not generated by client or auth, generated by anycast?)
        # if "Additional records" in packet['_source']['layers']['dns']:
        #     if "dns.resp.type" in packet['_source']['layers']['dns']["Additional records"]:
        #         opt_type = packet['_source']['layers']['dns']["Additional records"]["dns.resp.type"]
        if packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "0":  # and opt_type != "41":
            queries.append(packet)
    return queries


# No need?
def find_the_first_query_from_packets(packet_list):
    first_query_packet = None
    return first_query_packet


# Find and return the packet with the specified frame number
def get_packet_by_frame_no_from_list(frame_no, packet_list):
    for packet in packet_list:
        if packet["_source"]["layers"]["frame"]["frame.number"] == frame_no:
            return packet
    # If the frame number doesn't exist, return None
    return None


def find_lowest_frame_no(packet_list):
    frame_numbers = []
    for packet in packet_list:
        number = packet["_source"]["layers"]["frame"]["frame.number"]
        frame_numbers.append(number)
    return min(frame_numbers)


def src_ip_match(packet, ip_list):
    if len(ip_list) > 0:
        ip_src_of_packet = packet['_source']['layers']["ip"]["ip.src"]
        if ip_src_of_packet in ip_list:
            return True
    return False


def dst_ip_match(packet, ip_list):
    if len(ip_list) > 0:
        ip_dst_of_packet = packet['_source']['layers']["ip"]["ip.dst"]
        if ip_dst_of_packet in ip_list:
            return True
    return False


# Latency (between first query and answer) algorithm 2
# "Zeit bis zur ersten Antwort (unabhängig von RCODE)"
# if packet has dns.time, get the packets query name, if there are more than 2 (query + answer) queries with that query name,
# than you have duplicates, find the first query (using frame relative time of all of the queries),
# calculate the new latency with: dns.time + (time between first query and last query) = dns.time + (rel(last)-rel(first))
def calculate_latency_of_packet(current_packet, file_name):
    # Filter the source and destination Addresses for client
    if file_name == "client":
        src_match = src_ip_match(current_packet, client_only_source_ips)
        dst_match = dst_ip_match(current_packet, client_only_dest_ips)
        if not src_match and not dst_match:  # if src_match or dst_match -> Calculate latency of packet
            return None

    debug = False

    # Get the dns.time if it exists, packets with dns.time are Responses with either No error or Servfail
    # Note: the packet has to have "Answers" section because an NS record has also dns.time,
    # but we want A record for resolution. But NS records can be filtered in the beginning now.
    if 'dns.time' in current_packet['_source']['layers']['dns']:  # and "Answers" in current_packet['_source']['layers']['dns']:  # New and condition
        dns_time = float(current_packet['_source']['layers']['dns']['dns.time'])
        latency = dns_time

        query_name_of_packet = extract_query_name_from_packet(current_packet)

        # if "185-228-168-168" in query_name_of_packet:
        #     if "pl95" in query_name_of_packet:
        #         print(f"  Match for cleanbrowsing 95 {file_name}")
        #         debug = True

        # If already calculated, skip
        if query_name_of_packet is not None:
            if query_name_of_packet in calculated_queries:
                if debug:
                    print(f"    !! You already calculated latency for: {query_name_of_packet}")
                # f.write(f"    !! You already calculated latency for: {query_name_of_packet}\n")
                return None

        packets = find_all_packets_with_query_name(query_name_of_packet)

        # EDGE CASE: there were duplicate queries, but some of them actually are answered and some of them are not
        # How to handle: calculate the time between the first query, and the first answer.
        # Because the first answer is valid, all other answers are not needed
        responses = find_the_response_packets(packets, file_name)

        # latency = first_term(answer packet) - last_term(query packet)
        first_term = 0
        last_term = 0

        # If there are more than two packets with the same query name, there are duplicates (2 = query + answer)
        if len(packets) > 2:
            if debug:
                print(f"  {len(packets)} packets in total for: {query_name_of_packet}")
            # Get only all the query packets of the packets with the same query name
            queries = find_the_query_packets(packets, file_name)

            if debug:
                print(f"  {len(queries)} queries in total for: {query_name_of_packet}")

            # Find the first ever query that was sent for this query name
            lowest_frame_no_of_queries = find_lowest_frame_no(queries)
            query_packet_with_lowest_frame_no = get_packet_by_frame_no_from_list(lowest_frame_no_of_queries, queries)
            # get the relative frame time of packet
            rel_fr_time_of_first_query = get_frame_time_relative_of_packet(query_packet_with_lowest_frame_no)

            last_term = rel_fr_time_of_first_query

            # If there are multiple answers to the same query, find the first answer, but no separation between RCODES
            # (lower latency as a result)
            if len(responses) > 1:
                if debug:
                    print(f"  @@ Found multiple {len(responses)} answers for: {query_name_of_packet}")
                # f.write(f"  @@ Found multiple same answers for: {query_name_of_packet}\n")

                # TODO: "Zeit bis zur ersten NOERROR Antwort"
                # examine all the responses's RCODES, get the ones with RCODE = 0, get the first of them.
                responses_with_rcode_0 = []
                for response in responses:
                    if get_rcode_of_packet(response) == "0":
                        responses_with_rcode_0.append(response)

                # If there are any response packets with RCODE = 0 (No error)
                # Calculate the time between this packet and the first query
                if len(responses_with_rcode_0) > 0:
                    if debug:
                        print(f" {len(responses_with_rcode_0)} responses with no error for: {query_name_of_packet}")
                    lowest_frame_no_of_responses_with_0 = find_lowest_frame_no(responses_with_rcode_0)
                    response_packet_0_with_lowest_frame_no = get_packet_by_frame_no_from_list(
                        lowest_frame_no_of_responses_with_0,
                        responses)
                    # get the relative frame time of packet
                    rel_fr_time_of_first_response = get_frame_time_relative_of_packet(
                        response_packet_0_with_lowest_frame_no)

                    first_term = rel_fr_time_of_first_response
                # There were not a single answer packet with no error (all was ServFail)
                else:
                    if debug:
                        print(f" Every answer was error for: {query_name_of_packet}")
                    lowest_frame_no_of_responses = find_lowest_frame_no(responses)
                    response_packet_with_lowest_frame_no = get_packet_by_frame_no_from_list(lowest_frame_no_of_responses,
                                                                                            responses)
                    # get the relative frame time of packet
                    rel_fr_time_of_first_response = get_frame_time_relative_of_packet(response_packet_with_lowest_frame_no)

                    first_term = rel_fr_time_of_first_response
                    # Among all the response packets, get the first response packet with a NOERROR
                    # Note that there might not exist such a packet, in that case, mark the query as calculated
                    # and dont calculate its latency

                    # (Old)
                    # frame_time_of_first_response = find_lowest_relative_frame_time_of_packets(responses)
                    # first_term = frame_time_of_first_response
            # If there was only one answer to multiple queries, the current packet is this only answer
            elif len(responses) == 1:
                if debug:
                    print(f"  Only one answer but multiple queries for: {query_name_of_packet}")
                # f.write(f"  Only one answer but multiple queries for: {query_name_of_packet}\n")
                first_term = get_frame_time_relative_of_packet(current_packet)

            # Latency is the difference between the relative frame times of the answer and the first query
            latency = first_term - last_term

            if debug:
                print(f"  Latency of {query_name_of_packet}: {latency}")
                print(f"    Latency calculation: {first_term} - {last_term}")

            # NOTE: If there was not a single answer to any of the (duplicate) queries,
            # then increment the failure count by one.
            # If you increment the failure count everytime when a duplicate query doesn't get answered,
            # this would result in a different plot

            # print(f"  Found duplicate query for: {query_name_of_packet}")
            # print(f"  Count of all duplicate queries: {len(packets)}")
            # print(f"  Count of failures for that query name(unanswered query): {unanswered_count}")
            # print(f"  Latency of duplicate: {latency}")

            # f.write(f"  Found duplicate query for: {query_name_of_packet}\n")
            # f.write(f"  Count of all duplicate queries: {len(packets)}\n")
            # f.write(f"  Count of failures for that query name(unanswered query): {unanswered_count}\n")
            # f.write(f"  Latency of duplicate: {latency}\n")
            # Mark the query name as calculated to avoid calculating the duplicates multiple times
            calculated_queries.append(query_name_of_packet)
            return latency
        # There was only 2 packets, can be query and its answer, return the dns.time directly, or both of them are queries
        elif len(packets) == 2:
            # both of them are queries
            if len(responses) == 0:
                calculated_queries.append(query_name_of_packet)

                if debug:
                    print(f"    2 Queries and no answers found for: {query_name_of_packet}")
                    print(f"      (No latency calculation) {latency}")

                return None
            elif len(responses) == 1:
                calculated_queries.append(query_name_of_packet)
                if debug:
                    print(f"    Just one query and one answer(packet len 2): {query_name_of_packet}")
                    print(f"    Its Lantecy (dns_time): {dns_time}")
                    # print(f"      Latency calculation: {first_term} - {last_term}")
                return dns_time

        # Else, there was only one packet, which is (must be) the query,
        # cant calculate the latency of only one packet, return none
        else:
            calculated_queries.append(query_name_of_packet)
            if debug:
                print(f"   Only one single packet(must be query?): {query_name_of_packet}")
            return None
    # Adding the latency to the array is done outside of this function
    # Append only if result is not none:
    # latency = calculate_latency_of_packet(current_packet, i)
    # if latency != None:
    #    latencyData[i].append(latency)
    if debug:
        print(f"         No dns.time for {extract_query_name_from_packet(current_packet)}")
    return None


# Failure rate of client: Count of rcode != 0 for each query name + unanswered unique query count
# TODO: make sure duplicate valid responses wont make the failure rate lower -> count the valid answer just once for the query
# Count as fail if no answer with RCODE != 0
def calculate_failure_rate_of_packet(current_packet, packetloss_index, file_name):
    # DEBUG
    # print(f"len(failure_rate_data): {len(failure_rate_data)}")
    # print(f"failure_rate_data: {failure_rate_data}")

    # Filter the source and destination Addresses for client
    if file_name == "client":
        src_match = src_ip_match(current_packet, client_only_source_ips)
        dst_match = dst_ip_match(current_packet, client_only_dest_ips)
        if not src_match and not dst_match:  # if src_match or dst_match -> Calculate latency of packet
            return

    # If already calculated, skip
    query_name_of_packet = extract_query_name_from_packet(current_packet)

    # DEBUG
    # debug = False
    # if "64-6-64-6" in query_name_of_packet and "pl80" in query_name_of_packet:
    #     debug = True
    #     print(f"  NEUSTAR1 Match: {query_name_of_packet}")

    if query_name_of_packet is not None:
        if query_name_of_packet in calculated_failure_queries:
            # if debug:
            #     print(f"  Already calculated: {query_name_of_packet}")
            return

    rcode_is_error = False

    current_rcode = "-"
    # If the packet is a response with no error, dont examine that query name again, count as success
    if 'dns.flags.rcode' in current_packet['_source']['layers']['dns']['dns.flags_tree']:
        current_rcode = current_packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
        if current_rcode == "0":
            calculated_failure_queries.append(query_name_of_packet)
            failure_rate_data[packetloss_index].append("0")
            # if debug:
            #     print(f"  RCODE was 0; appended 0: {query_name_of_packet}")
            # TODO: What if multiple answers and multiple error codes + no error codes? -> Client success -> no error
            return
        # If it is a response with error, count as failure
        # TODO: But check if the query name has no error responses
        else:  # current_rcode != "0"
            rcode_is_error = True
            # If this is the only answer, which has an error code, count as fail (below)
    # The packet can be a query or a ServFail answer
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

    # DEBUG
    # for q in queries:
    #     print(f"Query name of queries:{extract_query_name_from_packet(q)}")

    # the query had an answer packet to it, that must be handled before?

    # if debug:
    #     print(f"    Response count for {query_name_of_packet} is {responses_count}")
    #     print(f"    Query count for {query_name_of_packet} is {queries_count}")

    # There was no response at all to the query, count as failure
    if responses_count == 0:
        # OLD: instead of appending an error code to the list, the list element is an integer that counts the errors
        # failure_rate_data[packetloss_index] += 1

        # New: List of RCODES, an unanswered query results in appending a new error code
        failure_rate_data[packetloss_index].append("2")

        # print(f"Incremented bcs no answer to {query_name_of_packet}")
        calculated_failure_queries.append(query_name_of_packet)
        # if debug:
        #     print(f"  Append 2 bcs not a single response found for: {query_name_of_packet}")
    # If this is the only answer, which has an error code, count as fail
    # But what if multiple error responses and not only one: Count as one
    elif responses_count >= 1:  # and rcode_is_error:
        # examine all the responses's RCODES, get the ones with RCODE = 0, get the first of them.
        responses_with_rcode_0 = []
        for response in responses:
            if get_rcode_of_packet(response) == "0":
                responses_with_rcode_0.append(response)

        # If there are successes among the responses, count the query as success
        if len(responses_with_rcode_0) > 0:
            failure_rate_data[packetloss_index].append("0")
        # No success among responses -> failure
        else:
            failure_rate_data[packetloss_index].append("2")

        # print(f"Incremented bcs only answer with error")
        calculated_failure_queries.append(query_name_of_packet)
        # if debug:
        #     print(f"  Append 2; rcode was error, response count >= 1: {query_name_of_packet}")
        #     print(f"      RCODE: {current_rcode} for {query_name_of_packet} (2)")
    else:
        # print(f"   Unknown branch for {query_name_of_packet}, rcode: {current_rcode}, response count: {
        # responses_count}, rcode_error = {rcode_is_error}")
        return

# Read the JSON files and store all the dns packets
# into these global lists:
# all_packets_pl, all_packets, list_of_operators
def initialize_packet_lists(file_prefix, opt_filter=False):
    index = 0
    # Read the JSON file and for each captured packet and
    # store the packets in a list
    for current_packetloss_rate in packetloss_rates:
        filename = file_prefix + "_" + str(current_packetloss_rate) + ".json"
        print(f"Reading {filename}")
        # f.write(f"Reading {filename}\n")
        if not os.path.exists("./" + filename):
            print(f"File not found: {filename}")
            exit()
        # Read the measured latencies from json file
        file = open(filename)
        json_data = json.load(file)
        packet_count = len(json_data)
        print(f"  Number of packets in JSON file: {packet_count}")
        # f.write(f"  Number of packets in JSON file: {packet_count}\n")
        # print(f"  Current packetloss rate: {current_packetloss_rate}")

        # Examine all the packets in the JSON file
        for i in range(0, packet_count):
            if 'dns' in json_data[i]['_source']['layers']:

                # Check if the dns packet is generated by our experiment
                json_string = str(json_data[i]['_source']['layers']['dns']['Queries'])
                splitted_json1 = json_string.split("'dns.qry.name': ")
                splitted2 = str(splitted_json1[1])
                # print(f"splitted_json[1]: {splitted2}")
                query_name = splitted2.split("'")[1]
                # print(f"Current query name: {query_name}")

                # Check if the current IP is structured right
                query_match = re.search(".*-.*-.*-.*-.*-pl.*.packetloss.syssec-research.mmci.uni-saarland.de",
                                        query_name)
                if query_match is None:
                    continue

                if opt_filter:
                    if "Additional records" in json_data[i]['_source']['layers']['dns']:
                        if list(dict(json_data[i]['_source']['layers']['dns']["Additional records"]).values())[0][
                              'dns.resp.type'] == "41":
                            # print(" OPT PACKET")
                            continue

                global all_packets_pl
                global all_packets
                all_packets_pl[index].append(json_data[i])
                all_packets.append(json_data[i])

                # Find the resolver name by examining the query name
                # and store the packet into its operator packet list
                splitted_domain = query_name.split("-")
                ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                                      splitted_domain[2] + "-" + splitted_domain[3]

                op_name = get_operator_name_from_ip(ip_addr_with_dashes)

                # Classify each packet by operator name
                if op_name == "AdGuard1":
                    list_of_operators[0].append(json_data[i])
                if op_name == "AdGuard2":
                    list_of_operators[1].append(json_data[i])
                if op_name == "CleanBrowsing1":
                    list_of_operators[2].append(json_data[i])
                if op_name == "CleanBrowsing2":
                    list_of_operators[3].append(json_data[i])
                if op_name == "Cloudflare1":
                    list_of_operators[4].append(json_data[i])
                if op_name == "Cloudflare2":
                    list_of_operators[5].append(json_data[i])
                if op_name == "Dyn1":
                    list_of_operators[6].append(json_data[i])
                if op_name == "Dyn2":
                    list_of_operators[7].append(json_data[i])
                if op_name == "Google1":
                    list_of_operators[8].append(json_data[i])
                if op_name == "Google2":
                    list_of_operators[9].append(json_data[i])
                if op_name == "Neustar1":
                    list_of_operators[10].append(json_data[i])
                if op_name == "Neustar2":
                    list_of_operators[11].append(json_data[i])
                if op_name == "OpenDNS1":
                    list_of_operators[12].append(json_data[i])
                if op_name == "OpenDNS2":
                    list_of_operators[13].append(json_data[i])
                if op_name == "Quad91":
                    list_of_operators[14].append(json_data[i])
                if op_name == "Quad92":
                    list_of_operators[15].append(json_data[i])
                if op_name == "Yandex1":
                    list_of_operators[16].append(json_data[i])
                if op_name == "Yandex2":
                    list_of_operators[17].append(json_data[i])

        index = index + 1


def loop_all_packets_add_latencies(file_name):
    print("Looping all packets to add latencies")
    # f.write("Looping all packets to add latencies\n")
    # global all_packets

    # for packet in all_packets:
    #     pass

    global all_packets_pl

    index = 0
    for packets_with_pl in all_packets_pl:
        print(f"  @@ Packetloss rate index: {index}")
        # f.write(f"  @@ Packetloss rate: {index}\n")
        for current_packet in packets_with_pl:
            latency = calculate_latency_of_packet(current_packet, file_name)
            if latency is not None:
                latencyData[index].append(latency)
        index += 1


# latency Data must be clear before this
def loop_operator_packets_add_latencies(operator_packets, file_name):
    print("Looping all packets to add latencies")

    for latency in latencyData:
        latency.clear()

    for packet in operator_packets:

        pl_index = get_index_of_packetloss_rate(get_packetloss_rate_of_packet(packet))
        latency = calculate_latency_of_packet(packet, file_name)
        if latency is not None:
            latencyData[pl_index].append(latency)


# Set the global list of retransmission data
def calculate_retransmission_of_query(current_packet, packetloss_index, file_name):

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
    # DEBUG for Adguard 2
    # if "94-140-14-15" in query_name_of_packet:
    #     if "pl85" in query_name_of_packet or "pl40" in query_name_of_packet:
    #         debug = True
    #         print(f"Adguard2 match: {query_name_of_packet}")

    if query_name_of_packet is not None:
        if query_name_of_packet in calculated_retransmission_queries:
            if debug:
                print(f"  Already calculated (skipping): {query_name_of_packet}")
            # f.write(f"  Already calculated (skipping): {query_name_of_packet}\n")
            return

    # Get all json packets that have the same query name
    # Slow runtime
    packets = find_all_packets_with_query_name(query_name_of_packet)

    # DEBUG
    # print(f" All packets with query name:")
    # for pac in packets:
    #     print(f"   query name: {extract_query_name_from_packet(pac)}")
    #     print(f"   frame_time_relative: {get_frame_time_relative_of_packet(pac)}")

    responses = find_the_response_packets(packets, file_name)
    responses_count = len(responses)

    # DEBUG
    # print(f"    Response count for {query_name_of_packet} is {responses_count}")
    # for resp in responses:
    #     print(f"Query name of responses: {extract_query_name_from_packet(resp)}")

    # Find all queries with that query name
    queries = find_the_query_packets(packets, file_name)
    queries_count = len(queries)

    # DEBUG
    # for q in queries:
    #     print(f"    Query count for {query_name_of_packet} is {queries_count}")
    #     print(f"Query name of queries:{extract_query_name_from_packet(q)}")

    global retransmission_data

    # When more than one query with same query name, they count as duplicate
    if queries_count > 1:
        if debug:
            print(f"  {file_name}: Multiple ({queries_count}) queries for: {query_name_of_packet}\n  Response count of it: {responses_count}\n  Packetloss index of it: {packetloss_index}")
            for query in queries:
                print(f"    Found query names: {extract_query_name_from_packet(query)}")
            for resp in responses:
                print(f"    Found response names: {extract_query_name_from_packet(resp)}")

        # f.write(f"  Multiple ({queries_count}) queries for: {query_name_of_packet}\n  Response count of it: {responses_count}\n  Packetloss index of it: {packetloss_index}\n")
        # Mark the query name as handled to not count other packets with query name again
        calculated_retransmission_queries.append(query_name_of_packet)
        # -1 Because the original (first) query doesn't count as duplicate
        duplicate_query_count = queries_count - 1

        # Set the global list that holds the duplicate count for each packetloss rate
        # print(f"PL index: {packetloss_index}")
        retransmission_data[packetloss_index] += duplicate_query_count
        # print(f"retransmission_data[{packetloss_index}]: {retransmission_data[packetloss_index]}")

        return duplicate_query_count
    else:
        # queries_count == 1 or 0 -> No duplicate
        return

# Loop all the json packets and calculate their latencies/response failure counts
def loop_all_packets_for_retransmission(packet_list, file_name):
    print("Looping packets to add retransmission counts")
    # global all_packets
    # for packet in all_packets:
    #     pass

    for packet in packet_list:
        pl_index = get_index_of_packetloss_rate(get_packetloss_rate_of_packet(packet))
        calculate_retransmission_of_query(packet, pl_index , file_name)


def show_all_latencies():
    print("Showing all latencies")
    global latencyData

    index = 0
    for pl_rate in latencyData:
        print(f"{index}. Latencies: {pl_rate}")
        # for latency in pl_rate:
        #     print
        index += 1


# Clear all the global lists for the next JSON file
def clear_lists():
    global list_of_operators
    global latencyData
    global all_packets_pl
    global all_packets

    for packet_list in all_packets_pl:
        packet_list.clear()

    for packet in list_of_operators:
        packet.clear()

    for packet_list in latencyData:
        packet_list.clear()

    all_packets.clear()

def find_operator_name_of_json_packet(packet):
    # print(f" DEBUG: packet: {packet}, len(): {len(packet)}")
    json_string = str(packet['_source']['layers']['dns']['Queries'])
    splitted_json1 = json_string.split("'dns.qry.name': ")
    splitted2 = str(splitted_json1[1])

    query_name = splitted2.split("'")[1]

    splitted_domain = query_name.split("-")
    ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                          splitted_domain[2] + "-" + splitted_domain[3]

    return get_operator_name_from_ip(ip_addr_with_dashes)


def clear_list(multi_list):
    for lst in multi_list:
        lst.clear()


# Clears all the lists etc. so that the next plotting
# doesn't read info from the previous json files
def prepare_for_next_iteration():
    # Clear lists for the next JSON files
    clear_list(answer_count_data)
    clear_list(packetlossData)

    # Clear failure rate data:
    global failure_rate_data
    for i in failure_rate_data:
        i.clear()
        # i = 0

    # Reset the retransmission_data
    global retransmission_data
    for i in range(len(retransmission_data)):
        retransmission_data[i] = 0
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
    global all_packets_pl
    for packet_list in all_packets_pl:
        packet_list.clear()

    global all_packets
    all_packets.clear()


# Get RCODE of a single JSON packet
def get_rcode_of_packet(packet):
    if 'dns.flags.rcode' in packet['_source']['layers']['dns']['dns.flags_tree']:
        return packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']


def loop_all_packets_get_all_query_names():
    all_query_names_pl0 = []
    all_query_names_pl10 = []
    all_query_names_pl20 = []
    all_query_names_pl30 = []
    all_query_names_pl40 = []
    all_query_names_pl50 = []
    all_query_names_pl60 = []
    all_query_names_pl70 = []
    all_query_names_pl80 = []
    all_query_names_pl85 = []
    all_query_names_pl90 = []
    all_query_names_pl95 = []
    all_query_names = [
        all_query_names_pl0,
        all_query_names_pl10,
        all_query_names_pl20,
        all_query_names_pl30,
        all_query_names_pl40,
        all_query_names_pl50,
        all_query_names_pl60,
        all_query_names_pl70,
        all_query_names_pl80,
        all_query_names_pl85,
        all_query_names_pl90,
        all_query_names_pl95
    ]
    global all_packets_pl
    index = 0
    for pl_rate in all_packets_pl:
        for packet in pl_rate:
            query_name_of_current_packet = extract_query_name_from_packet(packet)
            # If query already in list, don't add a duplicate
            if query_name_of_current_packet not in all_query_names[index]:
                all_query_names[index].append(query_name_of_current_packet)
        index += 1

    # print(all_query_names)
    return all_query_names


# Create a bar plot showing how many queries are not sent to the auth server
def create_missing_query_bar_plot_for_auth(operator_specific_packet_list):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0] is not None:
        operator_name = find_operator_name_of_json_packet(operator_specific_packet_list[0])

    print(f" Creating missing query bar plot: {operator_name}")

    global client_query_names
    global auth_query_names

    all_query_names_op_specific_pl0 = []
    all_query_names_op_specific_pl10 = []
    all_query_names_op_specific_pl20 = []
    all_query_names_op_specific_pl30 = []
    all_query_names_op_specific_pl40 = []
    all_query_names_op_specific_pl50 = []
    all_query_names_op_specific_pl60 = []
    all_query_names_op_specific_pl70 = []
    all_query_names_op_specific_pl80 = []
    all_query_names_op_specific_pl85 = []
    all_query_names_op_specific_pl90 = []
    all_query_names_op_specific_pl95 = []

    all_client_query_names_op_specific = [
        all_query_names_op_specific_pl0,
        all_query_names_op_specific_pl10,
        all_query_names_op_specific_pl20,
        all_query_names_op_specific_pl30,
        all_query_names_op_specific_pl40,
        all_query_names_op_specific_pl50,
        all_query_names_op_specific_pl60,
        all_query_names_op_specific_pl70,
        all_query_names_op_specific_pl80,
        all_query_names_op_specific_pl85,
        all_query_names_op_specific_pl90,
        all_query_names_op_specific_pl95
    ]

    all_auth_query_names_op_specific_pl0 = []
    all_auth_query_names_op_specific_pl10 = []
    all_auth_query_names_op_specific_pl20 = []
    all_auth_query_names_op_specific_pl30 = []
    all_auth_query_names_op_specific_pl40 = []
    all_auth_query_names_op_specific_pl50 = []
    all_auth_query_names_op_specific_pl60 = []
    all_auth_query_names_op_specific_pl70 = []
    all_auth_query_names_op_specific_pl80 = []
    all_auth_query_names_op_specific_pl85 = []
    all_auth_query_names_op_specific_pl90 = []
    all_auth_query_names_op_specific_pl95 = []

    all_auth_query_names_op_specific = [
        all_auth_query_names_op_specific_pl0,
        all_auth_query_names_op_specific_pl10,
        all_auth_query_names_op_specific_pl20,
        all_auth_query_names_op_specific_pl30,
        all_auth_query_names_op_specific_pl40,
        all_auth_query_names_op_specific_pl50,
        all_auth_query_names_op_specific_pl60,
        all_auth_query_names_op_specific_pl70,
        all_auth_query_names_op_specific_pl80,
        all_auth_query_names_op_specific_pl85,
        all_auth_query_names_op_specific_pl90,
        all_auth_query_names_op_specific_pl95
    ]

    # From the global list that has all the client queries, get all the queries of the current resolver
    # And separate them into different packetloss rates
    index = 0
    for client_query_names_pl in client_query_names:
        for client_query_name_pl in client_query_names_pl:
            # Check if the query packet is a packet of the current resolver
            if operator_name in client_query_name_pl:
            # if operator_name in find_operator_name_of_json_packet(client_query_name_pl):
                query_name_of_current_packet = client_query_name_pl
                # If the query not already examined, take it into the list
                if query_name_of_current_packet not in all_client_query_names_op_specific[index]:
                    all_client_query_names_op_specific[index].append(query_name_of_current_packet)
        index += 1

    # From the global list that has all the auth queries, get all the queries of the current resolver
    # And separate them into different packetloss rates
    index = 0
    for auth_query_names_pl in auth_query_names:
        for auth_query_name_pl in auth_query_names_pl:
            # Check if the query packet is a packet of the current resolver
            if operator_name in auth_query_name_pl:
                query_name_of_current_packet = auth_query_name_pl
                # If the query not already examined, take it into the list
                if query_name_of_current_packet not in all_auth_query_names_op_specific[index]:
                    all_auth_query_names_op_specific[index].append(query_name_of_current_packet)
        index += 1

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    missing_query_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                               '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary
    index = 0
    for current_packetloss_rate in packetloss_rates:
        client_query_name_count_pl = len(all_client_query_names_op_specific[index])
        auth_query_name_count_pl = len(all_auth_query_names_op_specific[index])
        missing_query_count_on_auth_pl = client_query_name_count_pl - auth_query_name_count_pl
        missing_query_data_dict[str(current_packetloss_rate)] = missing_query_count_on_auth_pl

        index = index + 1

    keys = list(missing_query_data_dict.keys())
    values = list(missing_query_data_dict.values())

    print(f"Failure rates: {keys}")
    print(f"Missing data counts: {values}")

    plt.figure(figsize=(10, 5))

    # adding text inside the plot
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
    plt.savefig((operator_name + '_barPlotMissingQuery.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created bar plot: {operator_name}")


# Clear the missing transmission lists for the next filtering option
def clear_missing_query_lists():
    global client_query_names
    for pl_rate in client_query_names:
        pl_rate.clear()

    global auth_query_names
    for pl_rate in auth_query_names:
        pl_rate.clear()


def run_with_filters():
    # Define all possible RCODE Filters
    rcodes1 = ["0", "2"]
    rcodes2 = ["0"]
    rcodes3 = ["2"]

    all_possible_rcodes = [rcodes1, rcodes2, rcodes3]

    # Define limits of the plots
    bottom_limit = 0
    upper_limit = 50

    bottom_limit2 = 0
    upper_limit2 = 100

    directory_names = ["All-Resolver_No-RCODE_All-Resolver", "All-Resolver_RCODE-0", "All-Resolver_RCODE-2"]
    for directory_name in directory_names:
        if not os.path.exists(directory_name):
            os.makedirs(directory_name)

    directory_index = 0
    for rcode_filter in all_possible_rcodes:
        print(f" @@@@ Creating Resolver plots with RCODE Filter: {rcode_filter} @@@@")
        # When creating missing queries on auth, make sure you read all the JSON files of both client and auth
        # auth_and_client_read = False
        for file_name in file_names:

            print(f"Creating plots for {file_name}")
            # Read the JSON files and store all the dns packets
            # into these global lists:
            # all_packets_pl, all_packets, list_of_operators
            initialize_packet_lists(file_name, opt_filter)

            # Loop all packets of client, get all the unique query names of the queries, store in
            # client_query_names, and also get all the unique query names of responses,
            # store in client_responses_query_names
            # if file_name == "client":
            #     global client_query_names
            #     client_query_names = loop_all_packets_get_all_query_names()
            #     # auth_and_client_read = False
            # if file_name == "auth1":
            #     global auth_query_names
            #     auth_query_names = loop_all_packets_get_all_query_names()
            #     # auth_and_client_read = True

            # Add the filtering options to the file name of the plots
            filter_names_on_filename = ""
            # If rcode is applied, add the filter to the file name
            if len(rcode_filter) > 0:
                filter_names_on_filename += "_rcodeFilter-"
                for rcode in rcode_filter:
                    filter_names_on_filename += (rcode + "-")
            if log_scale_y_axis:
                filter_names_on_filename += "_LogScaledY-"
            filter_names_on_filename += "Lim(" + str(bottom_limit) + "," + str(upper_limit) + ")"
            if opt_filter:
                filter_names_on_filename += "_OPT-filtered"

            file_name += filter_names_on_filename

            for operator in list_of_operators:
                # print(f"len(operator): {len(operator)}")
                loop_operator_packets_add_latencies(operator, file_name)
                create_box_plot(directory_names[directory_index], file_name, operator, rcode_filter, bottom_limit, upper_limit, log_scale_y_axis)
                create_bar_plot_failure(directory_names[directory_index], file_name, operator, bottom_limit, 100)
                create_violin_plot(directory_names[directory_index], file_name, operator, bottom_limit, upper_limit, log_scale_y_axis)
                loop_all_packets_for_retransmission(operator, file_name)
                create_bar_plot_retransmission(directory_names[directory_index], file_name, bottom_limit, upper_limit, operator, use_limits=False)

                # Clear lists
                clear_answers()
                clear_retransmission_data()
                clear_failure_rate_data()
                clear_packetloss_data()

                # Reset the retransmission_data
                for i in range(len(retransmission_data)):
                    retransmission_data[i] = 0
                calculated_retransmission_queries.clear()

                calculated_queries.clear()
                calculated_latency_queries.clear()
                calculated_failure_queries.clear()

            # Problem: this deletes all the global packets
            prepare_for_next_iteration()

        # Calculate, how many client queries are not redirected to the auth server
        # by the resolver suing client_query_names and auth_query_names
        # for operator in list_of_operators:
        #     create_missing_query_bar_plot_for_auth(operator)
        # clear_missing_query_lists()

        directory_index += 1


# List that store unique query names for each packetloss rate
# to find not redirected queries for auth server
client_query_names = []
auth_query_names = []

# Write text onto plots using this coordinates
x_axis_for_text = .5
y_axis_for_text = .5

client_only_source_ips = ["139.19.117.1"]
client_only_dest_ips = ["139.19.117.1"]

auth_only_dest_ips = ["139.19.117.11"]

file_names = ["client", "auth1"]  # , "auth2"]

log_scale_y_axis = False
opt_filter = False

run_with_filters()
