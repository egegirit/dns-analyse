import matplotlib.pyplot as plt
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


def get_operator_name_from_ip(ip_addr_with_dashes):
    for operator, ip_addr in operators.items():
        if ip_addr == ip_addr_with_dashes:
            return operator
    else:
        return "Not found!"


# operators[""Google1"] == "8-8-8-8"
# operator_names = list(operators.keys())  # "AdGuard1", "AdGuard2" ...
# operator_ip_addresses = list(operators.values())


def get_operator_name_from_ip(ip_addr_with_dashes):
    for operator, ip_addr in operators.items():
        if ip_addr == ip_addr_with_dashes:
            return operator
    else:
        return "Not found!"


# print(get_operator_name_from_ip("77-88-8-8"))
# print(operator_names)
# print(operator_ip_addresses)


def clear_list(multi_list):
    for lst in multi_list:
        lst.clear()

# TODO: if query duplicates -> calculate latency between first query and answer
# if .. in json_data[i]['_source']['layers']['dns']['dns.id_tree']['_ws.expert']["dns.retransmit_request"]:
# if .. in json_data[i]['_source']['layers']['dns']['dns.id_tree']['_ws.expert']["_ws.expert.message"]:

# Algorithm: get all the packets with ["dns.retransmit_request"],

# Read the JSON file and examine all the packets in the file.
# Examine all the packets with the given rcodes only, ignore all other packets.
# Dont examine the query names if they contain the IP of the filtered_resolvers
# file_prefix: String list, rcode_filter: boolean, rcodes: String list of rcodes. If empty, no rcode filtering
# filtered_resolvers: String list of ip's with dashes. If filtered_resolvers is empty ([]), no filtering.
def read_json_files(file_prefix, rcodes, filtered_resolvers):
    # not_dns = 0
    # dns_packets_count = 0

    index = 0
    # Read the JSON file and for each captured packet.
    # set its variables according to the information read in the packet
    for current_packetloss_rate in packetloss_rates:
        filename = file_prefix + "_" + str(current_packetloss_rate) + ".json"
        print(f"Reading {filename}")
        if not os.path.exists("./" + filename):
            print(f"File not found: {filename}")
            exit()
        # Read the measured latencies from json file
        file = open(filename)
        json_data = json.load(file)
        # print(f"Number of packets in the file: {len(data)}")  # Number of packets captured and saved in the file
        # print(data[0])  # Contents of the first packet in JSON format
        # print(data[1]['_source']['layers']['dns']['dns.time'])  # "0.044423000"
        packet_count = len(json_data)
        print(f"  Number of packets in JSON file: {packet_count}")

        # response_count = 0
        # Examine all the captured packets in the JSON file
        # dns_id = ""  # DEBUG
        # duplicate = 0
        # duplicate_bool = False

        # test_failure_rate_count = 0

        print(f"  Current packetloss rate: {current_packetloss_rate}")

        # Debug: count the packets with dns.time
        test_time_count = 0
        # Examine all the packets in the JSON file
        for i in range(0, packet_count):
            # Since break/continue with labels is not supported in python
            # I used a variable to break out of multiple loops
            abort_loop = False
            # Check if the packet is a DNS packet
            if 'dns' in json_data[i]['_source']['layers']:
                # dns_packets_count = dns_packets_count + 1
                # Check if the DNS packet is using UDP as transport protocol
                if 'udp' in json_data[i]['_source']['layers']:
                    pass
                # Check if the DNS packet is using TCP as transport protocol
                if 'tcp' in json_data[i]['_source']['layers']:
                    pass
                # Get the query name and break it down to its components like ip address, counter, packetloss rate.
                # Query structure: <ip_addr>-<counter>-<packetloss_rate>.packetloss.syssec-research.mmci.uni-saarland.de
                # Query example: 94-140-14-14-1-pl95.packetloss.syssec-research.mmci.uni-saarland.de
                if "Queries" in json_data[i]['_source']['layers']['dns']:
                    # print(f"Not none: {jsonData[i]['_source']['layers']['dns']['Queries']}")
                    json_string = str(json_data[i]['_source']['layers']['dns']['Queries'])
                    splitted_json1 = json_string.split("'dns.qry.name': ")
                    splitted2 = str(splitted_json1[1])
                    # print(f"splitted_json[1]: {splitted2}")
                    query_name = splitted2.split("'")[1]
                    # print(f"Current query name: {query_name}")

                    # Check if the current IP is structured right
                    # This filters the dns traffic that is not generated by the experiment
                    query_structure_match = re.search(
                        ".*-.*-.*-.*-.*-pl.*.packetloss.syssec-research.mmci.uni-saarland.de",
                        query_name)
                    if query_structure_match is None:
                        continue

                    if len(filtered_resolvers) > 0:
                        # Ignore the packet if its query contains an IP Address that is given
                        # in the filtered_resolvers list
                        queries = []
                        matches = []
                        for ip in filtered_resolvers:
                            queries.append(ip + "-.*-pl.*.packetloss.syssec-research.mmci.uni-saarland.de")
                        for query in queries:
                            # print(f"    query: {query}")
                            matches.append(re.search(query, query_name))

                        for match in matches:
                            # If there was a match, ignore this packet and continue with the next packet
                            if match is not None:
                                # print(f"    match: {match}")
                                abort_loop = True
                                break
                        if abort_loop:
                            # print(f"Aborting loop because of filtering")
                            continue
                    # splitted_domain = query_name.split("-")
                    # ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                    #                       splitted_domain[2] + "-" + splitted_domain[3]

                    # op_name = get_operator_name_from_ip(ip_addr_with_dashes)

                    # query_ip = ip_addr_with_dashes
                    # counter = splitted_domain[4]
                    # packetloss_rate = splitted_domain[5].split(".")[0]  # [2:]
                    # test = splitted_domain[5].split(".")[0]

                    # print(f"query_name: {query_name}")
                    # print(f"ip_addr_with_dashes: {ip_addr_with_dashes}")
                    # print(f"counter: {splitted_domain[4]}")
                    # print(f"packetloss_rate: {test}")

                    # if jsonData[i]['_source']['layers']['dns']['Queries'][0] is not None:
                    #     # print(f"Current: {jsonData[i]['_source']['layers']['dns']['Queries'][0]}")
                    #     if "dns.qry.name" in jsonData[i]['_source']['layers']['dns']['Queries']
                    #     ['94-140-14-14-1-pl95.packetloss.syssec-research.mmci.uni-saarland.de: type A, class IN']:
                    #         current_query_name = jsonData[i]['_source']['layers']['dns'][0]["dns.qry.name"]
                    #         currentPacket.query_name = current_query_name

                # Get latencies of the answer packets
                # print(data[i]['_source']['layers']['dns'])
                # To get the dns_time, the packet must have an "Answers" section
                if 'Answers' in json_data[i]['_source']['layers']['dns']:
                    # Mark packet as Answer # TODO: Unnecessary bcs of dns.flags.response(is_answer_response)?
                    # is_answer = "1"
                    # Note: Not all answers has dns.time?
                    pass
                else:
                    # is_answer = "0"
                    pass
                # Get failure rate (RCODE only present when there is an Answers section in the JSON)
                # count of dns.flags.rcode != 0
                if 'dns.flags.response' in json_data[i]['_source']['layers']['dns']['dns.flags_tree']:  # DEBUG
                    # response_count = response_count + 1  # DEBUG
                    # print(f"Response count: {response_count}")  # DEBUG
                    # Query = 0, Response (Answer) = 1
                    # RCode only exists if dns packet has is an answer
                    if json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "0":
                        # is_query = "1"

                        # Count the message as query
                        answer_count_data[index].append("0")
                    if json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "1":
                        # Count the message as response (answer to query)
                        answer_count_data[index].append("1")
                        test_time_count += 1
                        # print(f"DNS ID: {jsonData[i]['_source']['layers']['dns']['dns.id']}")  # DEBUG
                        # if dns_id == jsonData[i]['_source']['layers']['dns']['dns.id']:  # DEBUG
                        #    duplicate = duplicate + 1  # DEBUG
                        #    # print(f"Duplicate: {duplicate}")  # DEBUG
                        # else:
                        #    test_count += 1
                        #    # print(f"Unique packet Count: {test_count}")  # DEBUG
                        rcode = json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
                        failure_rate_data[index].append(int(rcode))

                        # Examine all the packets with the given rcodes only
                        # Ignore all other packets latencies
                        if len(rcodes) > 0:
                            if rcode not in rcodes:
                                continue
                                # if rcode == "0":
                                #     pass

                        # Assign packets RCODE
                        # response_code = rcode
                        # print(f"  rcode: {rcode}")  # DEBUG
                        # print(f"  currentPacket.response_code: {currentPacket.response_code}")  # DEBUG
                        # if rcode != "0":
                        #     test_failure_rate_count = test_failure_rate_count + 1
                        #     print(f"  test_failure_rate_count: {test_failure_rate_count}")  # DEBUG
                        # dns_id = jsonData[i]['_source']['layers']['dns']['dns.id']  # DEBUG
                        if 'dns.time' in json_data[i]['_source']['layers']['dns']:
                            # print(f"DNS ID: {jsonData[i]['_source']['layers']['dns']['dns.id']}")  # DEBUG
                            # Assign the dns response latency
                            # response_latency = jsonData[i]['_source']['layers']['dns']['dns.time']

                            dns_time = json_data[i]['_source']['layers']['dns']['dns.time']
                            packetlossData[index].append(float(dns_time))
                # Get the TC Bit
                # if 'dns.flags.truncated' in json_data[i]['_source']['layers']['dns']['dns.flags_tree']:
                # truncated = jsonData[i]['_source']['layers']['dns']['dns.flags_tree'][
                #     'dns.flags.truncated']
                #     pass
                # Get the DNS ID of the current DNS packet to check
                # if the next packet has the same ID to detect duplicates
                # dns_id = jsonData[i]['_source']['layers']['dns']['dns.id']  # Detect duplicates
                # Set the dns id to the current packet
                # dns_idx = jsonData[i]['_source']['layers']['dns']['dns.id']

                # Add the current dns packet to the list
                # append(currentPacket)
                # dns_packets_count_test = dns_packets_count_test + 1

                # packetlossData[index].append(currentPacket)
                if "dns.retransmission" in json_data[i]['_source']['layers']['dns']:
                    retransmission_data[index] += 1
            # else:
            #     not_dns = not_dns + 1
        print(f"  dns.time count: {test_time_count}")
        index = index + 1

        # This was outside the for loop
        # print(f"Packetloss rate: {current_packetloss_rate}")
        # print(f"    DNS Packet count: {dns_packets_count}")
        # print(f"  Non-DNS Packet count: {not_dns}")
        # Reset the packet count for the next packetloss config
        # dns_packets_count = 0
        # not_dns = 0


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


def add_dummy_value_to_empty_list():
    # If a list is empty (because all the packets were dropped and
    # there were no packets with latency), plotting gives an error
    # Spot the empty lists, add a dummy value
    global packetlossData
    for packet in packetlossData:
        print(f"  packet: {packet}")
        if len(packet) == 0:
            packet.append(float(-0.5))

def create_box_plot(file_name_prefix, bottom_limit, upper_limit):
    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percantage')

    user = file_name_prefix.split("_")[0]
    ax.set_title(f"Response Failure Rate for {user}")

    # y-axis labels
    ax.set_xticklabels(['0', '10', '20', '30', '40', '50', '60', '70', '80', '85', '90', '95'])
    # TODO: Fix UserWarning: FixedFormatter should only be used together with FixedLocator

    add_dummy_value_to_empty_list()

    # Creating plot
    # bp = ax.boxplot(packetlossData)
    ax.boxplot(packetlossData)

    # TODO: include the count of packets in the graph
    # len(packetlossData[i])

    plt.ylim(bottom=bottom_limit, top=upper_limit)
    # save plot as png
    plt.savefig((file_name_prefix + '_boxPlotLatency.png'), bbox_inches='tight')
    # show plot
    plt.show()


def create_violin_plot(file_name_prefix, bottom_limit, upper_limit):
    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percantage')
    user = file_name_prefix.split("_")[0]
    ax.set_title(f"Response Failure Rate for {user}")

    add_dummy_value_to_empty_list()

    # Create and save Violinplot
    # bp = ax.violinplot(packetlossData)
    bp = ax.violinplot(dataset=packetlossData, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')
    plt.ylim(bottom=bottom_limit, top=upper_limit)
    # save plot as png
    plt.savefig((file_name_prefix + '_violinPlotLatency.png'), bbox_inches='tight')
    # show plot
    plt.show()


def create_bar_plot(file_name_prefix, bottom_limit, upper_limit):
    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    failure_rate_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                              '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary
    index = 0
    for current_packetloss_rate in packetloss_rates:
        # print(f"index: {index}")
        # print(f"Data: {failure_rate_data[index]}")
        fail_count = 0
        for x in range(len(failure_rate_data[index])):
            if failure_rate_data[index][x] != 0:
                fail_count += 1
        # divide by len(failure_rate_data[index]) and multiply by 100 to get the percentage of the failure rate
        failure_rate_data_dict[str(current_packetloss_rate)] = (fail_count / len(failure_rate_data[index])) * 100
        index = index + 1

    keys = list(failure_rate_data_dict.keys())
    values = list(failure_rate_data_dict.values())

    print(f"Failure rates: {keys}")
    print(f"Failure ratio: {values}")

    plt.figure(figsize=(10, 5))
    # fig = plt.figure(figsize=(10, 5))

    # creating the bar plot
    plt.bar(failure_rates, values, color='maroon', width=4)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Response Failure Rate")
    user = file_name_prefix.split("_")[0]
    plt.title(f"Response Failure Rate for {user}")
    plt.ylim(bottom=bottom_limit, top=upper_limit)
    # save plot as png
    plt.savefig((file_name_prefix + '_barPlotResponseFailureRate.png'), bbox_inches='tight')
    # shot plot
    plt.show()


# File prefixes of JSON files
file_names = ["client", "auth1", "auth2"]

# Define limits of the plots
bottom_limit_client = 0
# If rcode_filter is True, recommended upper_limit_client value is
# 11 for client when rcode is "0", for rcode != "0", do 30
upper_limit_client = 30
bottom_limit_auth = 0
upper_limit_auth = 1  # If rcode_filter is True, recommended value is 11 for client
rcodes = ["0"]  # Examine all the packets only with given rcodes, if empty -> no filtering
# rcodes = ["0"]  # All packets with no error
# rcodes = ["2", "5"]  # All packets with ServFail or Refused
# rcodes = []  # To see all the packets
filtered_resolvers = ["77-88-8-1", "77-88-8-8"]  # Filter these IP from the results. If empty -> no filtering
# "77-88-8-1", "77-88-8-8" Yandex 1 and Yandex 2

for file_name in file_names:

    # Read the client logs
    read_json_files(file_name, rcodes, filtered_resolvers)

    # Add the filtering options to the file name of the plots
    filter_names_on_filename = ""

    # Set the lower-upper limits of the plots
    # Since the client and authoritative plots are very different,
    # set different limits for each
    bottom_limit = 0
    upper_limit = 11
    if file_name != "client":
        bottom_limit = bottom_limit_auth
        upper_limit = upper_limit_auth
    else:
        bottom_limit = bottom_limit_client
        upper_limit = upper_limit_client

    # If rcode is applied, add the filter to the file name
    if len(rcodes) > 0:
        filter_names_on_filename += "_rcodeFilter-"
        for rcode in rcodes:
            filter_names_on_filename += (rcode + "-")

    if len(filtered_resolvers) > 0:
        filter_names_on_filename += "_IPFilter-"
        for ip in filtered_resolvers:
            filter_names_on_filename += (get_operator_name_from_ip(ip) + "-")

    file_name += filter_names_on_filename

    # Create plots
    create_box_plot(file_name, bottom_limit, upper_limit)
    create_violin_plot(file_name, bottom_limit, upper_limit)
    create_bar_plot(file_name, bottom_limit, 100)

    # Show answer-query count
    show_answer_query_count(answer_count_data)

    # Show retransmission counts
    show_restransmission_data(retransmission_data)

    # Show latencies
    show_latencies(packetlossData)

    show_failure_count()

    # Clear lists for the next JSON files
    clear_list(answer_count_data)
    clear_list(packetlossData)
    # Reset the retransmission_data
    for i in retransmission_data:
        i = 0
    # Clear failure rate data:
    for lst in failure_rate_data:
        lst.clear()
