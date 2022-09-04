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

# Instead of saving rcodes one by one, save the sum of errors in one packetloss config
# failure_rate_data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

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


def get_operator_name_from_ip(ip_addr_with_dashes):
    for operator, ip_addr in operators.items():
        if ip_addr == ip_addr_with_dashes:
            return operator
    else:
        return "Not found!"


def clear_list(multi_list):
    for lst in multi_list:
        lst.clear()


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
                        # failure_rate_data[index].append(int(rcode))

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
    global latencyData
    for packet in latencyData:
        # print(f"  packet: {packet}")
        if len(packet) == 0:
            packet.append(float(-0.5))


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


def create_box_plot(file_name_prefix, bottom_limit, upper_limit, log_scale=False):
    print(f" Creating box plot: {file_name_prefix}")

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

    if log_scale:
        ax.set_yscale('log', base=2)
    # else: ax.set_yscale('linear')

    # Creating plot
    # bp = ax.boxplot(packetlossData)
    ax.boxplot(latencyData)

    # TODO: include the count of packets in the graph
    # len(packetlossData[i])

    plt.ylim(bottom=bottom_limit, top=upper_limit)
    # save plot as png
    plt.savefig((file_name_prefix + '_boxPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name_prefix}")


def create_violin_plot(file_name_prefix, bottom_limit, upper_limit, log_scale=False):
    print(f" Creating violin plot: {file_name_prefix}")

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

    if log_scale:
        ax.set_yscale('log', base=2)

    # Create and save Violinplot
    # bp = ax.violinplot(packetlossData)
    bp = ax.violinplot(dataset=latencyData, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')
    plt.ylim(bottom=bottom_limit, top=upper_limit)
    # save plot as png
    plt.savefig((file_name_prefix + '_violinPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created violin plot: {file_name_prefix}")


def create_bar_plot_old(file_name_prefix, bottom_limit, upper_limit):
    print(f" Creating bar plot: {file_name_prefix}")

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
        # fail_count = 0
        # for x in range(len(failure_rate_data[index])):
        # if failure_rate_data[index][x] != 0:
        # fail_count += 1

        fail_count = failure_rate_data[index]

        # divide by len(failure_rate_data[index]) and multiply by 100 to get the percentage of the failure rate
        # failure_rate_data_dict[str(current_packetloss_rate)] = (fail_count / len(failure_rate_data[index])) * 100

        # Divide by 900 because we send 900 queries from client pro packetloss config (18 Resolver * 50 counter),
        # multiply by 100 because we want the percentage
        failure_rate_data_dict[str(current_packetloss_rate)] = (fail_count / 1800) * 100
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
    # plt.show()
    print(f" Created bar plot: {file_name_prefix}")


# failure_rate_data is already filled when looping the packets
def create_bar_plot_failure(file_name, bottom_limit, upper_limit):
    print(f" Creating bar plot: {file_name}")

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
        fail_count = 0
        # Loop all the rcodes of the current packetloss rate
        for x in range(len(failure_rate_data[index])):
            if failure_rate_data[index][x] is not None and failure_rate_data[index][x] != "0":
                fail_count += 1
        # print(f"Fail count: {fail_count}")
        if fail_count != 0:
            # Divide by 900 because we send 900 queries from client pro packetloss config (18 Resolver * 50 counter),
            # when you filter by an IP, you need to adjust the query_count_per_pl_rate like so:
            query_count_per_pl_rate = 900 - (len(filtered_resolvers) * 50)
            # print(f"query_count_per_pl_rate: {query_count_per_pl_rate}")
            failure_rate_data_dict[str(current_packetloss_rate)] = (fail_count / query_count_per_pl_rate) * 100
        else:
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

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Response Failure Rate")
    plt.title(f"Overall Response Failure Rate")
    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # save plot as png
    plt.savefig((file_name + '_barPlotResponseFailureRate.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created bar plot: {file_name}")


# failure_rate_data is already filled when looping the packets
def create_bar_plot_retransmission(file_name, bottom_limit, upper_limit, use_limits=False):
    print(f" Creating retransmission plot: {file_name}")
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

    # creating the bar plot
    plt.bar(failure_rates, values, color='blue', width=4)

    # set labels
    plt.xlabel("Packetloss Rate")
    plt.ylabel("DNS Retransmission Count")
    plt.title(f"Overall Retransmission Count")

    if use_limits:
        plt.ylim(bottom=bottom_limit, top=upper_limit)

    # save plot as png
    plt.savefig((file_name + '_barPlotRetransmissionCount.png'), bbox_inches='tight')
    # shot plot
    # plt.show()
    print(f" Created retransmission plot: {file_name}")
    # f.write(f" Created retransmission plot: {file_name}\n")


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


# Same as finding all unique queries?
def find_total_query_count():
    global all_packets_pl

    pass


# Warning: Slow run time
def find_all_packets_with_query_name(query_name):
    # print(f"    find_all(): Returning all packets with query name: {query_name}")
    # Check the packetloss rate of the query name
    list_to_search = []
    global all_packets_pl
    if "pl0" in query_name:
        list_to_search = all_packets_pl[0]
    elif "pl10" in query_name:
        list_to_search = all_packets_pl[1]
    elif "pl20" in query_name:
        list_to_search = all_packets_pl[2]
    elif "pl30" in query_name:
        list_to_search = all_packets_pl[3]
    elif "pl40" in query_name:
        list_to_search = all_packets_pl[4]
    elif "pl50" in query_name:
        list_to_search = all_packets_pl[5]
    elif "pl60" in query_name:
        list_to_search = all_packets_pl[6]
    elif "pl70" in query_name:
        list_to_search = all_packets_pl[7]
    elif "pl80" in query_name:
        list_to_search = all_packets_pl[8]
    elif "pl85" in query_name:
        list_to_search = all_packets_pl[9]
    elif "pl90" in query_name:
        list_to_search = all_packets_pl[10]
    elif "pl95" in query_name:
        list_to_search = all_packets_pl[11]

    packets_with_query_name = []
    for packet in list_to_search:
        if extract_query_name_from_packet(packet) == query_name:
            # print(f"      Match: {query_name}")
            # print(f"      Frame time of Match: {get_frame_time_relative_of_packet(packet)}")
            # print(f"        Added to list")
            packets_with_query_name.append(packet)

    # DEBUG
    # for pac in list_to_search:
    #     print(f"    list_to_search packet: {extract_query_name_from_packet(pac)}")

    # DEBUG
    # for pac in packets_with_query_name:
    #     print(f"    Found packet with query: {extract_query_name_from_packet(pac)}")

    # sys.exit()

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
        # Filter responses of client, reponse must have destination IP of client
        if file_name == "client":
            if not dst_ip_match(packet, client_only_dest_ips):
                continue

        # New condition to filter NS record answers of anycast
        # and get only responses with A records
        if "Answers" in packet['_source']['layers']['dns']:
            response = packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response']
            # print(f"Response: {response}")
            if response == "1":
                responses.append(packet)
    return responses


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


# Latency (between first query and answer) algorithm 2
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

    # Get the dns.time if it exists
    # Note: the packet has to have "Answers" section because an NS record has also dns.time,
    # but we want A record for resolution. But NS records can be filtered in the beginning now.
    if 'dns.time' in current_packet['_source']['layers']['dns']:  # and "Answers" in current_packet['_source']['layers']['dns']:  # New and condition
        dns_time = float(current_packet['_source']['layers']['dns']['dns.time'])
        latency = dns_time

        query_name_of_packet = extract_query_name_from_packet(current_packet)
        # If already calculated, skip
        if query_name_of_packet is not None:
            if query_name_of_packet in calculated_queries:
                # print(f"    !! You already calculated latency for: {query_name_of_packet}")
                # f.write(f"    !! You already calculated latency for: {query_name_of_packet}\n")
                return None

        packets = find_all_packets_with_query_name(query_name_of_packet)

        # EDGE CASE: there were duplicate queries, but some of them actually are answered and some of them are not
        # How to handle: calculate the time between the first query, and the first answer.
        # Because the first answer is valid, all other answers are not needed
        responses = find_the_response_packets(packets, file_name)

        first_term = 0
        last_term = 0

        # TODO: check if the packet is an answer to check if the len(packets) > 1 ?
        # If there are more than two packets with the same query name, there are duplicates (2 = query + answer)
        if len(packets) > 2:

            # Get only all the query packets of the packets with the same query name
            queries = find_the_query_packets(packets, file_name)

            lowest_frame_no_of_queries = find_lowest_frame_no(queries)
            query_packet_with_lowest_frame_no = get_packet_by_frame_no_from_list(lowest_frame_no_of_queries, queries)
            # get the relative frame time of packet
            rel_fr_time_of_first_query = get_frame_time_relative_of_packet(query_packet_with_lowest_frame_no)

            last_term = rel_fr_time_of_first_query

            # If there are multiple answers to the same query, find the first answer (lower latency as a result)
            if len(responses) > 1:
                # print(f"  @@ Found multiple same answers for: {query_name_of_packet}")
                # f.write(f"  @@ Found multiple same answers for: {query_name_of_packet}\n")

                lowest_frame_no_of_responses = find_lowest_frame_no(responses)
                response_packet_with_lowest_frame_no = get_packet_by_frame_no_from_list(lowest_frame_no_of_responses,
                                                                                        responses)
                # get the relative frame time of packet
                rel_fr_time_of_first_response = get_frame_time_relative_of_packet(response_packet_with_lowest_frame_no)

                first_term = rel_fr_time_of_first_response

                # (Old)
                # frame_time_of_first_response = find_lowest_relative_frame_time_of_packets(responses)
                # first_term = frame_time_of_first_response
            # If there was only one answer to multiple queries, the current packet is this only answer
            elif len(responses) == 1:
                # print(f"  Only one answer but multiple queries for: {query_name_of_packet}")
                # f.write(f"  Only one answer but multiple queries for: {query_name_of_packet}\n")
                first_term = get_frame_time_relative_of_packet(current_packet)

            # Latency is the difference between the relative frame times of the answer and the first query
            latency = first_term - last_term

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
        else:
            # print(f"Lantecy: {latency}")
            return latency
    # Adding the latency to the array is done outside of this function
    # Append only if result is not none:
    # latency = calculate_latency_of_packet(current_packet, i)
    # if latency != None:
    #    latencyData[i].append(latency)
    return None


# Failure rate of client: Count of rcode != 0 for each query name + unanswered unique query count
# TODO: Failure rate of auth: unanswered unique query count (because there is no rcode != 0 in auth)
# Count as fail if no answer with RCODE != 0
def calculate_failure_rate_of_packet_old(current_packet, packetloss_index, file_name):
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
    if query_name_of_packet is not None:
        if query_name_of_packet in calculated_failure_queries:
            return

    rcode_is_error = False

    # If the packet is a response with no error, dont examine it, count as success
    if 'dns.flags.rcode' in current_packet['_source']['layers']['dns']['dns.flags_tree']:
        current_rcode = current_packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
        if current_rcode == "0":
            calculated_failure_queries.append(query_name_of_packet)
            return
        # If there is a response with error, count as failure
        else:  # current_rcode != "0"
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

    # DEBUG
    # for q in queries:
    #     print(f"Query name of queries:{extract_query_name_from_packet(q)}")

    # the query had an answer packet to it, that must be handled before?

    # There was no response at all to the query, count as failure
    if responses_count == 0:
        failure_rate_data[packetloss_index] += 1
        # print(f"Incremented bcs no answer to {query_name_of_packet}")
        calculated_failure_queries.append(query_name_of_packet)
    # If this is the only answer, which has an error code, count as fail
    # But what if multiple error responses and not only one: Count as one
    elif rcode_is_error and responses_count >= 1:
        failure_rate_data[packetloss_index] += 1
        # print(f"Incremented bcs only answer with error")
        calculated_failure_queries.append(query_name_of_packet)


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
    # If the packet is a response with no error, dont examine it, count as success
    if 'dns.flags.rcode' in current_packet['_source']['layers']['dns']['dns.flags_tree']:
        current_rcode = current_packet['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
        if current_rcode == "0":
            calculated_failure_queries.append(query_name_of_packet)
            # Testing append 0
            failure_rate_data[packetloss_index].append("0")
            # if debug:
            #     print(f"  RCODE was 0; appended 0: {query_name_of_packet}")
            # TODO: What if multiple answers and multiple error codes + no error codes? -> Client success -> no error
            return
        # If there is a response with error, count as failure
        else:  # current_rcode != "0"
            # TODO: Debug, auth1 shouldnt get to here but it executes this
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
    elif rcode_is_error and responses_count >= 1:
        # failure_rate_data[packetloss_index] += 1  # OLD
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


# Set the global list of retransmission data
def calculate_retransmission_of_query(current_packet, packetloss_index, file_name):

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
            # if debug:
            # print(f"  Already calculated (skipping): {query_name_of_packet}")
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
        # print(f"  {file_name}: Multiple ({queries_count}) queries for: {query_name_of_packet}\n  Response count of it: {responses_count}\n  Packetloss index of it: {packetloss_index}")
        # for query in queries:
        #    print(f"    Found query names: {extract_query_name_from_packet(query)}")
        # for resp in responses:
        #     print(f"    Found response names: {extract_query_name_from_packet(resp)}")

        # f.write(f"  Multiple ({queries_count}) queries for: {query_name_of_packet}\n  Response count of it: {responses_count}\n  Packetloss index of it: {packetloss_index}\n")
        # Mark the query name as handled to not count other packets with query name again
        calculated_retransmission_queries.append(query_name_of_packet)
        # -1 Because the original (first) query doesn't count as duplicate
        duplicate_query_count = queries_count - 1

        # Set the global list that holds the duplicate count for each packetloss rate
        retransmission_data[packetloss_index] += duplicate_query_count
        # print(f"retransmission_data[{packetloss_index}]: {retransmission_data[packetloss_index]}")

        return duplicate_query_count
    else:
        # queries_count == 1 or 0 -> No duplicate
        return


# Read the JSON files and store all the dns packets
# into the global lists
def initialize_packet_lists(file_prefix, filter_ip_list, rcodes, opt_filter=False):
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

            # Store only given source and destination IP's in the ip_src and ip_dst lists
            # if len(ip_srcs) > 0:
            #     ip_src_of_packet = json_data[i]['_source']['layers']["ip"]["ip.src"]
            #     if ip_src_of_packet not in ip_srcs:
            #          # print(f"Skipping packet with ip_src: {ip_src_of_packet}")
            #         continue
            # if len(ip_dsts) > 0:
            #     ip_dst_of_packet = json_data[i]['_source']['layers']["ip"]["ip.dst"]
            #     if ip_dst_of_packet not in ip_dsts:
            #         # print(f"Skipping packet with ip_src: {ip_dst_of_packet}")
            #         continue

            if 'dns' in json_data[i]['_source']['layers']:
                # Check if the dns packet is generated by our experiment
                json_string = str(json_data[i]['_source']['layers']['dns']['Queries'])
                splitted_json1 = json_string.split("'dns.qry.name': ")
                splitted2 = str(splitted_json1[1])
                # print(f"splitted_json[1]: {splitted2}")
                query_name = splitted2.split("'")[1]
                # print(f"Current query name: {query_name}")

                # Check if the current IP is structured right
                # This filters dns packets that is not related to the experiment
                query_match = re.search(".*-.*-.*-.*-.*-pl.*.packetloss.syssec-research.mmci.uni-saarland.de",
                                        query_name)
                if query_match is None:
                    # print(f"Skipping invalid domain name: {query_name}")
                    continue

                # Filter by Ip Address
                splitted_domain = query_name.split("-")
                ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                                      splitted_domain[2] + "-" + splitted_domain[3]

                if ip_addr_with_dashes in filter_ip_list:
                    # print(f"Skipping filtered IP: {ip_addr_with_dashes}")
                    continue

                # Filter by RCode
                # Note: A packet might be a query, in that case, not all packets will have the desired RCODE
                if json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "1":
                    rcode = json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
                    if rcode not in rcodes:
                        # print(f"Skipping filtered RCODE: {rcode}")
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
                # print(f"Added: {query_name}")

        index = index + 1


# Loop all the json packets and calculate their latencies/response failure counts
def loop_all_packets_latencies_failures_retransmissions(file_name):
    print("Looping all packets to add latencies")
    # f.write("Looping all packets to add latencies\n")
    # global all_packets

    # for packet in all_packets:
    #     pass

    global all_packets_pl

    index = 0
    for packets_with_pl in all_packets_pl:
        # print(f"len(all_packets_pl): {len(all_packets_pl)}")
        # print(f"  len(packets_with_pl): {len(packets_with_pl)}")

        print(f"  INDEX/Packetloss rate: {index}")
        # f.write(f"  @@ Packetloss rate: {index}\n")
        for current_packet in packets_with_pl:

            # print(f"    len(current_packet): {len(current_packet)}")
            latency = calculate_latency_of_packet(current_packet, file_name)
            calculate_failure_rate_of_packet(current_packet, index, file_name)
            if latency is not None:
                latencyData[index].append(latency)
            calculate_retransmission_of_query(current_packet, index, file_name)
        index += 1


def show_all_latencies():
    print("Showing all latencies")
    global latencyData

    index = 0
    for pl_rate in latencyData:
        # print(f"{index}. Latencies: {pl_rate}")
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
        if ip_dst_of_packet in ip_list:
            return True
    return False


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


# File prefixes of JSON files
file_names = ["client", "auth1"]  # , "auth2"]

# Define limits of the plots
bottom_limit_client = 0
# If rcode_filter is True, recommended upper_limit_client value is
# 11 for client when rcode is "0", for rcode != "0", do 30
upper_limit_client = 50
bottom_limit_auth = 0
upper_limit_auth = 50  # If rcode_filter is True, recommended value is 11 for client
rcodes = ["0", "2"]  # Examine all the packets only with given rcodes, if empty -> no filtering
# rcodes = ["0"]  # All packets with no error
# rcodes = ["2", "5"]  # All packets with ServFail or Refused
# rcodes = []  # To see all the packets
filtered_resolvers = []  # Filter these IP from the results. If empty -> no filtering
# "77-88-8-1", "77-88-8-8" Yandex 1 and Yandex 2

client_only_source_ips = ["139.19.117.1"]
client_only_dest_ips = ["139.19.117.1"]

log_scale_y_axis = False
opt_filter = False

for file_name in file_names:

    # Read the json dns packets

    # Filter the source and destination IP's of client for only the client packet capture
    initialize_packet_lists(file_name, filtered_resolvers, rcodes, opt_filter)

    # file_name as argument because latency calculation needs to know if its client or auth capture
    loop_all_packets_latencies_failures_retransmissions(file_name)

    # print("Showing failures:")
    # for lst in failure_rate_data:
    #     print(f"List: {lst}")

    # print("latencyData:")
    # for lst in latencyData:
    #    print(f"List: {lst}")

    # Add the filtering options to the file name of the plots
    filter_names_on_filename = ""

    # Set the lower-upper limits of the plots
    # Since the client and authoritative plots are very different,
    # set different limits for each
    bottom_limit = 0
    upper_limit = 50
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

    if log_scale_y_axis:
        filter_names_on_filename += "_LogScaledY-"

    filter_names_on_filename += "Lim(" + str(bottom_limit) + "," + str(upper_limit) + ")"
    if opt_filter:
        filter_names_on_filename += "_OPT-filtered"

    if file_name == "client":
        if len(client_only_source_ips) > 0:
            filter_names_on_filename += "_SRC-IP-"
            for ip in client_only_source_ips:
                filter_names_on_filename += ip + "_"
        if len(client_only_dest_ips) > 0:
            filter_names_on_filename += "_DST-IP-"
            for ip in client_only_dest_ips:
                filter_names_on_filename += ip + "_"

    file_name += filter_names_on_filename

    # Create plots
    create_box_plot(file_name, bottom_limit, upper_limit, log_scale_y_axis)
    create_violin_plot(file_name, bottom_limit, upper_limit, log_scale_y_axis)
    create_bar_plot_failure(file_name, bottom_limit, 100)
    create_bar_plot_retransmission(file_name, bottom_limit, upper_limit, use_limits=False)

    # Show answer-query count
    # show_answer_query_count(answer_count_data)

    # Show retransmission counts
    # show_restransmission_data(retransmission_data)

    # Show latencies
    # show_latencies(packetlossData)

    # show_failure_count()

    prepare_for_next_iteration()
