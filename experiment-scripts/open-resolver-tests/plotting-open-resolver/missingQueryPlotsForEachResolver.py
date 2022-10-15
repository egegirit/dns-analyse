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

# Store all packets by their packetloss rates
# client Packets
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

# auth Packets
packet_pl0_2 = []
packet_pl10_2 = []
packet_pl20_2 = []
packet_pl30_2 = []
packet_pl40_2 = []
packet_pl50_2 = []
packet_pl60_2 = []
packet_pl70_2 = []
packet_pl80_2 = []
packet_pl85_2 = []
packet_pl90_2 = []
packet_pl95_2 = []
all_packets_pl_2 = [packet_pl0_2, packet_pl10_2, packet_pl20_2, packet_pl30_2, packet_pl40_2, packet_pl50_2,
                  packet_pl60_2, packet_pl70_2, packet_pl80_2, packet_pl85_2, packet_pl90_2, packet_pl95_2
                  ]

# All the packets in all of the JSON files
all_packets = []  # client
all_packets_2 = []  # auth

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


def get_ip_with_dashes_from_operator_name(operator_name):
    return operators[operator_name]


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


def extract_ip_adr_with_dashes_from_packet(packet):
    query_name = extract_query_name_from_packet(packet)
    result = ""
    result += query_name.split("-")[0] + "-" + query_name.split("-")[1] + "-" + query_name.split("-")[2] + "-" + \
              query_name.split("-")[3]
    return result


# Get the packetloss string of the json packet
def get_packetloss_rate_of_packet(packet):
    query_name = extract_query_name_from_packet(packet)
    if query_name is not None:
        query_ab_pl_rate = query_name.split("-")[5]
        pl_rate = query_ab_pl_rate.split(".")[0]
        return pl_rate  # <ipnr>-<ipnr>-<ipnr>-<ipnr>-<counter>-pl*.
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

        # Examine all the packets in the JSON file with a packetloss rate config
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
                global all_packets_pl_2

                if file_prefix == "client":
                    all_packets_pl[index].append(json_data[i])
                    all_packets.append(json_data[i])
                elif file_prefix == "auth1":
                    all_packets_pl_2[index].append(json_data[i])
                    all_packets_2.append(json_data[i])

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


def loop_all_packets_get_all_query_names(file_name):
    global client_query_names
    global auth_query_names
    global all_packets_pl
    global all_packets_pl_2
    global all_packets
    global all_packets_2

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

    if file_name == "client":
        print(f"       Filling client_query_names")

        for packet in all_packets:
            qry_name = extract_query_name_from_packet(packet)
            pl_rate_of_pkt = get_packetloss_rate_of_packet(packet)
            pl_index = get_index_of_packetloss_rate(pl_rate_of_pkt)
            if qry_name not in client_query_names[pl_index]:
                client_query_names[pl_index].append(qry_name)

        # index = 0
        # for pl_rate in all_packets_pl:
        #     for packet in pl_rate:
        #         # Note, no check if query or response
        #         query_name_of_current_packet = extract_query_name_from_packet(packet)
        #         # If query already in list, don't add a duplicate
        #         if query_name_of_current_packet not in client_query_names[index]:
        #             client_query_names[index].append(query_name_of_current_packet)
        #     index += 1
    elif file_name == "auth1":
        print(f"       Filling auth_query_names")

        for packet in all_packets_2:
            qry_name = extract_query_name_from_packet(packet)
            pl_rate_of_pkt = get_packetloss_rate_of_packet(packet)
            pl_index = get_index_of_packetloss_rate(pl_rate_of_pkt)
            if qry_name not in auth_query_names[pl_index]:
                auth_query_names[pl_index].append(qry_name)

        #index = 0
        #for pl_rate in all_packets_pl:
        #    for packet in pl_rate:
        #        # Note, no check if query or response
        #        query_name_of_current_packet = extract_query_name_from_packet(packet)
        #        # If query already in list, don't add a duplicate
        #        if query_name_of_current_packet not in auth_query_names[index]:
        #            auth_query_names[index].append(query_name_of_current_packet)
        #    index += 1


# Create a bar plot showing how many queries are not sent to the auth server
def create_missing_query_bar_plot_for_auth(operator_specific_packet_list):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0] is not None:
        operator_name = find_operator_name_of_json_packet(operator_specific_packet_list[0])

    print(f" Creating missing query bar plot: {operator_name}")

    # if operator_name == "CleanBrowsing1":
    #     print(f"    CleanBrowsing1 MATCH!")

    global client_query_names
    global auth_query_names

    # for query in auth_query_names:
    #     if "185-228-168-168-27-pl0.packetloss.syssec-research.mmci.uni-saarland.de" in query:
    #         print(f"  WAAAA!")

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

    # debug = False
    # print(f"  from plotting: len(client_query_names): {len(client_query_names)}")
    # print(f"  from plotting: len(auth_query_names): {len(auth_query_names)}")
    # index = 0
    # for packet in operator_specific_packet_list:
    #     index += 1

    # From the global list that has all the client queries, get all the queries of the current resolver
    # And separate them into different packetloss rates
    index = 0
    for client_query_names_pl in client_query_names:
        for client_query_name_pl in client_query_names_pl:
            ip_of_operator = get_ip_with_dashes_from_operator_name(operator_name)
            if ip_of_operator in client_query_name_pl:
                # if operator_name in find_operator_name_of_json_packet(client_query_name_pl):
                query_name_of_current_packet = client_query_name_pl
                # If the query not already examined, take it into the list
                if query_name_of_current_packet not in all_client_query_names_op_specific[index]:
                    all_client_query_names_op_specific[index].append(query_name_of_current_packet)
        index += 1

    # print(f"      FINISHED READING CLIENT @@@@@@")

    # From the global list that has all the auth queries, get all the queries of the current resolver
    # And separate them into different packetloss rates
    index = 0
    for auth_query_names_pl in auth_query_names:
        for auth_query_name_pl in auth_query_names_pl:
            # if auth_query_name_pl == "185-228-168-168-27-pl0.packetloss.syssec-research.mmci.uni-saarland.de":
            #     debug = True
            #     print(f"  WROONG!!")
            #     print(f"  27. Counter!")
            #    print(f"  Name: {auth_query_name_pl}")
            # else:
            #     debug = False
            # Check if the query packet is a packet of the current resolver
            # Check if the query name is a name of the current resolver
            ip_of_operator = get_ip_with_dashes_from_operator_name(operator_name)
            if ip_of_operator in auth_query_name_pl:
                # if debug:
                #     print(f" Matched auth {operator_name} with {auth_query_name_pl}")
                query_name_of_current_packet = auth_query_name_pl
                # If the query not already examined, take it into the list
                if query_name_of_current_packet not in all_auth_query_names_op_specific[index]:
                    # if debug:
                    #     print(f"   Added to auth {auth_query_name_pl}")
                    all_auth_query_names_op_specific[index].append(query_name_of_current_packet)
        index += 1

    # print(f"      FINISHED READING AUTH @@@@@@")

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    missing_query_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                               '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary

    # index = 0
    # for all_client_query_names in all_client_query_names_op_specific:
    #     print(f"Length of all_client_query_names[{index}]: {len(all_client_query_names)}")
    #     index += 1

    # index = 0
    # for all_auth_query_names in all_auth_query_names_op_specific:
    #     print(f"Length of all_auth_query_names[{index}]: {len(all_auth_query_names)}")
    #     index += 1

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
    plt.title(f"Missing Query Count For Authoritative Server ({operator_name})")

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

    # When creating missing queries on auth, make sure you read all the JSON files of both client and auth
    # auth_and_client_read = False
    for file_name in file_names:
        print(f"Executing for {file_name}")
        # Read the JSON files and store all the dns packets
        # into these global lists:
        # all_packets_pl, all_packets_pl_2, all_packets, list_of_operators
        initialize_packet_lists(file_name, opt_filter)

        # Loop all packets of client, get all the unique query names of the queries, store in
        # client_query_names, and also get all the unique query names of responses,
        # store in client_responses_query_names
        print(f"         @@ All packets of JSON: {len(all_packets)}")

        loop_all_packets_get_all_query_names(file_name)

    # Calculate, how many client queries are not redirected to the auth server
    # by the resolver suing client_query_names and auth_query_names
    for operator in list_of_operators:
        create_missing_query_bar_plot_for_auth(operator)

    print(f"Printing client query counts for each packetloss rate")
    a = 0
    for query_name_pl in client_query_names:
        print(f"{a}. packetloss rate query count: {len(query_name_pl)}")
        # for query_name in query_name_pl:
        #     print(f"{query_name}")
        a += 1

    print(f"Printing auth query counts for each packetloss rate")
    a = 0
    for query_name_pl in auth_query_names:
        print(f"{a}. packetloss rate query count: {len(query_name_pl)}")
        # for query_name in query_name_pl:
        #     print(f"{query_name}")
        a += 1

    clear_missing_query_lists()


# List that store unique query names for each packetloss rate
# to find not redirected queries for auth server
client_query_names_pl0 = []
client_query_names_pl10 = []
client_query_names_pl20 = []
client_query_names_pl30 = []
client_query_names_pl40 = []
client_query_names_pl50 = []
client_query_names_pl60 = []
client_query_names_pl70 = []
client_query_names_pl80 = []
client_query_names_pl85 = []
client_query_names_pl90 = []
client_query_names_pl95 = []
client_query_names = [
    client_query_names_pl0,
    client_query_names_pl10,
    client_query_names_pl20,
    client_query_names_pl30,
    client_query_names_pl40,
    client_query_names_pl50,
    client_query_names_pl60,
    client_query_names_pl70,
    client_query_names_pl80,
    client_query_names_pl85,
    client_query_names_pl90,
    client_query_names_pl95
]

auth_query_names_pl0 = []
auth_query_names_pl10 = []
auth_query_names_pl20 = []
auth_query_names_pl30 = []
auth_query_names_pl40 = []
auth_query_names_pl50 = []
auth_query_names_pl60 = []
auth_query_names_pl70 = []
auth_query_names_pl80 = []
auth_query_names_pl85 = []
auth_query_names_pl90 = []
auth_query_names_pl95 = []
auth_query_names = [
    auth_query_names_pl0,
    auth_query_names_pl10,
    auth_query_names_pl20,
    auth_query_names_pl30,
    auth_query_names_pl40,
    auth_query_names_pl50,
    auth_query_names_pl60,
    auth_query_names_pl70,
    auth_query_names_pl80,
    auth_query_names_pl85,
    auth_query_names_pl90,
    auth_query_names_pl95
]

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
