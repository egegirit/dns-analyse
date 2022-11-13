import sys
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import json
import re
import os
import time

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

operator_packets = {
    "AdGuard1": [],
    "AdGuard2": [],
    "CleanBrowsing1": [],
    "CleanBrowsing2": [],
    "Cloudflare1": [],
    "Cloudflare2": [],
    "Dyn1": [],
    "Dyn2": [],
    "Google1": [],
    "Google2": [],
    "Neustar1": [],
    "Neustar2": [],
    "OpenDNS1": [],
    "OpenDNS2": [],
    "Quad91": [],
    "Quad92": [],
    "Yandex1": [],
    "Yandex2": []
}

responses_pl_rate = {
    "0": 0,
    "10": 0,
    "20": 0,
    "30": 0,
    "40": 0,
    "50": 0,
    "60": 0,
    "70": 0,
    "80": 0,
    "85": 0,
    "90": 0,
    "95": 0,
    "100": 0,
}

queries_pl_rate = {
    "0": 0,
    "10": 0,
    "20": 0,
    "30": 0,
    "40": 0,
    "50": 0,
    "60": 0,
    "70": 0,
    "80": 0,
    "85": 0,
    "90": 0,
    "95": 0,
    "100": 0,
}

norerror_pl_rate = {
    "0": 0,
    "10": 0,
    "20": 0,
    "30": 0,
    "40": 0,
    "50": 0,
    "60": 0,
    "70": 0,
    "80": 0,
    "85": 0,
    "90": 0,
    "95": 0,
    "100": 0,
}

failed_packet_pl_rate = {
    "0": 0,
    "10": 0,
    "20": 0,
    "30": 0,
    "40": 0,
    "50": 0,
    "60": 0,
    "70": 0,
    "80": 0,
    "85": 0,
    "90": 0,
    "95": 0,
    "100": 0,
}

# For example if we are reading the pcap for 10 packetloss rate,
# but there are packets with other packetloss rates in their queries,
# filter and count them
non_matching_pl_rate = {
    "0": 0,
    "10": 0,
    "20": 0,
    "30": 0,
    "40": 0,
    "50": 0,
    "60": 0,
    "70": 0,
    "80": 0,
    "85": 0,
    "90": 0,
    "95": 0,
    "100": 0,
}

stale_count_of_pl = {
    "0": 0,
    "10": 0,
    "20": 0,
    "30": 0,
    "40": 0,
    "50": 0,
    "60": 0,
    "70": 0,
    "80": 0,
    "85": 0,
    "90": 0,
    "95": 0,
    "100": 0,
}

non_stale_count_of_pl = {
    "0": 0,
    "10": 0,
    "20": 0,
    "30": 0,
    "40": 0,
    "50": 0,
    "60": 0,
    "70": 0,
    "80": 0,
    "85": 0,
    "90": 0,
    "95": 0,
    "100": 0,
}

latency_of_stales_pl = {
    "0": [],
    "10": [],
    "20": [],
    "30": [],
    "40": [],
    "50": [],
    "60": [],
    "70": [],
    "80": [],
    "85": [],
    "90": [],
    "95": [],
    "100": [],
}

auth_json_prefix = "auth_stale_pl"
client_json_prefix = "client_stale_pl"

ttl_wait_time = 124
wait_packetloss_config = 595

all_query_names = set()


def read_json_file(filename, pl_rate):
    print(f"Reading file: {filename}")
    if not os.path.exists("./" + filename):
        print(f"File not found: {filename}")
        exit()
    # Read the measured latencies from json file
    file = open(filename)
    json_data = json.load(file)
    packet_count = len(json_data)
    print(f"  Number of packets in JSON file: {packet_count}")

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
                print(f"Skipping invalid domain name: {query_name}")
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

            elif wait_packetloss_config < time_diff_abs < 700:
                # print(f"  @@@@@ First packet after cooldown phase")
                phase_index = 0
                # print(f"  Adding packet to phase: {phases[phase_index]}")

            elif time_diff_abs >= 700:
                # print(f"  @@@@@ NEW EXPERIMENT BEGIN?")
                phase_index = 0
                # print(f"  Adding packet to phase: {phases[phase_index]}")

            frame_time_relative_of_previous = frame_time_relative

            global stale_count_of_pl
            global non_stale_count_of_pl
            global latency_of_stales_pl
            # Count if query was stale
            if is_response == "1" and phases[phase_index] == "Stale":
                latency_of_stales_pl[pl_rate_of_query_name].append(dns_time)
                # print(f"    Added latency")
                if pl_rate_of_query_name in a_record:
                    # print("1")
                    stale_count_of_pl[pl_rate_of_query_name] += 1
                    # print(f"    Marked as stale")
                else:
                    # print("0")
                    non_stale_count_of_pl[pl_rate_of_query_name] += 1
                    # print(f"    Marked as Non-stale")

            # Calculate failure rate of stale phase packets
            if is_response == "1" and phases[phase_index] == "Stale":
                if str(rcode) != "0":
                    failed_packet_pl_rate[str(pl_rate)] += 1
                elif str(rcode) == "0":
                    norerror_pl_rate[str(pl_rate)] += 1

            # Test
            if phases[phase_index] == "Stale":
                if is_response == "1":
                    responses_pl_rate[str(pl_rate)] += 1
                elif is_response == "0":
                    queries_pl_rate[str(pl_rate)] += 1

            # if query_name == "stale-8-8-8-8-100-Mqs-0.packetloss.syssec-research.mmci.uni-saarland.de" and is_response == "1" and phases[phase_index] == "Stale":
            #     time.sleep(20)


for current_pl_rate in packetloss_rates:
    print(f"Current packetloss rate: {current_pl_rate}")

    client_json_file_name = client_json_prefix + str(current_pl_rate) + ".json"
    # auth_json_file_name = auth_json_prefix + current_pl_rate + ".json"

    read_json_file(client_json_file_name, current_pl_rate)

    # Group all the packets into prefetching(1,2, ...) and stale(1,2,...) phase.
    # phase_packets = {
    #     "prefetch": [],
    #     "stale": []
    # }
    # current_phase = "prefetch"
    # wait_time = 120
    # wait_packetloss_config = 599
    # add current_packet to current_phase
    # next_packet
    # time_diff_of_packets = abs(next_packet.time - current_packet.time)
    # if time_diff_of_packets < wait_time:
    #     phase_packets[current_phase].add(next_packet)
    # elif time_diff_of_packets > wait_time and time_diff_of_packets < wait_packetloss_config:
    #     current_phase = "stale"
    #     phase_packets[current_phase].add(next_packet)
    # elif time_diff_of_packets > wait_packetloss_config:
    #     current_phase = "prefetch"
    #     phase_packets[current_phase].add(next_packet)

    # For the stale record phase packets, Check if the last Octet of the A record answer == current_pl_rate or == (current_pl_rate + 1)
    # Get the ratio of stale records, measure latency of the stale record responses

print(f"---------------")

print(f"Non matching (filtered) pl rates:{non_matching_pl_rate}")

print(f"Stale rates:")
for i in packetloss_rates:
    print(
        f"PL {i}: {stale_count_of_pl[str(i)]}/{stale_count_of_pl[str(i)] + non_stale_count_of_pl[str(i)]} = {stale_count_of_pl[str(i)] / (stale_count_of_pl[str(i)] + non_stale_count_of_pl[str(i)])}")

print(f"\nResponse packet counts:{responses_pl_rate}")
print(f"Query packet counts:{queries_pl_rate}")

print(f"Failed packet counts:{failed_packet_pl_rate}")
print(f"No error packet counts:{norerror_pl_rate}\n")

print(f"Failure rates:")
for i in packetloss_rates:
    print(
        f"PL {i}: {failed_packet_pl_rate[str(i)]}/{failed_packet_pl_rate[str(i)] + norerror_pl_rate[str(i)]} = {failed_packet_pl_rate[str(i)] / (failed_packet_pl_rate[str(i)] + norerror_pl_rate[str(i)])}")
