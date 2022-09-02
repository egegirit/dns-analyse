import time
import numpy as np
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

class DNSPacket:
    def __init__(self, dns_idx, transport_protocol, query_name, is_answer, response_latency,
                 response_code, truncated, opcode, ip_src, ip_dst, is_answer_response, query_ip, packetloss_rate,
                 counter, is_query, operator, retransmission):
        self.query_name = query_name  # domain name
        self.ip_src = ip_src  # ip_src inside ["_source"]["layers"]["ip"]
        self.ip_dst = ip_dst  # ip_dst inside ["_source"]["layers"]["ip"]
        self.transport_protocol = transport_protocol  # udp or tcp inside ["_source"]["layers"]
        self.dns_idx = dns_idx  # dns.id inside dns
        self.is_answer = is_answer  # QR Flag in the header, 0 = Query, 1 = Response (Answer)
        self.is_answer_response = is_answer_response  # QR Flag in the header, 0 = Query, 1 = Response (Answer)
        self.truncated = truncated  # dns.flags.truncated inside dns.flags_tree
        # Following attributes are valid only if the dns packet is an answer
        self.response_latency = response_latency  # dns.time inside dns
        self.response_code = response_code  # RCODE = 0 -> No error, 1 -> Error: dns.flags.response inside dns.flags_tree
        self.opcode = opcode  # dns.flags.opcode inside dns.flags_tree
        self.query_ip = query_ip  # ip with dashes
        self.packetloss_rate = packetloss_rate
        self.counter = counter
        self.is_query = is_query
        self.operator = operator  # "Google1" etc
        self.retransmission = retransmission  # "1" or "0"


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


def read_json_files(file_prefix):
    # not_dns = 0
    # dns_packets_count = 0

    index = 0
    # Read the JSON file and for each captured packet, create a DNSPacket object,
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

        # Examine all the packets in the JSON file
        for i in range(0, packet_count):
            # Check if the packet is a DNS packet
            if 'dns' in json_data[i]['_source']['layers']:
                # dns_packets_count = dns_packets_count + 1

                # Create a dns packet object for the current packet
                currentPacket = DNSPacket("-", "-", "-", "0", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-",
                                          "-", "-")

                # Check if the DNS packet is using UDP as transport protocol
                if 'udp' in json_data[i]['_source']['layers']:
                    currentPacket.transport_protocol = "UDP"
                # Check if the DNS packet is using TCP as transport protocol
                if 'tcp' in json_data[i]['_source']['layers']:
                    currentPacket.transport_protocol = "TCP"
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
                    query_match = re.search(".*-.*-.*-.*-.*-pl.*.packetloss.syssec-research.mmci.uni-saarland.de",
                                            query_name)
                    if query_match is None:
                        continue

                    splitted_domain = query_name.split("-")
                    ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                                          splitted_domain[2] + "-" + splitted_domain[3]

                    op_name = get_operator_name_from_ip(ip_addr_with_dashes)

                    query_ip = ip_addr_with_dashes
                    counter = splitted_domain[4]
                    packetloss_rate = splitted_domain[5].split(".")[0]  # [2:]
                    test = splitted_domain[5].split(".")[0]

                    currentPacket.query_name = query_name
                    currentPacket.query_ip = query_ip
                    currentPacket.counter = counter
                    currentPacket.packetloss_rate = packetloss_rate
                    currentPacket.operator = op_name

                    # print(f"query_name: {query_name}")
                    # print(f"ip_addr_with_dashes: {ip_addr_with_dashes}")
                    # print(f"counter: {splitted_domain[4]}")
                    # print(f"packetloss_rate: {test}")

                    # if json_data[i]['_source']['layers']['dns']['Queries'][0] is not None:
                    #    # print(f"Current: {jsonData[i]['_source']['layers']['dns']['Queries'][0]}")
                    #     if "dns.qry.name" in jsonData[i]['_source']['layers']['dns']['Queries']
                    #     ['94-140-14-14-1-pl95.packetloss.syssec-research.mmci.uni-saarland.de: type A, class IN']:
                    #        current_query_name = json_data[i]['_source']['layers']['dns'][0]["dns.qry.name"]
                    #        currentPacket.query_name = current_query_name

                # Get latencies of the answer packets
                # print(data[i]['_source']['layers']['dns'])
                # To get the dns_time, the packet must have an "Answers" section
                if 'Answers' in json_data[i]['_source']['layers']['dns']:
                    # Mark packet as Answer # TODO: Unnecessary bcs of dns.flags.response(is_answer_response)?
                    # is_answer = "1"
                    currentPacket.is_answer = "1"
                    # Note: Not all answers has dns.time?
                else:
                    # is_answer = "0"
                    currentPacket.is_answer = "0"
                # Get failure rate (RCODE only present when there is an Answers section in the JSON)
                # count of dns.flags.rcode != 0
                if 'dns.flags.response' in json_data[i]['_source']['layers']['dns']['dns.flags_tree']:  # DEBUG
                    # response_count = response_count + 1  # DEBUG
                    # print(f"Response count: {response_count}")  # DEBUG
                    # Query = 0, Response (Answer) = 1
                    # RCode only exists if dns packet has is an answer
                    if json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "0":
                        # is_query = "1"
                        currentPacket.is_query = "0"
                        # Count the message as query
                        answer_count_data[index].append("0")
                    if json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "1":
                        # Count the message as response (answer to query)
                        answer_count_data[index].append("1")
                        currentPacket.is_query = "1"

                        # print(f"DNS ID: {jsonData[i]['_source']['layers']['dns']['dns.id']}")  # DEBUG
                        # if dns_id == jsonData[i]['_source']['layers']['dns']['dns.id']:  # DEBUG
                        #    duplicate = duplicate + 1  # DEBUG
                        #    # print(f"Duplicate: {duplicate}")  # DEBUG
                        # else:
                        #    test_count += 1
                        #    # print(f"Unique packet Count: {test_count}")  # DEBUG
                        rcode = json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
                        failure_rate_data[index].append(int(rcode))
                        currentPacket.response_code = rcode

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
                            # packetlossData[index].append(float(dns_time))
                            currentPacket.response_latency = dns_time
                # Get the TC Bit
                if 'dns.flags.truncated' in json_data[i]['_source']['layers']['dns']['dns.flags_tree']:
                    truncated = json_data[i]['_source']['layers']['dns']['dns.flags_tree'][
                        'dns.flags.truncated']
                    currentPacket.truncated = truncated
                # Get the DNS ID of the current DNS packet to check
                # if the next packet has the same ID to detect duplicates
                dns_id = json_data[i]['_source']['layers']['dns']['dns.id']  # Detect duplicates
                # Set the dns id to the current packet
                # dns_idx = jsonData[i]['_source']['layers']['dns']['dns.id']
                currentPacket.dns_idx = dns_id

                # packetlossData[index].append(currentPacket)
                if "dns.retransmission" in json_data[i]['_source']['layers']['dns']:
                    retransmission_data[index] += 1
                    currentPacket.retransmission = "1"

                # Add the current dns packet to the list
                # dns_packets_in_pl.append(currentPacket)
                all_packetloss_packets[index].append(currentPacket)
            # else:
            #     not_dns = not_dns + 1

        # all_packetloss_packets[index].append(dns_packets_in_pl)
        # dns_packets_in_pl.clear()
        index = index + 1

        # This was outside the for loop
        # print(f"Packetloss rate: {current_packetloss_rate}")
        # print(f"    DNS Packet count: {dns_packets_count}")
        # print(f"  Non-DNS Packet count: {not_dns}")
        # Reset the packet count for the next packetloss config
        # dns_packets_count = 0
        # not_dns = 0


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
def create_box_plot(file_name, operator_specific_packet_list, rcodes, bottom_limit, upper_limit):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0].operator is not None:
        operator_name = operator_specific_packet_list[0].operator

    print(f"Creating box plot for {operator_name}")

    global packetlossData
    for packet in operator_specific_packet_list:
        # Filter/Ignore the rcodes not defined in the list
        if packet.response_code in rcodes:
            if packet.packetloss_rate == "pl0" and packet.response_latency != "-":
                packetlossData[0].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl10" and packet.response_latency != "-":
                packetlossData[1].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl20" and packet.response_latency != "-":
                packetlossData[2].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl30" and packet.response_latency != "-":
                packetlossData[3].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl40" and packet.response_latency != "-":
                packetlossData[4].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl50" and packet.response_latency != "-":
                packetlossData[5].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl60" and packet.response_latency != "-":
                packetlossData[6].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl70" and packet.response_latency != "-":
                packetlossData[7].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl80" and packet.response_latency != "-":
                packetlossData[8].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl85" and packet.response_latency != "-":
                packetlossData[9].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl90" and packet.response_latency != "-":
                packetlossData[10].append(float(packet.response_latency))
            if packet.packetloss_rate == "pl95" and packet.response_latency != "-":
                packetlossData[11].append(float(packet.response_latency))

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percantage')
    ax.set_title(f'Packetloss-Latency for {operator_name}')

    # y-axis labels
    ax.set_xticklabels(['0', '10', '20', '30', '40', '50', '60', '70', '80', '85', '90', '95'])
    # TODO: Fix UserWarning: FixedFormatter should only be used together with FixedLocator

    # Creating plot
    # bp = ax.boxplot(packetlossData)
    ax.boxplot(packetlossData)

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # save plot as png
    plt.savefig((file_name + "_" + operator_name + '_boxPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()


def create_violin_plot(file_name, operator_specific_packet_list, bottom_limit, upper_limit):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0].operator is not None:
        operator_name = operator_specific_packet_list[0].operator

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

    global packetlossData
    print(f"Debug violin plot packetlossData:")
    # If a list is empty (because all the packets were dropped and
    # there were no packets with latency), plotting gives an error
    # Spot the empty lists, add a dummy value
    for packet in packetlossData:
        print(f"  packet: {packet}")
        if len(packet) == 0:
            packet.append(float(-0.1))

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
    plt.savefig((file_name + "_" + operator_name + '_violinPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()


def create_bar_plot(file_name, operator_specific_packet_list, bottom_limit, upper_limit):
    operator_name = "UNKNOWN"
    if operator_specific_packet_list[0].operator is not None:
        operator_name = operator_specific_packet_list[0].operator

    print(f"Creating bar plot for {operator_name}")

    global failure_rate_data

    for lst in failure_rate_data:
        lst.clear()

    for packet in operator_specific_packet_list:
        if packet.packetloss_rate == "pl0":
            failure_rate_data[0].append(packet.response_code)
        if packet.packetloss_rate == "pl10":
            failure_rate_data[1].append(packet.response_code)
        if packet.packetloss_rate == "pl20":
            failure_rate_data[2].append(packet.response_code)
        if packet.packetloss_rate == "pl30":
            failure_rate_data[3].append(packet.response_code)
        if packet.packetloss_rate == "pl40":
            failure_rate_data[4].append(packet.response_code)
        if packet.packetloss_rate == "pl50":
            failure_rate_data[5].append(packet.response_code)
        if packet.packetloss_rate == "pl60":
            failure_rate_data[6].append(packet.response_code)
        if packet.packetloss_rate == "pl70":
            failure_rate_data[7].append(packet.response_code)
        if packet.packetloss_rate == "pl80":
            failure_rate_data[8].append(packet.response_code)
        if packet.packetloss_rate == "pl85":
            failure_rate_data[9].append(packet.response_code)
        if packet.packetloss_rate == "pl90":
            failure_rate_data[10].append(packet.response_code)
        if packet.packetloss_rate == "pl95":
            failure_rate_data[11].append(packet.response_code)

    # Create bar plot for failure rate
    # data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
    failure_rate_data_dict = {'0': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                              '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

    failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

    # DEBUG
    # for packet in failure_rate_data:
    #     print(f"packet: {packet}")
    #     for pac in packet:
    #         print(f"pac.response_code: {pac}")

    # The bar plot accepts a dictionary like above.
    # This for loop extracts the saved RCODE counts and converts them to a dictionary
    index = 0
    for current_packetloss_rate in packetloss_rates:
        # print(f"index: {index}")
        # print(f"Data: {failure_rate_data[index]}")
        fail_count = 0
        for x in range(len(failure_rate_data[index])):
            if failure_rate_data[index][x] != "0" and failure_rate_data[index][x] != "-":
                fail_count += 1
        # print(f"Fail count: {fail_count}")
        if fail_count != 0:
            # divide by len(failure_rate_data[index]) and multiply by 100 to get the percentage of the failure rate
            failure_rate_data_dict[str(current_packetloss_rate)] = (fail_count / len(failure_rate_data[index])) * 100
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
    plt.title(f"Response Failure Rate for {operator_name}")
    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # save plot as png
    plt.savefig((file_name + "_" + operator_name + '_barPlotResponseFailureRate.png'), bbox_inches='tight')
    # shot plot
    # plt.show()


file_names = ["client", "auth1", "auth2"]
# rcodes cant be an empty list
# rcodes = ["0"]
# rcodes = ["2"]
rcodes = ["2"]

# Define limits of the plots
bottom_limit = 0
upper_limit = 30

for file_name in file_names:
    # Read the client logs
    read_json_files(file_name)

    classify_packets_by_operators()

    # Add the filtering options to the file name of the plots
    filter_names_on_filename = ""
    # If rcode is applied, add the filter to the file name
    if len(rcodes) > 0:
        filter_names_on_filename += "_rcodeFilter-"
        for rcode in rcodes:
            filter_names_on_filename += (rcode + "-")

    file_name += filter_names_on_filename

    for operator in list_of_operators:
        # print(f"len(operator): {len(operator)}")
        create_box_plot(file_name, operator, rcodes, bottom_limit, upper_limit)
        create_bar_plot(file_name, operator, bottom_limit, 100)
        create_violin_plot(file_name, operator, bottom_limit, upper_limit)

        # Clear lists
        clear_answers()
        clear_retransmission_data()
        clear_failure_rate_data()
        clear_packetloss_data()


        # Show answer-query count
        #  show_answer_query_count(answer_count_data)

        # Show retransmission counts
        # show_restransmission_data(retransmission_data)

        # Show latencies
        # show_latencies(packetlossData)

        # show_failure_count()
