import json
import sys

import matplotlib.pyplot as plt
import numpy as np
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

packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]


class DNSPacket:
    def __init__(self, dns_idx, transport_protocol, query_name, is_answer, response_latency,
                 response_code, truncated, opcode, ip_src, ip_dst, is_answer_response, query_ip, packetloss_rate,
                 counter, is_query):
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
        self.query_ip = query_ip
        self.packetloss_rate = packetloss_rate
        self.counter = counter
        self.is_query = is_query


dns_packets = []

index = 0
file_prefix = "client"
current_packetloss_rate = "0"
# Read the JSON files and for each captured packet, create a DNSPacket object,
# set its variables according to the information read in the packet
for current_packetloss_rate in packetloss_rates:
    filename = file_prefix + "_" + str(current_packetloss_rate) + ".json"
    print(f"Reading {filename}")
    if not os.path.exists("./" + filename):
        print(f"File not found: {filename}")
        exit()
    # Read the measured latencies from json file
    file = open(filename)
    jsonData = json.load(file)
    # print(f"Number of packets in the file: {len(data)}")  # Number of packets captured and saved in the file
    # print(data[0])  # Contents of the first packet in JSON format
    # print(data[1]['_source']['layers']['dns']['dns.time'])  # "0.044423000"
    packetCount = len(jsonData)
    print(f"  Number of packets in JSON file: {packetCount}")

    response_count = 0
    test_count = 0
    # Examine all the captured packets in the JSON file
    dns_id = ""  # DEBUG
    duplicate = 0
    # duplicate_bool = False

    test_failure_rate_count = 0

    # Examine all the packets in the JSON file
    for i in range(0, packetCount):
        # Create a dns packet object for the current packet
        currentPacket = DNSPacket("-", "-", "-", "0", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-", "-")

        # Check if the packet is a DNS packet
        if 'dns' in jsonData[i]['_source']['layers']:
            # Check if the DNS packet is using UDP as transport protocol
            if 'udp' in jsonData[i]['_source']['layers']:
                currentPacket.transport_protocol = "UDP"

            # Check if the DNS packet is using TCP as transport protocol
            if 'tcp' in jsonData[i]['_source']['layers']:
                currentPacket.transport_protocol = "TCP"

            # Get the query name and break it down to its components like ip address, counter, packetloss rate.
            # Query structure: <ip_addr>-<counter>-<packetloss_rate>.packetloss.syssec-research.mmci.uni-saarland.de
            # Query example: 94-140-14-14-1-pl95.packetloss.syssec-research.mmci.uni-saarland.de
            if "Queries" in jsonData[i]['_source']['layers']['dns']:
                # print(f"Not none: {jsonData[i]['_source']['layers']['dns']['Queries']}")
                json_string = str(jsonData[i]['_source']['layers']['dns']['Queries'])
                splitted_json1 = json_string.split("'dns.qry.name': ")
                splitted2 = str(splitted_json1[1])
                # print(f"splitted_json[1]: {splitted2}")
                query_name = splitted2.split("'")[1]
                currentPacket.query_name = query_name

                splitted_domain = query_name.split("-")
                ip_addr_with_dashes = splitted_domain[0] + "-" + splitted_domain[1] + "-" + \
                                      splitted_domain[2] + "-" + splitted_domain[3]

                currentPacket.query_ip = ip_addr_with_dashes
                currentPacket.counter = splitted_domain[4]
                currentPacket.packetloss_rate = splitted_domain[5].split(".")[0]  # [2:]
                test = splitted_domain[5].split(".")[0]
                # print(f"query_name: {query_name}")
                # print(f"ip_addr_with_dashes: {ip_addr_with_dashes}")
                # print(f"counter: {splitted_domain[4]}")
                # print(f"packetloss_rate: {test}")

                # if jsonData[i]['_source']['layers']['dns']['Queries'][0] is not None:
                #     # print(f"Current: {jsonData[i]['_source']['layers']['dns']['Queries'][0]}")
                #     if "dns.qry.name" in jsonData[i]['_source']['layers']['dns']['Queries']['94-140-14-14-1-pl95.packetloss.syssec-research.mmci.uni-saarland.de: type A, class IN']:
                #         current_query_name = jsonData[i]['_source']['layers']['dns'][0]["dns.qry.name"]
                #         currentPacket.query_name = current_query_name

            # Get latencies of the answer packets
            # print(data[i]['_source']['layers']['dns'])
            # To get the dns_time, the packet must have an "Answers" section
            if 'Answers' in jsonData[i]['_source']['layers']['dns']:
                # Mark packet as Answer # TODO: Unnecessary bcs of dns.flags.response(is_answer_response)?
                currentPacket.is_answer = "1"
                # Note: Not all answers has dns.time?
                if 'dns.time' in jsonData[i]['_source']['layers']['dns']:
                    # print(f"DNS ID: {jsonData[i]['_source']['layers']['dns']['dns.id']}")  # DEBUG
                    # Assign the dns response latency
                    currentPacket.response_latency = jsonData[i]['_source']['layers']['dns']['dns.time']

                    dns_time = jsonData[i]['_source']['layers']['dns']['dns.time']
                    packetlossData[index].append(float(dns_time))
            else:
                currentPacket.is_answer = "0"
            # Get failure rate (RCODE only present when there is an Answers section in the JSON)
            # count of dns.flags.rcode != 0
            if 'dns.flags.response' in jsonData[i]['_source']['layers']['dns']['dns.flags_tree']:  # DEBUG
                # response_count = response_count + 1  # DEBUG
                # print(f"Response count: {response_count}")  # DEBUG
                # Query = 0, Response (Answer) = 1
                # RCode only exists if dns packet has is an answer
                if jsonData[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "0":
                    currentPacket.is_query = "1"
                if jsonData[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "1":
                    # Mark packet as answer
                    currentPacket.is_answer_response = "1"
                    # print(f"DNS ID: {jsonData[i]['_source']['layers']['dns']['dns.id']}")  # DEBUG
                    # if dns_id == jsonData[i]['_source']['layers']['dns']['dns.id']:  # DEBUG
                    #    duplicate = duplicate + 1  # DEBUG
                    #    # print(f"Duplicate: {duplicate}")  # DEBUG
                    # else:
                    #    test_count += 1
                    #    # print(f"Unique packet Count: {test_count}")  # DEBUG
                    rcode = jsonData[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
                    failure_rate_data[index].append(int(rcode))
                    # Assign packets RCODE
                    currentPacket.response_code = rcode
                    # print(f"  rcode: {rcode}")  # DEBUG
                    # print(f"  currentPacket.response_code: {currentPacket.response_code}")  # DEBUG
                    if rcode != "0":
                        test_failure_rate_count = test_failure_rate_count + 1
                        # print(f"  test_failure_rate_count: {test_failure_rate_count}")  # DEBUG
                    # dns_id = jsonData[i]['_source']['layers']['dns']['dns.id']  # DEBUG
            # Get the TC Bit
            if 'dns.flags.truncated' in jsonData[i]['_source']['layers']['dns']['dns.flags_tree']:
                currentPacket.truncated = jsonData[i]['_source']['layers']['dns']['dns.flags_tree'][
                    'dns.flags.truncated']
        # Get the DNS ID of the current DNS packet to check if the next packet has the same ID to detect duplicates
        dns_id = jsonData[i]['_source']['layers']['dns']['dns.id']  # Detect duplicates
        # Set the dns id to the current packet
        currentPacket.dns_idx = jsonData[i]['_source']['layers']['dns']['dns.id']

        dns_packets.append(currentPacket)
        packetlossData[index].append(currentPacket)

    index = index + 1

    # This was outside the for loop
    print(f"Packetloss rate: {current_packetloss_rate}")
    print(f"  DNS Packet count: {len(dns_packets)}")
    tcp_count = 0
    udp_count = 0
    query_count = 0
    answer_count = 0
    answer_count2 = 0
    truncated_count = 0
    failure_count = 0
    # print(f"Listing packet attributes:")
    for packet in dns_packets:
        # print(f"  packet: {packet}")
        # print(f"  packet.is_answer_response: {packet.is_answer_response}")
        # print(f"  packet.transport_protocol: {packet.transport_protocol}")
        # print(f"  packet.response_code: {packet.response_code}")
        # print(f"  packet.is_answer: {packet.is_answer}")
        # print(f"  packet.query_name: {packet.query_name}")
        if packet.is_query == "1":
            query_count = query_count + 1
        if packet.is_answer_response == "1":
            answer_count = answer_count + 1
        # else:
        # print("Undefined Response")
        if packet.transport_protocol != "-":
            if packet.transport_protocol == "UDP":
                udp_count = udp_count + 1
            if packet.transport_protocol == "TCP":
                tcp_count = tcp_count + 1
        # else:
        # print("Undefined Protocol")
        # 0 or - = No failure(could be a query and not an answer), Other entries = failure
        if packet.response_code != "0" and packet.response_code != "-":
            failure_count = failure_count + 1
            # print("  Failure count incremented")
        if packet.truncated != "0" and packet.truncated != "-":
            truncated_count = truncated_count + 1
        if packet.is_answer == "1":
            answer_count2 = answer_count2 + 1
    print(f"    UDP count: {udp_count}")
    print(f"    TCP count: {tcp_count}")
    print(f"    Query count: {query_count}")
    print(f"    Answer count: {answer_count}")
    print(f"    Answer count 2: {answer_count}")
    print(f"    Truncated count: {truncated_count}")
    print(f"    Failure count: {failure_count}")
    # dns_packets.clear()

#for p in packetlossData:
#    print(p[0])

packetlossData.clear()

packetlossz_0 = []
packetlossz_10 = []
packetlossz_20 = []
packetlossz_30 = []
packetlossz_40 = []
packetlossz_50 = []
packetlossz_60 = []
packetlossz_70 = []
packetlossz_80 = []
packetlossz_85 = []
packetlossz_90 = []
packetlossz_95 = []


packetlossDatas = [packetlossz_0, packetlossz_10, packetlossz_20, packetlossz_30, packetlossz_40, packetlossz_50,
                  packetlossz_60, packetlossz_70, packetlossz_80, packetlossz_85, packetlossz_90, packetlossz_95]

index = 0
for packet in dns_packets:
    if packet.response_latency != "-":
        print(f"packet.response_latency: {packet.response_latency}")
        if packet.packetloss_rate == "pl0":
            packetlossDatas[0].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl10":
            packetlossDatas[1].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl20":
            packetlossDatas[2].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl30":
            packetlossDatas[3].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl40":
            packetlossDatas[4].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl50":
            packetlossDatas[5].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl60":
            packetlossDatas[6].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl70":
            packetlossDatas[7].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl80":
            packetlossDatas[8].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl85":
            packetlossDatas[9].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl90":
            packetlossDatas[10].append(float(packet.response_latency))
        if packet.packetloss_rate == "pl95":
            packetlossDatas[11].append(float(packet.response_latency))
    index = index + 1


# sys.exit()

# Create box plot for latency-packetloss
fig2 = plt.figure(figsize=(10, 7))

# Creating axes instance
ax = fig2.add_axes([0, 0, 1, 1])
ax.set_ylabel('Latency in seconds')
ax.set_xlabel('Packetloss in percantage')
ax.set_title('Packetloss-Latency')

# y-axis labels
ax.set_xticklabels(['0', '10', '20', '30', '40', '50', '60', '70', '80', '85', '90', '95'])
# TODO: Fix UserWarning: FixedFormatter should only be used together with FixedLocator

# Creating plot
bp = ax.boxplot(packetlossDatas)

# save plot as png
plt.savefig('test_boxPlotLatency.png', bbox_inches='tight')
# show plot
plt.show()

# Create violin plot
fig2 = plt.figure(figsize=(10, 7))

# Creating axes instance
ax = fig2.add_axes([0, 0, 1, 1])

# Set the X axis labels/positions
ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])

ax.set_ylabel('Latency in seconds')
ax.set_xlabel('Packetloss in percantage')
ax.set_title('Packetloss-Latency')

# Create and save Violinplot
# bp = ax.violinplot(packetlossData)
# bp = ax.violinplot(dataset=packetlossData, showmeans=True, showmedians=True,
#                  showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
# Mean is blue
# bp['cmeans'].set_color('b')
# Median is red
# bp['cmedians'].set_color('r')

# save plot as png
# plt.savefig('test_violinPlotLatency.png', bbox_inches='tight')
# show plot
# plt.show()

# Create bar plot for failure rate
# data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
# failureRateData = {'00': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
    #                    '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

# failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

# The bar plot accepts a dictionary like above.
# This for loop extracts the saved RCODE counts and converts them to a dictionary
# index = 0
# for current_packetloss_rate in packetloss_rates:
    #    print(f"Data: {failure_rate_data[index]}")
    #    fail_count = 0
    #    for x in range(len(failure_rate_data[index])):
    #        if failure_rate_data[index][x] != 0:
    #            fail_count += 1
    #    if current_packetloss_rate == 0:
    #        failureRateData['00'] = fail_count
    #    else:
    #        failureRateData[str(current_packetloss_rate)] = fail_count
    #    index = index + 1


# rates = list(failureRateData.keys())
# values = list(failureRateData.values())

# Debug
# print(f"Packetloss rates: {rates}")
# print(f"Failure rate datas: {values}")

# fig = plt.figure(figsize=(10, 5))

# creating the bar plot
# plt.bar(failure_rates, values, color='maroon', width=4)

# set labels
# plt.xlabel("Packetloss Rate")
# plt.ylabel("DNS Response Failure Rate")
# plt.title("Response Failure Rate")

# save plot as png
# plt.savefig('test_barPlotResponseFailureRate.png', bbox_inches='tight')
# shot plot
# plt.show()
