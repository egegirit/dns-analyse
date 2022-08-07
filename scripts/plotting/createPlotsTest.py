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
    def __init__(self, dns_idx, transport_protocol, is_answer, response_latency,
                 response_code, truncated, opcode, ip_src, ip_dst, is_answer_response):
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


dns_packets = []

index = 0

# Read the latency values from each of the JSON files (12 files in total)
for current_packetloss_rate in packetloss_rates:
    filename = "wireshark" + str(current_packetloss_rate) + "PL.json"
    print(f"Reading {filename}")
    # print(f"Index: {index}")  # Debug
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

    # Create the dns packet object

    response_count = 0
    test_count = 0
    # Examine all the captured packets in the JSON file
    dns_id = ""  # DEBUG
    duplicate = 0
    # duplicate_bool = False

    test_failure_rate_count = 0

    # Examine all the packets in the JSON file
    for i in range(0, packetCount):

        currentPacket = DNSPacket("-", "-", "0", "-", "-", "-", "-", "-", "-", "-")

        # Check if the packet is a DNS packet
        if 'dns' in jsonData[i]['_source']['layers']:
            # Check if the DNS packet is using UDP as transport protocol
            if 'udp' in jsonData[i]['_source']['layers']:
                currentPacket.transport_protocol = "UDP"

            # Check if the DNS packet is using TCP as transport protocol
            if 'tcp' in jsonData[i]['_source']['layers']:
                currentPacket.transport_protocol = "TCP"

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
            # Get failure rate (RCODE only present when there is an Answers section in the JSON)
            # count of dns.flags.rcode != 0
            if 'dns.flags.response' in jsonData[i]['_source']['layers']['dns']['dns.flags_tree']:  # DEBUG
                # response_count = response_count + 1  # DEBUG
                # print(f"Response count: {response_count}")  # DEBUG
                # Query = 0, Response (Answer) = 1
                # RCode only exists if dns packet has is an answer
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
    index = index + 1
    # This was outside for loop
    print(f"DNS Packet count: {len(dns_packets)}")
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
        if packet.is_answer_response != "-":
            if packet.is_answer_response == "0":  # 0 = Query, 1 = Response (Answer)
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
    dns_packets.clear()

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
bp = ax.boxplot(packetlossData)

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
bp = ax.violinplot(dataset=packetlossData, showmeans=True, showmedians=True,
                   showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95])
# Mean is blue
bp['cmeans'].set_color('b')
# Median is red
bp['cmedians'].set_color('r')

# save plot as png
plt.savefig('test_violinPlotLatency.png', bbox_inches='tight')
# show plot
plt.show()

# Create bar plot for failure rate
# data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
failureRateData = {'00': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0,
                   '60': 0, '70': 0, '80': 0, '85': 0, '90': 0, '95': 0}

failure_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

# The bar plot accepts a dictionary like above.
# This for loop extracts the saved RCODE counts and converts them to a dictionary
index = 0
for current_packetloss_rate in packetloss_rates:
    print(f"index: {index}")
    # for i in range(len(failure_rate_data)):
    print(f"Data: {failure_rate_data[index]}")
    fail_count = 0
    for x in range(len(failure_rate_data[index])):
        if failure_rate_data[index][x] != 0:
            fail_count += 1
    if current_packetloss_rate == 0:
        failureRateData['00'] = fail_count
    else:
        failureRateData[str(current_packetloss_rate)] = fail_count
    index = index + 1
# print(failureRateData)

rates = list(failureRateData.keys())
values = list(failureRateData.values())

# Debug
print(f"Packetloss rates: {rates}")
print(f"Failure rate datas: {values}")

fig = plt.figure(figsize=(10, 5))

# creating the bar plot
plt.bar(failure_rates, values, color='maroon', width=4)

# set labels
plt.xlabel("Packetloss Rate")
plt.ylabel("DNS Response Failure Rate")
plt.title("Response Failure Rate")

# save plot as png
plt.savefig('test_barPlotResponseFailureRate.png', bbox_inches='tight')
# shot plot
plt.show()
