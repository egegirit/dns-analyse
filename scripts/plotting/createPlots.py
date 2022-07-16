import json
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
packetloss_90 = []

packetlossData = [packetloss_0, packetloss_10, packetloss_20, packetloss_30, packetloss_40, packetloss_50,
                  packetloss_60, packetloss_70, packetloss_80, packetloss_90]

failure_rate_0 = []
failure_rate_10 = []
failure_rate_20 = []
failure_rate_30 = []
failure_rate_40 = []
failure_rate_50 = []
failure_rate_60 = []
failure_rate_70 = []
failure_rate_80 = []
failure_rate_90 = []

failure_rate_data = [failure_rate_0, failure_rate_10, failure_rate_20, failure_rate_30, failure_rate_40,
                     failure_rate_50, failure_rate_60, failure_rate_70, failure_rate_80, failure_rate_90]

# Read the latency values from each of the JSON files (There are 10 files from 0 to 9)
for x in range(0, 10):  # 10 is excluded
    filename = "wireshark" + str(x) + "PL.json"
    print(f"Reading {filename}")
    if not os.path.exists("./" + filename):
        print(f"File not found: {filename}")
        exit()
    # Read the measured latencies from json file
    file = open(filename)
    jsonData = json.load(file)
    # print(len(data))  # Number of packets captured and saved in the file
    # print(data[0])  # Contents of the first packet in JSON format
    # print(data[1]['_source']['layers']['dns']['dns.time'])  # 0.044423000
    packetCount = len(jsonData)
    print(f"  Number of packets in JSON: {packetCount}")
    # Examine all the captured packets in the JSON file
    for i in range(0, packetCount):
        # Check if the packet is a DNS packet
        if 'dns' in jsonData[i]['_source']['layers']:
            # Get latencies of the answer packets
            # print(data[i]['_source']['layers']['dns'])
            # To get the dns_time, the packet must have an "Answers" section
            if 'Answers' in jsonData[i]['_source']['layers']['dns']:
                if 'dns.time' in jsonData[i]['_source']['layers']['dns']:
                    dns_time = jsonData[i]['_source']['layers']['dns']['dns.time']
                    packetlossData[x].append(float(dns_time))
            # Get failure rate (RCODE only present when there is an Answers section in the JSON)
            # count of dns.flags.rcode != 0
            if jsonData[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.response'] == "1":
                rcode = jsonData[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
                # If there was an error, store 1, if not, store 0. The count of 1's is the total failure count.
                failure_rate_data[x].append(int(rcode))
                #if rcode != 0:
                #    failure_rate_data[x].append(1)
                #else:
                #    failure_rate_data[x].append(0)

# Create box plot for latency-packetloss

fig = plt.figure(figsize=(10, 7))

# Creating axes instance
ax = fig.add_axes([0, 0, 1, 1])
ax.set_ylabel('Latency in seconds')
ax.set_xlabel('Packetloss in percantage')
ax.set_title('Packetloss-Latency')

# y-axis labels
ax.set_xticklabels(['0', '10', '20', '30', '40', '50', '60', '70', '80', '90'])
# TODO: Fix UserWarning: FixedFormatter should only be used together with FixedLocator

# Creating plot
bp = ax.boxplot(packetlossData)

# save plot as png
plt.savefig('boxPlotLatency.png', bbox_inches='tight')
# show plot
plt.show()

# Create bar plot for failure rate

# data is defined as dictionary, key value pairs ('paketloss1' : failure rate1, ...)
failureRateData = {'00': 0, '10': 0, '20': 0, '30': 0, '40': 0, '50': 0, '60': 0, '70': 0, '80': 0, '90': 0}
# The bar plot acceps a dictionary like above. This for loop extracts the saved RCODE counts and converts them to a dictionary
for i in range(len(failure_rate_data)):
    print(failure_rate_data[i])
    fail_count = 0
    for x in range(len(failure_rate_data[i])):
        if failure_rate_data[i][x] != 0:
            fail_count += 1
    failureRateData[str(str(i) + str(0))] = fail_count

# print(failureRateData)

courses = list(failureRateData.keys())
values = list(failureRateData.values())

fig = plt.figure(figsize=(10, 5))

# creating the bar plot
plt.bar(courses, values, color='maroon', width=0.4)

# set labels
plt.xlabel("Packetloss Rate")
plt.ylabel("DNS Response Failure Rate")
plt.title("Response Failure Rate")

# save plot as png
plt.savefig('barPlotResponseFailureRate.png', bbox_inches='tight')
# shot plot
plt.show()
