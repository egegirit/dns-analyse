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

data = [packetloss_0, packetloss_10, packetloss_20, packetloss_30, packetloss_40, packetloss_50,
        packetloss_60, packetloss_70, packetloss_80, packetloss_90]

# Read the latency values from each of the JSON files
for i in range(0, 10):  # 10 is excluded (There are 10 files from 0 to 9)
    filename = "dnsPacketsW" + str(i) + "PL.json"
    os.path.exists("./" + filename)
    # Read the measured latencies from json file
    file = open(filename)
    count = 0  # Current line count of file
    while True:
        count += 1
        # Get next line from file
        line = file.readline()
        # if line is empty
        # end of file is reached
        if not line:
            break
        line = line.replace("\'", "\"")  # Convert ' to "
        dns_dict = json.loads(line)
        # Get Latencies
        if 'Answers' in dns_dict.keys():
            dns_time = dns_dict['dns.time']
            data[i].append(float(dns_time))
       # Get Response failure rates
       # count of dns.flags.rcode != 0

# Example data
# packetloss_currentRate = [measuredLatency1, measuredLatency2, ...]
packetloss_0 = [100, 200, 150, 130]
packetloss_10 = [120, 220, 170, 150]
packetloss_20 = [140, 240, 200, 170]
packetloss_30 = [160, 280, 230, 190]
packetloss_40 = [180, 310, 230, 210]
packetloss_50 = [190, 330, 250, 220]
packetloss_60 = [300, 330, 300, 220]
packetloss_70 = [350, 400, 420, 300]
packetloss_80 = [550, 500, 520, 400]
packetloss_90 = [650, 570, 600, 500]
data = [packetloss_0, packetloss_10, packetloss_20, packetloss_30, packetloss_40, packetloss_50,
        packetloss_60, packetloss_70, packetloss_80, packetloss_90]

fig = plt.figure(figsize=(10, 7))

# Creating axes instance
ax = fig.add_axes([0, 0, 1, 1])
ax.set_ylabel('Latency')
ax.set_xlabel('Packetloss in percantage')
ax.set_title('Packetloss-Latency')

# y-axis labels
ax.set_xticklabels(['0', '10', '20', '30', '40', '50', '60', '70', '80', '90'])
# TODO: Fix UserWarning: FixedFormatter should only be used together with FixedLocator

# Creating plot
bp = ax.boxplot(data)

# save plot as png
plt.savefig('boxPlotLatencyExample.png', bbox_inches='tight')
# show plot
plt.show()
