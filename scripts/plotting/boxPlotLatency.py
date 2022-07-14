# Import libraries
import matplotlib.pyplot as plt
import numpy as np

# TODO: read the measured latencies from a file (file structure not known yet)

# Add the data here
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
