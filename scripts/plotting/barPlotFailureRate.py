import numpy as np
import matplotlib.pyplot as plt

# TODO: read the failure rates from a file (file structure not known yet)

# add the data as key value pairs ('paketloss1' : failure rate1, ...)
data = {'10': 0, '20': 0, '30': 10, '40': 20, '50': 30, '60': 50, '70': 55, '80': 70, '90': 80}
courses = list(data.keys())
values = list(data.values())

fig = plt.figure(figsize=(10, 5))

# creating the bar plot
plt.bar(courses, values, color='maroon', width=0.4)

# set labels
plt.xlabel("Packetloss Rate")
plt.ylabel("DNS Response Failure Rate")
plt.title("Example Graph Response for Failure Rate")

# save plot as png
plt.savefig('barPlotResponseFailureRate.png', bbox_inches='tight')
# shot plot
plt.show()
