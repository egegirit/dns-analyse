import numpy as np
import matplotlib.pyplot as plt
import ast
import statistics


# Convert a string (read from a text file) to python dictionary
def convert_string_to_dict(string_obj):
    return ast.literal_eval(string_obj)


# Read a file and return the string representation of it
def read_dict_from_file(file_name):
    f = open(file_name, "r")
    content = str(f.read())
    return content


# Read Latencies_(PacketLoss_RCODE)_[Latencies].txt
# Create CDF for each packetloss rate
file_name = "Latencies_(PacketLoss_RCODE)_[Latencies].txt"

all_responses_of_pl_count_dict = convert_string_to_dict(read_dict_from_file(file_name))

# TODO: Separate plots for every packetloss rate and RCODE 0 and 2 -> 12 * 2 = 24 plots for each operator?
# Or find mean/median of a packetloss rate, combine all the packetloss rates into 1 CDF plot

rcode_0_latencies = []
rcode_2_latencies = []

for key, value in all_responses_of_pl_count_dict.items():
    if key[1] == 0:
        rcode_0_latencies += value
    elif key[1] == 2:
        rcode_2_latencies += value

median_rcode_0 = statistics.median(rcode_0_latencies)
mean_rcode_0 = statistics.mean(rcode_0_latencies)

# Printing result
print("Median: " + str(median_rcode_0))
print("Mean: " + str(mean_rcode_0))

# print(f"rcode_0_latencies: {rcode_0_latencies}")
# print(f"rcode_2_latencies: {rcode_2_latencies}")

# some fake data
# n = 1000
# latency_list = np.random.randn(n)

# evaluate the histogram
count, bins_count = np.histogram(rcode_0_latencies, bins=10)

# finding the PDF of the histogram using count values
pdf = count / sum(count)

# using numpy np.cumsum to calculate the CDF
# We can also find using the PDF values by looping and adding
cdf = np.cumsum(pdf)

plot_title = f"Cumulative Distribution Function of Latencies"
plt.xlabel("Latencies")
plt.ylabel("CDF")

# Title position
plt.title(plot_title, x=0.5, y=1)

# plotting PDF and CDF
plt.plot(bins_count[1:], pdf, color="red", label="PDF")
plt.plot(bins_count[1:], cdf, label="CDF")
plt.legend()
plt.show()

# save plot as png
# plt.savefig(f"{save_path}/{file_name}_RatePlot.png", dpi=100, bbox_inches='tight')
print(f"      Created rate plot")

# Clear plots
plt.cla()
plt.close()
