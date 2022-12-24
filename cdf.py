import numpy as np
import matplotlib.pyplot as plt
import ast
import statistics
import os.path


# Convert a string (read from a text file) to python dictionary
def convert_string_to_dict(string_obj):
    return ast.literal_eval(string_obj)


# Read a file and return the string representation of it
def read_dict_from_file(file_name):
    f = open(file_name, "r")
    content = str(f.read())
    return content


# Create a folder with the given name
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Folder {folder_name} created")
    else:
        print(f"Folder {folder_name} already exists")


def iterate_latency_dict(latency_dict, folder_name):
    for key, value in latency_dict.items():
        if value:
            print(f"Length of latency list: {len(value)}")
            plot_cdf(value, f"({folder_name} PL {key[0]} RCODE {key[1]})")


# Calculate latencies of all RCODE 0/2 packets (All packetloss rates combined)
def calculate_all_pl_latencies(latency_dict):
    rcode_0_latencies = []
    rcode_2_latencies = []

    for key, value in latency_dict.items():
        if key[1] == 0:
            rcode_0_latencies += value
        elif key[1] == 2:
            rcode_2_latencies += value

    # Calculate median of RCODE 0 and RCODE 2 latencies separately
    median_rcode_0 = statistics.median(rcode_0_latencies)
    all_median_latencies["RCODE_0"].append(median_rcode_0)
    median_rcode_2 = statistics.median(rcode_2_latencies)
    all_median_latencies["RCODE_2"].append(median_rcode_2)

    # Calculate mean of RCODE 0 and RCODE 2 latencies separately
    mean_rcode_0 = statistics.mean(rcode_0_latencies)
    all_mean_latencies["RCODE_0"].append(mean_rcode_0)
    mean_rcode_2 = statistics.mean(rcode_2_latencies)
    all_mean_latencies["RCODE_2"].append(mean_rcode_2)

    plot_cdf(rcode_0_latencies, "(RCODE 0)")
    plot_cdf(rcode_2_latencies, "(RCODE 2)")


# Create CDF
def plot_cdf(latency_list, title):
    # evaluate the histogram
    count, bins_count = np.histogram(latency_list, bins=10)

    # finding the PDF of the histogram using count values
    pdf = count / sum(count)

    # using numpy np.cumsum to calculate the CDF
    # We can also find using the PDF values by looping and adding
    cdf = np.cumsum(pdf)

    plot_title = f"Cumulative Distribution Function of Latencies {title}"
    plt.xlabel("Latencies")
    plt.ylabel("CDF")

    # Title position
    plt.title(plot_title, x=0.5, y=1)

    # plotting PDF and CDF
    plt.plot(bins_count[1:], pdf, color="red", label="PDF")
    plt.plot(bins_count[1:], cdf, label="CDF")
    plt.legend()
    # plt.show()

    title_without_whitespace = title.replace(' ', '')

    # save plot as png
    plt.savefig(f"{title_without_whitespace}_CDFPlot.png", dpi=100, bbox_inches='tight')
    print(f"      Created plot")

    # Clear plots
    plt.cla()
    plt.close()


file_name = "Latencies_(PacketLoss_RCODE)_[Latencies].txt"

# find mean/median of a packetloss rate, combine all the packetloss rates into 1 CDF plot
all_mean_latencies = {"RCODE_0": [], "RCODE_2": []}
all_median_latencies = {"RCODE_0": [], "RCODE_2": []}

# Get the current working directory
cwd = os.path.abspath('')
print(f"Current working directory: {cwd}")

# Get a list of all the folders in the directory
folders = [f for f in os.listdir(cwd) if os.path.isdir(os.path.join(cwd, f))]
print(f"Folder names in the working directory: {folders}")

# Iterate all the resolver data folders
for folder in folders:
    try:
        # Read Latencies_(PacketLoss_RCODE)_[Latencies].txt
        latency_dict = convert_string_to_dict(read_dict_from_file(os.path.join(folder, file_name)))

        # Create CDF for each packetloss rate
        iterate_latency_dict(latency_dict, folder)

        # Create CDF for all packetloss rates combined but separate RCODES
        calculate_all_pl_latencies(latency_dict)
    except Exception:
        print(f"  Error opening file in directory {folder}")


