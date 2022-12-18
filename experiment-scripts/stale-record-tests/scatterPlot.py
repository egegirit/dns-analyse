import matplotlib.pyplot as plt
import matplotlib.lines as mlines
from matplotlib.patches import Patch
import numpy as np
import os
import ast


# Create a folder with the given name
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Folder {folder_name} created")
    else:
        print(f"Folder {folder_name} already exists")


# Read a file and return the string representation of it
def read_dict_from_file(file_name):
    print(f"Reading dictionary from file: {file_name}")
    f = open(file_name, "r")
    content = str(f.read())
    return content


# Convert a string (read from a text file) to python dictionary
def convert_string_to_dict(string_obj):
    return ast.literal_eval(string_obj)


ttl_values = [60, 300, 900, 3600]  # [60, 300, 900, 3600]
all_resolvers = ["Cloudflare-1", "Cloudflare-2", "Cloudflare-3", "Dyn-1", "OpenDNS-1", "OpenDNS-3"]
file_name_to_read = "Response_Rcode_Timings_(IP-Of-Resolver_Rcode)_[Packet_time].txt"

color_of_error_packets = "red"
color_of_stale_packets = "green"
marker_of_error_packets = "s"
marker_of_stale_packets = "s"
size_of_error_packets = 10
size_of_stale_packets = 10
dummy_value = np.nan

for current_ttl in ttl_values:
    print(f"TTL Value: {current_ttl}")

    minimum_latency = 99999999999999
    maximum_length_of_list = 0
    all_latencies_by_rcode_and_ip_normalised = {}
    # Del?
    all_list_of_stales = {}
    all_list_of_errors = {}
    all_list_of_stale_times = []
    all_list_of_error_times = []
    rcodes_timings_dict = {}
    servfail_timings = []
    stale_timings = []

    directory_of_client_datas = f"ClientDataTTL{current_ttl}"
    # directory_of_auth_datas = f"AuthDataTTL{current_ttl}"
    for file_name in all_resolvers:
        print(f"  Current resolver: {file_name}")
        # Create root folder for client plots
        client_root_plot_folder_name = f"ClientPlotsTTL{current_ttl}"
        create_folder(client_root_plot_folder_name)

        rcodes_timings_dict = convert_string_to_dict(
                read_dict_from_file(directory_of_client_datas + "/" + file_name + "/" + file_name_to_read))

        servfail_timings = []
        stale_timings = []

        for key, value in rcodes_timings_dict.items():
            if key[1] == 0:
                stale_timings = value
            elif key[1] == 2:
                servfail_timings = value
            else:
                print(f"Other RCODE!")

        maximum_length_of_list = max(len(stale_timings), len(servfail_timings))

        # Find the minimum seconds to build the 0 point of axis
        # Stale list is empty
        if len(stale_timings) == 0:
            # Servfail has elements
            if len(servfail_timings) > 0:
                minimum_latency = min(servfail_timings[0], minimum_latency)
            # Both lists are empty
            else:
                print(f"All latency lists are empty!")
                raise Exception
        # Stale list has elements
        elif len(stale_timings) > 0:
            # Servfail list is empty
            if len(servfail_timings) == 0:
                minimum_latency = min(stale_timings[0], minimum_latency)
            # Both lists have element
            else:
                if stale_timings[0] < servfail_timings[0]:
                    minimum_latency = min(stale_timings[0], minimum_latency)
                else:
                    minimum_latency = min(servfail_timings[0], minimum_latency)

    print(f"Minimum latency: {minimum_latency}")
    print(f"Maximum list size: {maximum_length_of_list}")

    for file_name in all_resolvers:
        print(f"  Reading file: {file_name}")
        rcodes_timings_dict = convert_string_to_dict(
                read_dict_from_file(directory_of_client_datas + "/" + file_name + "/" + file_name_to_read))

        servfail_timings = []
        stale_timings = []

        for key, value in rcodes_timings_dict.items():
            if key[1] == 0:
                stale_timings = value
            elif key[1] == 2:
                servfail_timings = value
            else:
                print(f"Other RCODE!")

        for i in range(len(servfail_timings)):
            servfail_timings[i] -= minimum_latency

        for i in range(len(stale_timings)):
            stale_timings[i] -= minimum_latency

        # print(f"servfail_timings: {servfail_timings}")
        # print(f"stale_timings: {stale_timings}")

        if (file_name, "stale") not in all_latencies_by_rcode_and_ip_normalised:
            all_latencies_by_rcode_and_ip_normalised[file_name, "stale"] = stale_timings
        if (file_name, "error") not in all_latencies_by_rcode_and_ip_normalised:
            all_latencies_by_rcode_and_ip_normalised[file_name, "error"] = servfail_timings

    # print(f"all_latencies_by_rcode_and_ip_normalised: {all_latencies_by_rcode_and_ip_normalised}")

    for i in range(maximum_length_of_list):
        for file_name in all_resolvers:
            if i not in all_list_of_stales:
                all_list_of_stales[i] = []
            try:
                if all_latencies_by_rcode_and_ip_normalised[file_name, "stale"][i] is not None:
                    all_list_of_stales[i].append(all_latencies_by_rcode_and_ip_normalised[file_name, "stale"][i])
            # If no more list entries for a resolver, dummy value
            except Exception:
                all_list_of_stales[i].append(dummy_value)

    # print(f"all_list_of_stales: {all_list_of_stales}")

    for i in range(maximum_length_of_list):
        for file_name in all_resolvers:
            if i not in all_list_of_errors:
                all_list_of_errors[i] = []
            try:
                if all_latencies_by_rcode_and_ip_normalised[file_name, "error"][i] is not None:
                    all_list_of_errors[i].append(all_latencies_by_rcode_and_ip_normalised[file_name, "error"][i])
            # If no more list entries for a resolver, dummy value
            except Exception:
                all_list_of_errors[i].append(-1)

    # print(f"all_list_of_stales: {all_list_of_errors}")

    # Columns are interpreted together

    all_list_of_stale_times = list(all_list_of_stales.values())
    all_list_of_error_times = list(all_list_of_errors.values())

    fig = plt.figure()
    ax1 = fig.add_subplot(111)

    plt.title(f"Stale Record Duration Experiment (TTL {current_ttl})")
    plt.xlabel("Time in Seconds")
    plt.ylabel("Resolver IPs")

    for lst in all_list_of_stale_times:
        ax1.scatter(lst, all_resolvers, s=size_of_stale_packets, c=color_of_stale_packets,
                    marker=marker_of_stale_packets)  # label='first'

    for lst in all_list_of_error_times:
        ax1.scatter(lst, all_resolvers, s=size_of_error_packets, c=color_of_error_packets,
                    marker=marker_of_error_packets)  # label='first'

    green = Patch(facecolor='green', edgecolor='green', label='Stale Record')
    red = Patch(facecolor='red', edgecolor='red', label='ServFail')
    ax1.legend(handles=[green, red], loc='upper left', framealpha=0.5, bbox_to_anchor=(0.0, 1.25))

    # plt.show()

    # Save to
    plt.savefig(f"{client_root_plot_folder_name}/StaleDurationTTL{current_ttl}Plot.png", dpi=100, bbox_inches='tight')
    print(f"      Created plot")

    # Clear plots
    plt.cla()
    plt.close()
