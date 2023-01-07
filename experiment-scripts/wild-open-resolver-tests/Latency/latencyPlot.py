import sys
import time
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import re
import os
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import ast


packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]


# Read a file and return the string representation of it
def read_from_file(file_name):
    f = open(file_name, "r")
    content = str(f.read())
    print(f"  Returning string from file")
    return content


# Create a folder with the given name
def create_folder(folder_name):
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)
        print(f"Folder {folder_name} created")
    else:
        print(f"Folder {folder_name} already exists")


# Create box plot for the calculated latencies
def create_latency_box_plot(root_directory_name, file_name_prefix, bottom_limit, upper_limit, latency_list):
    print(f"    Creating box plot: {file_name_prefix}")

    save_path = f"{root_directory_name}"
    create_folder(save_path)

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')
    # ax.set_title(f"Response Latency of " + file_name_prefix)

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks(packetloss_rates)
    ax.set_xticklabels(packetloss_rates)

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Creating plot
    ax.boxplot(latency_list, positions=packetloss_rates, widths=4.4)

    plt.savefig(f"{save_path}/{file_name_prefix}_LatencyBoxPlot.pdf", bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created latency box plot")
    # Clear plots
    plt.cla()
    plt.close()


# Create violin plots of the calculated latencies
def create_latency_violin_plot(root_directory_name, file_name_prefix, bottom_limit, upper_limit, latency_list):
    print(f"    Creating violin plot: {file_name_prefix}")
    # print(f"   Inside the folder: {root_directory_name}")
    # print(f"   Log-scale: {log_scale}")

    save_path = f"{root_directory_name}"
    create_folder(save_path)

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks(packetloss_rates)
    ax.set_xticklabels(packetloss_rates)

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')
    # ax.set_title(f"Response Latency of " + file_name_prefix)

    # for lst in latency_list:
    #     for latency in lst:
    #         if latency > upper_limit:
    #             upper_limit = latency

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Handle zero values with a -1 dummy value
    # empty_list_indexes = []
    # for i in range(len(latency_list)):
    #     if len(latency_list[i]) == 0:
    #         latency_list[i] = [-1]
    #         empty_list_indexes.append(i)
    #
    # print(f"  empty_list_indexes: {empty_list_indexes}")

    # Create and save Violinplot
    bp = ax.violinplot(dataset=latency_list, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=packetloss_rates)

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    # data_count_string = ""
    # for i in range(len(latency_list)):
    #     length_of_list_index = len(latency_list[i])
    #     if i in empty_list_indexes:
    #         length_of_list_index -= 1
    #     data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
    #         length_of_list_index) + "\n"
    #
    # left, width = .25, .5
    # bottom, height = .25, .5
    # right = left + width
    # top = bottom + height
    # ax.text(0.5 * (left + right), .80 * (bottom + top), data_count_string,
    #         horizontalalignment='center',
    #         verticalalignment='center',
    #         transform=ax.transAxes, color='red')

    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')

    # Add legend for mean and median
    blue_line = mlines.Line2D([], [], color='blue', marker='', markersize=15, label='mean')
    red_line = mlines.Line2D([], [], color='red', marker='', markersize=15, label='median')
    ax.legend(handles=[blue_line, red_line], loc=(0,1))

    # save plot
    plt.savefig(f"{save_path}/{file_name_prefix}_LatencyViolinPlot.pdf", bbox_inches='tight')

    # show plot
    # plt.show()
    print(f"      Created latency violin plot")
    # Clear plots
    plt.cla()
    plt.close()


file_name_prefix = "Latencies_PL"
all_latencies_with_pl = []
plot_name = "DNSScan"
directory_name = "DNSScanPlots"

for pl in packetloss_rates:
    print(f"packetloss_rate: {pl}")
    file_name = file_name_prefix + str(pl) + ".txt"
    all_latencies_with_pl.append(ast.literal_eval(read_from_file(file_name)))

create_latency_box_plot(directory_name, plot_name, 0, 20, all_latencies_with_pl)
create_latency_violin_plot(directory_name, plot_name, 0, 20, all_latencies_with_pl)
