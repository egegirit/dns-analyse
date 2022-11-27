import sys
import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import numpy as np
import re
import os
from scapy.all import *

# TODO: split pcap into iterations?
iteration = []

operators = {
    "Cloudflare1": "1-1-1-1",
    "Cloudflare2": "1-0-0-1",
    "Dyn1": "216-146-35-35",
    "Dyn2": "216-146-36-36",
    "OpenDNS1": "208-67-222-222",
    "OpenDNS2": "208-67-222-2",
    "Quad91": "9-9-9-9",
    "Quad92": "9-9-9-11"
}

overall_directory_name = "Overall-plot-results"
resolver_directory_name = "Resolver-plot-results"


def read_pcap(pcap_file_name):
    all_packets = PcapReader(pcap_file_name)
    for packet in all_packets:
        try:
            print(packet[IPv4].src)
            t = packet.fields['IPv4']
            print(t)
            # packet.show()
        except Exception:
            pass






# ---------------------------

def create_combined_plots(file_name_prefix, operator_name):
    n = 13
    ind = np.arange(n)  # the x locations for the groups
    width = 0.21  # the width of the bars
    arr = np.array([0, 1, 2, 3, 4, 5, 6, 7, 8, 8.5, 9, 9.5, 10])

    fig = plt.figure()
    ax = fig.add_subplot(111)

    # Get failure rates
    values = list(failed_packet_pl_rate.values())
    # print(f"Failure ratio: {values}")

    failure_rate_vals = values.copy()
    for i in range(len(failure_rate_vals)):
        try:
            failure_rate_vals[i] = failed_packet_pl_rate[str(packetloss_rates[i])]
        except ZeroDivisionError:
            print("Zero division error!")
            failure_rate_vals[i] = 0
    failure_rects = ax.bar(arr + width, failure_rate_vals, width, bottom=0, color='red')


    ok_vals = list(norerror_pl_rate.values())
    ok_rate_vals = ok_vals.copy()
    for i in range(len(ok_rate_vals)):
        try:
            ok_rate_vals[i] = (ok_rate_vals[i])
        except ZeroDivisionError:
            print("Zero division error!")
            ok_rate_vals[i] = 0

    # Calculate stale record values
    stale_rate_vals = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    index = 0
    for i in packetloss_rates:
        try:
            stale_rate_vals[index] = (stale_count_of_pl[str(i)])
        except ZeroDivisionError:
            print("Zero division error!")
            stale_rate_vals[index] = 0
        finally:
            index += 1

    subtracted = list()
    for item1, item2 in zip(ok_rate_vals, stale_rate_vals):
        subtracted.append(item1 - item2)

    subtracted1 = list()
    for item1, item2 in zip(ok_rate_vals, subtracted):
        subtracted1.append(item1 - item2)

    ok_rects = ax.bar(arr, subtracted, width, bottom=0, color='green')
    stale_rects = ax.bar(arr, stale_rate_vals, width, bottom=subtracted, color='yellow')

    plot_title = f"Stale Record Experiment ({operator_name})"

    plt.xlabel("Packetloss rate")
    plt.ylabel("Results")
    # ax.set_ylabel('Results')
    plt.title(plot_title, x=0.5, y=1.1)
    plt.ylim(bottom=0)

    ax.set_xticks(arr + width/2)
    ax.set_xticklabels((0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100))
    ax.legend((failure_rects[0], ok_rects[0], stale_rects[0]), ('Failure', 'OK', 'Stale'), framealpha=0.5, bbox_to_anchor=(1, 1))

    def autolabel(rects):
        for rect in rects:
            h = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., h + 1, '%d' % int(h),
                    ha='center', va='bottom')

    def autolabel_ok(rects):
        for rect in rects:
            h = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., h - 1.5, '%d' % int(h),
                    ha='center', va='bottom')

    def autolabel_stale(rects, ok_rects):
        h_of_ok = []
        for rect in ok_rects:
            h = rect.get_height()
            h_of_ok.append(int(h))

        i = 0
        for rect in rects:
            h = rect.get_height()
            ax.text(rect.get_x() + rect.get_width() / 2., (h + 1.5) + h_of_ok[i], '%d' % int(h),
                    ha='center', va='bottom')
            i += 1

    autolabel(failure_rects)
    autolabel_ok(ok_rects)
    autolabel_stale(stale_rects, ok_rects)
    # autolabel(refused_rects)

    plt.show()

    # save plot as png
    # plt.savefig((file_name_prefix + '_StaleRecordPlot.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create box plot for the calculated latencies
def create_overall_box_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, log_scale=False):
    print(f" Creating box plot: {file_name_prefix}")
    print(f"   Inside the folder: {directory_name}")
    print(f"   Limits: [{bottom_limit}, {upper_limit}]")
    # print(f"   Log-scale: {log_scale}")

    # Create box plot for latency-packetloss
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])
    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    ax.set_title(f"Response Latency of Stale Records")

    # y-axis labels
    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

    if log_scale:
        ax.set_yscale('log', base=2)
    # else: ax.set_yscale('linear')

    # Add the data counts onto the plot as text
    data_count_string = ""
    for i in range(len(get_values_of_dict(latency_of_stales_pl))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(get_values_of_dict(latency_of_stales_pl)[i])) + "\n"

    left, width = .25, .5
    bottom, height = .25, .5
    right = left + width
    top = bottom + height
    ax.text(0.5 * (left + right), .75 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Creating plot
    ax.boxplot(get_values_of_dict(latency_of_stales_pl), positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100],
               widths=4.4)

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name_prefix + '_boxPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created box plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


# Create violin plots of the calculated latencies
def create_overall_latency_violin_plot(directory_name, file_name_prefix, bottom_limit, upper_limit, log_scale=False):
    print(f" Creating violin plot: {file_name_prefix}")
    print(f"   Inside the folder: {directory_name}")
    print(f"   Limits: [{bottom_limit}, {upper_limit}]")
    # print(f"   Log-scale: {log_scale}")

    # Create violin plot
    fig2 = plt.figure(figsize=(10, 7))

    # Creating axes instance
    ax = fig2.add_axes([0, 0, 1, 1])

    # Set the X axis labels/positions
    ax.set_xticks([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])
    ax.set_xticklabels([0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

    ax.set_ylabel('Latency in seconds')
    ax.set_xlabel('Packetloss in percentage')

    ax.set_title(f"Response Latency for Stale Records")

    if log_scale:
        ax.set_yscale('log', base=2)

    # Handle zero values with a -1 dummy value
    data = get_values_of_dict(latency_of_stales_pl)
    for i in range(len(data)):
        if len(data[i]) == 0:
            data[i] = -1

    # Create and save Violinplot
    bp = ax.violinplot(dataset=data, showmeans=True, showmedians=True,
                       showextrema=True, widths=4.4, positions=[0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100])

    # Add the data counts onto plot
    # But if the list was empty and we added a dummy value, subtract it from the plot text
    data_count_string = ""
    for i in range(len(get_values_of_dict(latency_of_stales_pl))):
        data_count_string += "PL " + str(packetloss_rates[i]) + ": " + str(
            len(get_values_of_dict(latency_of_stales_pl)[i])) + "\n"

    left, width = .25, .5
    bottom, height = .25, .5
    right = left + width
    top = bottom + height
    ax.text(0.5 * (left + right), .75 * (bottom + top), data_count_string,
            horizontalalignment='center',
            verticalalignment='center',
            transform=ax.transAxes, color='red')

    # Mean is blue
    bp['cmeans'].set_color('b')
    # Median is red
    bp['cmedians'].set_color('r')
    plt.ylim(bottom=bottom_limit, top=upper_limit)

    # Add legend for mean and median
    blue_line = mlines.Line2D([], [], color='blue', marker='', markersize=15, label='mean')
    red_line = mlines.Line2D([], [], color='red', marker='', markersize=15, label='median')
    ax.legend(handles=[blue_line, red_line], loc='upper left')

    # save plot as png
    plt.savefig(directory_name + "/" + (file_name_prefix + '_violinPlotLatency.png'), bbox_inches='tight')
    # show plot
    # plt.show()
    print(f" Created violin plot: {file_name_prefix}")
    # Clear plots
    plt.cla()
    plt.close()


auth_json_prefix = "auth_stale_pl"
client_json_prefix = "client_stale_pl"

# Debug
stale_phase_count = 0
prefetching_phase_count = 0
experiment_count = 0

all_query_names = set()


def read_json_file(filename, pl_rate, resolver_filter):
    global stale_phase_count
    global prefetching_phase_count
    global experiment_count
    print(f"Reading file: {filename}")
    if not os.path.exists("./" + filename):
        print(f"File not found: {filename}")
        exit()
    # Read the measured latencies from json file
    file = open(filename)
    json_data = json.load(file)
    packet_count = len(json_data)
    # print(f"  Number of packets in JSON file: {packet_count}")

    pcap_type = ""
    if "client" in filename:
        pcap_type = "client"
    elif "auth" in filename:
        pcap_type = "auth"
    else:
        pcap_type = "Unknown"

    frame_time_relative_of_previous = 0
    phases = ["Prefetching", "Stale"]
    phase_index = 0

    # Examine all the packets in the JSON file
    for i in range(0, packet_count):
        # print(f"----------------")
        # Check if the packet is a DNS packet
        if 'dns' in json_data[i]['_source']['layers']:

            json_string = str(json_data[i]['_source']['layers']['dns']['Queries'])
            splitted_json1 = json_string.split("'dns.qry.name': ")
            splitted2 = str(splitted_json1[1])
            query_name = splitted2.split("'")[1]
            # print(f"Pcap type: {pcap_type}")
            # print(f"Current query name: {query_name}")

            # Filter query names that doesn't belong to our experiment
            # Example query: stale-1-0-0-1-50-ENM-0.packetloss.syssec-research.mmci.uni-saarland.de
            query_name_lower = query_name.lower()
            if "ns1.packetloss.syssec-research.mmci.uni-saarland.de" in query_name_lower or "_.packetloss.syssec-research.mmci.uni-saarland.de" in query_name_lower \
                    or ".packetloss.syssec-research.mmci.uni-saarland.de" not in query_name_lower \
                    or "_" in query_name_lower:
                # print(f"Skipping invalid domain name: {query_name}")
                continue

            # Get frame number and frame time relative of packet
            if 'frame' in json_data[i]['_source']['layers']:
                if "frame.time_relative" in json_data[i]['_source']['layers']['frame']:
                    frame_time_relative = float(json_data[i]['_source']['layers']['frame']["frame.time_relative"])
                    # print(f"frame_time_relative: {frame_time_relative}")
                if "frame.number" in json_data[i]['_source']['layers']['frame']:
                    frame_number = int(json_data[i]['_source']['layers']['frame']["frame.number"])
                    # print(f"frame_number: {frame_number}")
                if "frame.time_epoch" in json_data[i]['_source']['layers']['frame']:
                    frame_time_epoch = float(json_data[i]['_source']['layers']['frame']["frame.time_epoch"])
                    # print(f"frame_time_epoch: {frame_time_epoch}")
                if "frame.time" in json_data[i]['_source']['layers']['frame']:
                    frame_time = json_data[i]['_source']['layers']['frame']["frame.time"]
                    # print(f"frame_time: {frame_time}")

            # Get source and destination IP of the DNS packet
            if 'ip' in json_data[i]['_source']['layers']:
                if "ip.src" in json_data[i]['_source']['layers']["ip"]:
                    ip_src = json_data[i]['_source']['layers']["ip"]["ip.src"]
                    # print(f"IP SRC: {ip_src}")
                if "ip.dst" in json_data[i]['_source']['layers']["ip"]:
                    ip_dst = json_data[i]['_source']['layers']["ip"]["ip.dst"]
                    # print(f"IP DST: {ip_dst}")

            # Filter specific resolver packets by the query's IP Address

            try:
                last_label = query_name.split(".")[0]
                splitted_domain = last_label.split("-")
                ip_addr_with_dashes = splitted_domain[1] + "-" + splitted_domain[2] + "-" + \
                                      splitted_domain[3] + "-" + splitted_domain[4]
            except Exception as e:
                print(f"Error")
                print(f"{e}")
                print(f"Current query name: {query_name}")
                print(f"frame_number: {frame_number}")

            operator = get_operator_name_from_ip(ip_addr_with_dashes)
            # print(f"Operator: {operator}")

            # Filter the given resolvers packets
            skip_packet = False
            if filtered_resolvers:
                for resolver in filtered_resolvers:
                    if resolver == operator:
                        skip_packet = True
                        break
            if skip_packet:
                continue

            # print(f"IP Address in query: {ip_addr_with_dashes}")
            pl_rate_of_query_name = splitted_domain[5]

            if str(pl_rate) != pl_rate_of_query_name:
                # print(f"  Different packetloss query detected!")
                # print(f"  Current PL: {str(pl_rate)}")
                # print(f"  Packet  PL: {pl_rate_of_query_name}")
                # print(f"  Skipping packet...")
                non_matching_pl_rate[str(pl_rate)] += 1
                # time.sleep(1)
                continue

            # print(f"Packetloss rate: {pl_rate_of_query_name}")
            random_token_of_query = splitted_domain[6]
            # print(f"random_token_of_query: {random_token_of_query}")
            counter_of_random_token = splitted_domain[7]
            # print(f"counter_of_random_token: {counter_of_random_token}")

            if "dns.id" in json_data[i]['_source']['layers']['dns']:
                dns_id = json_data[i]['_source']['layers']['dns']["dns.id"]
                # print(f"DNS ID: {dns_id}")

            if "dns.flags_tree" in json_data[i]['_source']['layers']['dns']:
                if "dns.flags.response" in json_data[i]['_source']['layers']['dns']["dns.flags_tree"]:
                    is_response = json_data[i]['_source']['layers']['dns']["dns.flags_tree"]["dns.flags.response"]
                    # print(f"Is response: {is_response}")
                    if is_response == "1":
                        rcode = json_data[i]['_source']['layers']['dns']['dns.flags_tree']['dns.flags.rcode']
                        # print(f"RCODE: {rcode}")

                        if 'dns.time' in json_data[i]['_source']['layers']['dns']:
                            dns_time = float(json_data[i]['_source']['layers']['dns']['dns.time'])
                            # print(f"dns_time: {dns_time}")
                        if "dns.count.answers" in json_data[i]['_source']['layers']['dns']:
                            answer_count = json_data[i]['_source']['layers']['dns']["dns.count.answers"]
                            if int(answer_count) >= 1:
                                # print(f"Answer count: {answer_count}")
                                answer_string = str(json_data[i]['_source']['layers']['dns']["Answers"])
                                # print(f"answer_string: {answer_string}")
                                splitted1 = answer_string.split("'dns.a': ")
                                # print(f"splitted1: {splitted1}")
                                splitted2 = str(splitted1[1])
                                a_record = splitted2.split("'")[1]
                                # print(f"A record: {a_record}")

                                splitted3 = answer_string.split("'dns.resp.ttl': ")
                                splitted4 = str(splitted3[1])
                                ttl_of_answer = int(splitted4.split("'")[1])
                                # print(f"TTL: {ttl_of_answer}")

            is_a_new_query = query_name in all_query_names
            if is_a_new_query:
                pass
                # print(f"  Query is NEW ********")
            else:
                pass
                # print(f"  Query was sent before")
            # Add only query names of queries, not responses
            if is_response == "0":
                all_query_names.add(query_name)

            # Calculate the time difference to the previous packet and try to calculate, which phase the packet belongs to
            time_diff_to_previous_packet = frame_time_relative - frame_time_relative_of_previous
            # print(f"                               Time diff to previous packet: {time_diff_to_previous_packet}")
            time_diff_abs = abs(frame_time_relative - frame_time_relative_of_previous)
            if time_diff_abs < ttl_wait_time:
                pass
                # print(f"Same phase, add packet")
                # print(f"Adding packet to phase: {phases[phase_index]}")
            elif ttl_wait_time <= time_diff_abs <= wait_packetloss_config:
                # print(f"  @@@@@ Phase switching detected, first packet of the phase")
                phase_index = (phase_index + 1) % 2
                # print(f"  Adding packet to phase: {phases[phase_index]}")
                # Debug
                # print(f"Reading file: {filename}")
                # print(f"Current query name: {query_name}")
                # print(f"frame_number: {frame_number}")
                # print(f"Time diff to previous packet: {time_diff_abs}")
                pass
                if phases[phase_index] == "Stale":
                    stale_phase_count += 1
                elif phases[phase_index] == "Prefetching":
                    prefetching_phase_count += 1

            # Packet capture is terminated after 600 sec waiting phase
            # elif wait_packetloss_config < time_diff_abs < 700:
            #    # print(f"  @@@@@ First packet after cooldown phase")
            #    phase_index = 0
            #    # print(f"  Adding packet to phase: {phases[phase_index]}")

            elif time_diff_abs >= 700:  # 7200 = 12(pl araları) * 600(pl arası cooldown)
                # print(f"  @@@@@ NEW EXPERIMENT BEGIN?")
                phase_index = 0
                experiment_count += 1
                # Debug
                # print(f"Reading file: {filename}")
                # print(f"Current query name: {query_name}")
                # print(f"frame_number: {frame_number}")
                # print(f"Time diff to previous packet: {time_diff_abs}")

            frame_time_relative_of_previous = frame_time_relative

            global stale_count_of_pl
            global non_stale_count_of_pl
            global latency_of_stales_pl
            # Count if query was stale
            if is_response == "1" and phases[phase_index] == "Stale" and rcode == "0":
                latency_of_stales_pl[pl_rate_of_query_name].append(dns_time)
                expected_stale_a_record = ("139." + str(pl_rate) + "." + str(pl_rate) + "." + str(pl_rate))
                expected_noerror_a_record = (
                        "139." + str(int(pl_rate) + 1) + "." + str(int(pl_rate) + 1) + "." + str(int(pl_rate) + 1))

                # print(f"expected_stale_a_record: {expected_stale_a_record}")
                # print(f"expected_noerror_a_record: {expected_noerror_a_record}")

                # print(f"    Added latency")
                if expected_stale_a_record == a_record:
                    # print("1")
                    stale_count_of_pl[pl_rate_of_query_name] += 1
                    # print(f"    Marked as stale")
                elif expected_noerror_a_record == a_record:
                    # print("0")
                    non_stale_count_of_pl[pl_rate_of_query_name] += 1
                    # print(f"    Marked as Non-stale")

            # Calculate failure rate/refused/noerror rate of stale phase packets
            if is_response == "1" and phases[phase_index] == "Stale":
                if str(rcode) == "2":
                    failed_packet_pl_rate[str(pl_rate)] += 1
                elif str(rcode) == "0":
                    norerror_pl_rate[str(pl_rate)] += 1
                elif str(rcode) == "5":
                    refused_packet_pl_rate[str(pl_rate)] += 1

            # Get all response and queries count
            if phases[phase_index] == "Stale":
                if is_response == "1":
                    responses_pl_rate[str(pl_rate)] += 1
                elif is_response == "0":
                    queries_pl_rate[str(pl_rate)] += 1

            # Debug yandex latencies
            # if is_response == "1":
            #    if dns_time >= 40:
            #        print(f"dns_time: {dns_time}")
            #        print(f"qry name: {query_name}")
            #        print(f"frame no: {frame_number}")
            #        print(f"JSON PL rate: {pl_rate}")
            #        # time.sleep(20)

            # Store packet to operator list
            if is_response == "1" and phases[phase_index] == "Stale":
                operator_stale_packets[operator].append(json_data[i])


# "Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92",
filtered_resolvers = ["Cloudflare1", "Cloudflare2", "Dyn1", "Dyn2", "OpenDNS1", "OpenDNS2", "Quad91", "Quad92"]

name = "AdGuard"

directory_name = name

read_pcap()

# Create directory to store logs into it
if not os.path.exists(directory_name):
    os.makedirs(directory_name)

# create_combined_plots(name, name)
