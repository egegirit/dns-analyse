import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import json
import re
import os
import time
import base64
import dns.message
from collections import deque


# The packetloss rates that are simulated in the experiment
packetloss_rates = [40, 60, 70, 80, 90, 95]


def get_desired_attribute(string_to_search, attribute_string):
    if attribute_string in string_to_search:
        return string_to_search.split(attribute_string)[1].split(",")[0]


def getIndex(s, i):
    # If input is invalid.
    if s[i] != '{':
        return -1

    # Create a deque to use it as a stack.
    d = deque()

    # Traverse through all elements
    # starting from i.
    for k in range(i, len(s)):

        # Pop a starting bracket
        # for every closing bracket
        if s[k] == '}':
            d.popleft()

        # Push all starting brackets
        elif s[k] == '{':
            d.append(s[i])

        # If deque becomes empty
        if not d:
            return k

    return -1


# TODO: multiple times, abufs, qbufs. Count the {}'s?
for pl_rate in packetloss_rates:
    print(f"**** Current packetloss rate: {pl_rate} ****")
    file_name_to_read_jsons = "ripeAtlasJSON-pl" + str(pl_rate) + ".txt"
    file = open(file_name_to_read_jsons, "r")
    print(f"Reading file: {file_name_to_read_jsons}")
    line_count = 1
    for line in file:
        print(f"=================")
        print(f"Result ({line_count}):")
        stripped_line = line.rstrip()

        list_of_reports = []

        json_count = 0
        stop = False
        while not stop:
            # count_brackets(stripped_line)
            first_bracket_index = stripped_line.find("{")
            # print(first_bracket_index)
            matching_bracket_index = getIndex(stripped_line, first_bracket_index)
            # print(matching_bracket_index)
            # print(f"Stripped: {stripped_line[first_bracket_index:matching_bracket_index]}")

            list_of_reports.append(stripped_line[first_bracket_index:matching_bracket_index])
            # print(f"Added to list")
            json_count += 1

            stripped_line = stripped_line[matching_bracket_index + 1:]
            # print(f"Remaining: {stripped_line}")
            next_bracket_index = stripped_line.find("{")
            # print(next_bracket_index)
            if next_bracket_index == -1:
                stop = True
                # print(f"Stopping with {json_count}")

        print(f"  Total report count: {len(list_of_reports)}")

        report_count = 1
        for report in list_of_reports:

            print(f"\n  Report ({report_count}):")

            epoch_time = int(get_desired_attribute(report, "'time': "))
            epoch_to_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(epoch_time))
            print(f"Time: {epoch_time} -> {epoch_to_date}")
            src_ip = get_desired_attribute(report, "'src_addr': ")
            print(f"Source IP: {src_ip}")
            dst_ip = get_desired_attribute(report, "'dst_addr': ")
            print(f"Source IP: {dst_ip}")
            ttl = get_desired_attribute(report, "'ttl': ")
            print(f"TTL: {ttl}")
            protocol = get_desired_attribute(report, "'proto': ")
            print(f"Protocol: {protocol}")

            qbuf = get_desired_attribute(report, "'qbuf': ")
            if qbuf is not None:
                qbuf_decoded = dns.message.from_wire(base64.b64decode(qbuf))
                print(f"\nQBUF:\n{qbuf_decoded}")

            if "'result':" in report:
                # print(f"Packet has result")
                result_json = report.split("'result':")[1]
                # print(f"result_json: {result_json}")
                response_time = float(get_desired_attribute(report, "'rt': "))
                print(f"Response time: {response_time} (ms) -> {response_time/1000.0} (s)")

                abuf = get_desired_attribute(report, "'abuf': ")
                if abuf is not None:
                    abuf_decoded = dns.message.from_wire(base64.b64decode(abuf))
                    print(f"\nABUF:\n{abuf_decoded}")
            report_count += 1

        print(f"\n")
        line_count += 1


    file.close()


