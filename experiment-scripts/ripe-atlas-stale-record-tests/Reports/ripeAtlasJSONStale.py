import matplotlib.pyplot as plt
import matplotlib.lines as mlines
import json
import re
import os
import time
import base64
import dns.message
from collections import deque


latencies_with_pl = {
    "latency_0": []
}

query_names_with_pl = {
    "query_names_0": []
}

answer_names_with_pl = {
    "answer_names_0": []
}

global duplicate_query_count_with_pl
duplicate_query_count_with_pl = {
    "duplicate_query_count_0": 0
}
global duplicate_answer_count_with_pl
duplicate_answer_count_with_pl = {
    "duplicate_answer_count_0": 0
}

global servfail_count_with_pl
servfail_count_with_pl = {
    "servfail_count_0": 0
}

global count_of_answers_with_pl
count_of_answers_with_pl = {
    "count_of_answers_0": 0
}

def get_desired_attribute(string_to_search, attribute_string):
    if attribute_string in string_to_search:
        return string_to_search.split(attribute_string)[1].split(",")[0]


def extract_attribute_from_buf(attr, buf):
    if attr in buf:
        return buf.split(attr)[1].split("\n")[0]


def extract_field_from_buf(attr, buf):
    if attr in buf:
        return buf.split(attr)[1].split("\n")[1]
    else:
        print(f"{attr} not in the string")


def extract_query_name(string):
    if string == "" or string is None:
        return ""
    try:
        last_index_of_dot = string.rindex(".")
    except ValueError:
        return ""
    result = string[0:last_index_of_dot]
    return result


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


directory_name_of_plots = "ripe-probes-plot-results"

if not os.path.exists(directory_name_of_plots):
    os.makedirs(directory_name_of_plots)


file_name_to_read_jsons = "JsonDecodedOnlyStalePhase.txt"
file = open(file_name_to_read_jsons, "r")
print(f"Reading file: {file_name_to_read_jsons}")

line_count = 1
answer_detected = False

for line in file:
    # print(f"=================")
    # print(f"Result ({line_count}):")
    stripped_line = line.rstrip()
    # print(f"Line: {stripped_line}")

    if "rcode" in stripped_line:
        print(f"{stripped_line}")

    if answer_detected:
        if ";" in stripped_line:
            # print(f"Skipping: {stripped_line}")
            answer_detected = False
        else:
            # print(f"Found answer: {stripped_line}")
            answer_detected = False

    if ";ANSWER" in stripped_line:
        answer_detected = True
        # print(f" Answer detected")
        # answer = extract_field_from_buf(';ANSWER', stripped_line)

    line_count += 1

file.close()

# index = 0
# for latencies_of_pl in latencies_with_pl:
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of {pl_rate} Packetloss rate latencies: {len(latencies_of_pl)}")
#     index += 1
#
# print(f"\n")
#
# index = 0
# for answer_names_of_pl in answer_names_with_pl:
#     values = list(answer_names_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of answer_names_of_pl {pl_rate}: {len(values)}")
#     # index2 = 0
#     # for query in values:
#     #     print(f"  {index2}. Query: {query}")
#     #     index2 += 1
#     index += 1
#
# index = 0
# for query_names_of_pl in query_names_with_pl:
#     values = list(query_names_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of query_names_of_pl {pl_rate}: {len(values)}")
#     # index2 = 0
#     # for query in values:
#     #     print(f"  {index2}. Query: {query}")
#     #     index2 += 1
#     index += 1
#
# print(f"\n")
#
# index = 0
# for elem in duplicate_answer_count_with_pl:
#     value = list(duplicate_answer_count_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of duplicate answer count for PL {pl_rate}: {value}")
#     index += 1
#
# print(f"\n")
#
# index = 0
# for elem in duplicate_query_count_with_pl:
#     value = list(duplicate_query_count_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of duplicate query count for PL {pl_rate}: {value}")
#     index += 1
#
# index = 0
# for elem in servfail_count_with_pl:
#     value = list(servfail_count_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of servfail_count_with_pl for PL {pl_rate}: {value}")
#     index += 1
#
# index = 0
# for elem in count_of_answers_with_pl:
#     value = list(count_of_answers_with_pl.values())[index]
#     pl_rate = get_pl_rate_of_index(index)
#     print(f"Length of count_of_answers_with_pl for PL {pl_rate}: {value}")
#     index += 1
#
# create_overall_latency_violin_plot(directory_name_of_plots, "ripe-atlas", bottom_limit, upper_limit, False)
# create_overall_box_plot(directory_name_of_plots, "ripe-atlas", bottom_limit, upper_limit, False)
# create_overall_bar_plot_failure(directory_name_of_plots, "ripe-atlas")
