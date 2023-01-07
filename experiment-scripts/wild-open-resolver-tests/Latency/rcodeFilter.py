import ast
import json


def string_to_dict(string):
    return json.loads(string)


# Read a file and return the string representation of it
def read_dict_from_file(file_name):
    f = open(file_name, "r")
    content = str(f.read())
    print(f"  Returning string from file")
    return content


# Convert a string (read from a text file) to python dictionary
def convert_string_to_dict(string_obj):
    print(f"  Converting to dict")
    return ast.literal_eval(string_obj)


# Convert a string (read from a text file) to python dictionary
def convert_string_to_dictv2(string_obj):
    print(f"  Converting to dict")
    return eval(string_obj)


# Read a file and return the string representation of it
def write_to_file(file_name, content):
    print(f"    Writing to file {file_name}")
    f = open(file_name, "w")
    f.write(str(content))


packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]
file_name_prefix = "IP_PLRate_to_RCODEs_PL"

# # List of: (pl_rate, IP): [Rcode list]
# ip_dict = []
# # Read all text files into dicts
# for pl in packetloss_rates:
#     current_file_name = file_name_prefix + str(pl) + ".txt"
#     print(f"Reading file: {current_file_name}")
#     read_dict = convert_string_to_dictv2(read_dict_from_file(current_file_name))
#     print(f"  Appending to list")
#     ip_dict.append(read_dict)
#
# valid_rcode_ips = set()
# # invalid_rcode_ips = set()
# for i in range(len(ip_dict)):
#     print(f"Iteration: {i} of {len(ip_dict)}")
#     for key, value in ip_dict[i].items():
#         if 0 in value:
#             valid_rcode_ips.add(key[1])
#         # else:
#         #     invalid_rcode_ips.add(key[1])
#
# print(f"Writing to file")
# write_to_file("validRcodeIPs.txt", valid_rcode_ips)

for pl in packetloss_rates:
    print(f"Current PL rate: {pl}")

    current_file_name = file_name_prefix + str(pl) + ".txt"
    string = read_dict_from_file(current_file_name)
    ip_beginning = False
    in_rcode_list = False

    ip_addr = ""
    ip_list = set()
    rcode_list = []

    for c in string:
        if c == "'":
            ip_beginning = not ip_beginning
            # if not ip_beginning:
                # ip_list.add(ip_addr)
                # print(f"IP found: {ip_addr}")
                # ip_addr = ""
        else:
            if ip_beginning:
                ip_addr += str(c)

        if c == "[":  # and not ip_beginning:
            in_rcode_list = True
            continue
        elif c == "]":
            in_rcode_list = False
            # ip_list.add(ip_addr)
            # print(f"IP found: {ip_addr}")
            if "0" in rcode_list:
                if ip_addr not in ip_list:
                    ip_list.add(ip_addr)
                else:
                    print(f"Duplicate")
                # print(f"IP with RCODE 0 found: {ip_addr}")
                # print(f"  RCODE List: {rcode_list}")

            ip_addr = ""
            rcode_list = []
            continue

        if in_rcode_list:
            if c != "," and c != " ":
                rcode_list.append(c)
                # print(f"RCODE found: {c}")

    write_to_file(f"IPs_With_Rcode_0_PL_{pl}.txt", ip_list)
