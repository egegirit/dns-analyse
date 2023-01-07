
# Read a file and return the string representation of it
def read_from_file(file_name):
    f = open(file_name, "r")
    content = str(f.read())
    print(f"  Returning string from file")
    return content


# Read a file and return the string representation of it
def write_to_file(file_name, content):
    print(f"    Writing to file {file_name}")
    f = open(file_name, "w")
    f.write(str(content))


file_name_prefix = "IPs_With_Rcode_0_PL_"

packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

for pl in packetloss_rates:
    print(f"Current PL rate: {pl}")

    current_file_name = file_name_prefix + str(pl) + ".txt"
    string = read_from_file(current_file_name)
    count = 0
    for c in string:
        if c == ",":
            count += 1

    write_to_file(f"IP_Count_Of_PL_{pl}.txt", str(count))

# for pl in packetloss_rates:
#     print(f"Current PL rate: {pl}")
#
#     current_file_name = file_name_prefix + str(pl) + ".txt"
#     string = read_from_file(current_file_name)
#     ip_set = set(string)
#     print(f"Length of PL rate {pl}: {len(ip_set)}")
