import ast


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


file_name_prefix = "Latencies_(PacketLoss_RCODE)_[Latencies]_PL"
latency_file_name = "Latencies_PL"
packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]

index = 1
for pl in packetloss_rates:
    print(f"PL: {pl}")
    file_name = file_name_prefix + str(pl) + ".txt"
    content = read_from_file(file_name)

    first_index_to_search = 0

    for i in range(index):
        print(f"  {i}")
        first_index_to_search = content.find("[", first_index_to_search + 1)

    second_index = content.find("]", first_index_to_search)

    substring = content[first_index_to_search:second_index + 1]

    # lst = ast.literal_eval(substring)
    write_to_file(f"{latency_file_name}{pl}.txt", str(substring))
    index += 1

