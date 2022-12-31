import ast

# Read a file and return the string representation of it
def read_dict_from_file(file_name):
    f = open(file_name, "r")
    content = str(f.read())
    return content


# Return all the values (lists) of the given dictionary
def get_values_of_dict(dictionary):
    all_values = list(dictionary.values())
    return all_values


# Convert a string (read from a text file) to python dictionary
def convert_string_to_dict(string_obj):
    return ast.literal_eval(string_obj)


file_name = "Retr_Query_Names_and_Counts_Pl_(PL_QueryName)_[Counts].txt"
retr_dict = convert_string_to_dict(read_dict_from_file(file_name))


max_value = 20
probe_ids = set()

for key, value in retr_dict.items():
    if value > max_value:
        print(f"{key}, {value}")
        probe_ids.add(key[1].split("-")[0])

print(f"Probes: (length {len(probe_ids)}) \n{probe_ids}")
