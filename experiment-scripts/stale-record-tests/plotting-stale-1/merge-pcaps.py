import subprocess
import os

packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95, 100]

directory_of_json_logs = "/home/domeras/Desktop/log"

auth_json_prefix = "tcpdump_log_auth_bond0_"
client_json_prefix = "tcpdump_log_client_bond0_"
random_chars_of_file = set()
command_input = ""

print(f"Listing auth files...")
# Extract the 3 random characters at the end of the json files
for path, currentDirectory, files in os.walk(directory_of_json_logs):
    for file in files:
        if file.startswith(auth_json_prefix):
            print(f"Found file: {file}")
            # Last 3 random character before the .pcap
            rnd = str(file).split(".")[0][-3:]
            print(f"  Extracted random string: {rnd}")
            random_chars_of_file.add(rnd)

print(f"Unique random strings: {random_chars_of_file}\n")


for current_file in ["client", "auth"]:
    print(f"Creating command for: {current_file}")

    for current_pl_rate in packetloss_rates:
        command_input = ""
        print(f"Current packetloss rate: {current_pl_rate}")

        output_file_name = current_file + "_stale_pl" + str(current_pl_rate) + ".pcap"
        print(f"  Output file name: {output_file_name}")

        files_to_merge = []
        for rand in random_chars_of_file:
            files_to_merge.append(str("tcpdump_log_" + current_file + "_bond0_" + str(current_pl_rate) + "_" + rand + ".pcap"))

        for f in files_to_merge:
            # all the files to be merged separated by a white space
            command_input += str(" " + f)


        merge_command = "mergecap -w " + output_file_name + command_input
        print(f"  Merge command: {merge_command}")

        try:
            subprocess.run(merge_command, shell=True, stdout=subprocess.PIPE, check=True)
        except Exception as e:
            print(e)

# TODO: also merge the pcaps from log2 directory, convert the merged PCAPs to JSON

