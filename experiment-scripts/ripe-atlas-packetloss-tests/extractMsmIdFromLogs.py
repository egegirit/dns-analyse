import os


def show_results():
    directory_name = "Measurement-IDs"
    file_name_all_JSON = "allMeasurementIDs.txt"
    file_name_to_read = "measurement-logs.txt"

    file_name_with_pl_rate_end = "-measurement-ids.txt"

    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

    joined_path1 = os.path.join(directory_name, file_name_all_JSON)

    file_to_write = open(joined_path1, "w")
    file_to_read = open(file_name_to_read, "r")

    for line in file_to_read:
        packetlossrate = line.rstrip().split(": ")[1].split(",")[0]
        print(packetlossrate)

        file_name_with_pl_rate = str(packetlossrate) + file_name_with_pl_rate_end
        joined_path2 = os.path.join(directory_name, file_name_with_pl_rate)
        file_to_append = open(joined_path2, "a")

        current_msm_id = line.rstrip().split("[")[1].split("]")[0]
        print(current_msm_id)

        file_to_append.write(f"{current_msm_id}\n")
        file_to_append.close()
        file_to_write.write(f"{current_msm_id}\n")

    file_to_write.close()
    file_to_read.close()


show_results()
