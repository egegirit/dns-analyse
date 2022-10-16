from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
from ripe.atlas.sagan import DnsResult
import os

# Store all measurement ID's here
id_list_all = []
id_list_with_pl = {
    "40": [], "60": [], "70": [], "80": [], "90": [], "95": []
}


# Initialize the measurement ID array by reading the text file line by line
def initialize_id_list(file_name_of_msm_ids):

    dir_name_of_files = "Measurement-IDs"
    joined_path = os.path.join(dir_name_of_files, file_name_of_msm_ids)

    f1 = open(joined_path, "r")
    print("Initialising all ID's")
    global id_list_all
    for line in f1:
        current_msm_id = line.rstrip()
        print(current_msm_id)
        id_list_all.append(int(current_msm_id))
    f1.close()
    print("DONE")

    print("Initialising ID's by packetloss rate")
    global id_list_with_pl
    pl_rates = id_list_with_pl.keys()
    for pl_rate in pl_rates:
        file_name = pl_rate + "-measurement-ids.txt"
        joined_path = os.path.join(dir_name_of_files, file_name)
        f2 = open(joined_path, "r")
        for line in f2:
            current_msm_id = line.rstrip()
            print(current_msm_id)
            id_list_with_pl[pl_rate].append(int(current_msm_id))
    f2.close()
    print("DONE")


# Fetch results from ripe atlas, write it to a text file
def show_results(msm_id_list, directory_name):
    print("Storing all results")
    if not os.path.exists(directory_name):
        os.makedirs(directory_name)

    file_name_of_reports = "ripeAtlasReport.txt"
    file_name_of_all_jsons = "ripeAtlasAllJSONs.txt"
    file_name_of_json_by_pl_rate = "ripeAtlasJSON-pl"

    joined_path_reports = os.path.join(directory_name, file_name_of_reports)
    joined_path_all_jsons = os.path.join(directory_name, file_name_of_all_jsons)

    f = open(joined_path_reports, "w")
    f2 = open(joined_path_all_jsons, "w")

    # print(f"Showing results")
    f.write("Showing results\n")

    # print(f"Count of measurement id's: {len(id_list_all)}\n")
    f.write(f"Count of measurement id's: {len(id_list_all)}\n\n")

    for msm_id in msm_id_list:

        # print(f"\n===== CURRENT MEASUREMENT ID: {msm_id} =====\n")
        f.write(f"\n===== CURRENT MEASUREMENT ID: {msm_id} =====\n\n")

        kwargs = {
            "msm_id": msm_id
        }

        is_success, results = AtlasResultsRequest(**kwargs).create()

        counter = 0
        for result in results:
            # print(f"\n{counter}. Probe of the measurement:\n")
            f.write(f"\n{counter}. Probe of the measurement:\n\n")
            # print(DnsResult.get(result))
            f.write(str(DnsResult.get(result)) + "\n")
            # print(f"Built response:\n{DnsResult.get(result).build_responses()}\n")
            f.write(f"Built response:\n{DnsResult.get(result).build_responses()}\n\n")
            f2.write(f"{DnsResult.get(result).build_responses()}\n")
            counter += 1

    f.close()
    f2.close()
    print("DONE")

    print("Storing results by packetloss rate")
    global id_list_with_pl
    pl_rates = id_list_with_pl.keys()
    for pl_rate in pl_rates:
        file_name = file_name_of_json_by_pl_rate + pl_rate + ".txt"
        print(f"Opening file: {file_name}")
        joined_path = os.path.join(directory_name, file_name)
        f3 = open(joined_path, "w")
        for msm_id in id_list_with_pl[pl_rate]:
            kwargs = {
                "msm_id": msm_id
            }
            is_success, results = AtlasResultsRequest(**kwargs).create()
            for result in results:
                f3.write(f"{DnsResult.get(result).build_responses()}\n")

    f3.close()
    print("DONE")


file_name_of_measurement_ids = "allMeasurementIDs.txt"
dir_name = "Reports"

initialize_id_list(file_name_of_measurement_ids)
show_results(id_list_all, dir_name)
