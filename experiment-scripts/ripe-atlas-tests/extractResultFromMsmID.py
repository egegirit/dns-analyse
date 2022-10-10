import subprocess
import sys
import time
import os
import signal
from datetime import datetime, timedelta
from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
from ripe.atlas.sagan import DnsResult

id_list = [45678802, 45678803, 45678804]


def show_results(msm_id_list):
    f = open("ripeAtlasReport.txt", "w")

    print(f"Showing results")
    f.write("Showing results\n")

    print(f"Count of measurement id's: {len(id_list)}\n")
    f.write(f"Count of measurement id's: {len(id_list)}\n\n")

    for msm_id in msm_id_list:

        print(f"\n===== CURRENT MEASUREMENT ID: {msm_id} =====\n")
        f.write(f"\n===== CURRENT MEASUREMENT ID: {msm_id} =====\n\n")

        kwargs = {
            "msm_id": msm_id
        }

        is_success, results = AtlasResultsRequest(**kwargs).create()

        print(f"  All measurements with probes:")
        f.write("  All measurements with probes:\n")

        counter = 0
        for result in results:
            print(f"\n**** {counter}. Probe of the measurement ****")
            f.write(f"\n**** {counter}. Probe of the measurement ****\n")
            print(DnsResult.get(result))
            f.write(str(DnsResult.get(result)) + "\n")
            print(f"  Built response:\n{DnsResult.get(result).build_responses()}")
            f.write(f"  Built response:\n{DnsResult.get(result).build_responses()}\n")
            counter += 1

    f.close()


show_results(id_list)
