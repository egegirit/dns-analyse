from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
from ripe.atlas.sagan import DnsResult
from pprint import pprint
from datetime import datetime
import sys
import concurrent.futures

# https://atlas.ripe.net/docs/api/v2/reference/#!/measurements/Type
#
# [dns] udp_payload_size (integer): Set the EDNS0 option for UDP payload size to this value, between 512 and 4096.Defaults to 512),
# [dns] use_probe_resolver (boolean): Send the DNS query to the probe's local resolvers (instead of an explicitly specified target),
# [dns] set_rd_bit (boolean): Indicates Recursion Desired bit was set,
# [dns] prepend_probe_id (boolean): Each probe prepends its probe number and a timestamp to the DNS query argument to make it unique,
# [dns] protocol (string) = ['UDP' or 'TCP']: Protocol used in measurement. Defaults to UDP,
# [dns] retry (integer): Number of times to retry,
# [dns] include_qbuf (boolean): include the raw DNS query data in the result. Defaults to false,
# [dns] set_nsid_bit (boolean): Indicates Name Server Identifier (RFC5001) was set,
# [dns] include_abuf (boolean): include the raw DNS answer data in the result. Defaults to true,
# [dns] query_class (string) = ['IN' or 'CHAOS']: The `class` part of the query used in the measurement,
# [dns] query_argument (string): The `argument` part of the query used in the measurement,
# [dns] query_type (string) = ['A' or 'AAAA' or 'ANY' or 'CNAME' or 'DNSKEY' or 'DS' or 'MX' or 'NS' or 'NSEC' or 'PTR' or 'RRSIG' or 'SOA' or 'TXT' or 'SRV' or 'NAPTR' or 'TLSA']: The `type` part of the query used in the measurement,
# [dns] set_cd_bit (boolean): Indicates DNSSEC Checking Disabled (RFC4035) was set,
# [dns] set_do_bit (boolean): Indicates DNSSEC OK (RFC3225) was set,
# [dns] use_macros (boolean): Allow the use of $p (probe ID), $r (random 16-digit hex string) and $t (timestamp) in the query_argument,
# [dns] timeout (integer): Timeout in milliseconds (default: 5000),
# [dns] tls (boolean): Enable DNS over Transport Layer Security (RFC7858),
# [dns] port (integer): UDP or TCP port, if not specified defaults to port 53 or to port 853 for DNS-over-TLS,
# [dns] default_client_subnet (boolean): Enable an EDNS Client Subnet (RFC7871) of 0.0.0.0/0 0 or ::/0,
# [dns] cookies (boolean): Insert client cookie in requests and process server cookies,
# [dns] ttl (boolean): Report the IP time-to-live field (hop limit for IPv6) of DNS reply packets received (only for UDP),

# Sleep for a duration and show the remaining time on the console
def sleep_for_seconds(sleep_time):
    print(
        f"  Sleeping for {sleep_time} seconds."
    )
    print("  Remaining time:")
    # Output how many seconds left to sleep
    for i in range(sleep_time, 0, -1):
        print(f"{i}")
        time.sleep(1)
        # Delete the last output line of the console
        # to show the remaining time without creating new lines
        print("\033[A                             \033[A")

# Create a source from probe_id and send a query with domain_name as query name
def send_query_from_probe(probe_id, domain_name):
    dns = Dns(
        key=ATLAS_API_KEY,
        description = "Ege Girit Packetloss Experiment",
        protocol = "UDP",
        af = "4",
        
        # Enable more values as results
        include_abuf = True,
        include_qbuf = True,
        ttl = True,
        
        # Configure the DNS query
        query_class = "IN",
        query_type = "A",
        # Domain structure: <ip_addr>-<counter>-<packetloss_rate>.packetloss.syssec-research.mmci.uni-saarland.de
        query_argument = domain_name  # "packetloss.syssec-research.mmci.uni-saarland.de",  
        use_macros = True,
        # Each probe prepends its probe number and a timestamp to the DNS query argument to make it unique
        prepend_probe_id = True,
        
        # Use the probe's list of local resolvers instead of specifying a target to use as the resolver.
        use_probe_resolver = True,
        # Recursion Desired flag (RD, RFC1035)
        set_rd_bit = True,
        # DNSSEC OK flag (DO, RFC3225)
        set_do_bit = True,
        
        # Timeout in milliseconds
        timeout = 10000,
        # How often to retry the measurement
        retry = 0,
        
        udp_payload_size = 1200,
    )
    
    # Probe ID as parameter
    source2 = AtlasSource(    
        "type": "asn",
        "value": probe_ID,
        "requested": 1    
    )

    # Create request from given probe ID
    atlas_request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=ATLAS_API_KEY,
        measurements=[dns],
        sources=[source2],
        # Always set this to true
        # The measurement will only be run once
        is_oneoff=True
    )
    
    # Start the measurement
    (is_success, response) = atlas_request.create()
    is_success, response

    # %%
    kwargs = {
        "msm_id": response["measurements"][0]
    }

    # Wait for the probes to upload their results before asking for the results
    sleep_for_seconds(300)

    # Create results
    is_success, results = AtlasResultsRequest(**kwargs).create()
    is_success

    # Print results
    for result in results:
        print(DnsResult.get(result))

    # %%
    m = DnsResult.get(results[0])

    # %%
    m.measurement_id

    # %%
    m.build_responses()

    

# Run the script as follows:
# $ python3 ./packetlossExperimentRipeAtlas.py probeID .ripe-atlas<counter>.packetloss.syssec-research.mmci.uni-saarland.de
print(f"Number of arguments: {len(sys.argv)}")
print(f"Argument List: {str(sys.argv))}")
# Name of Python script: sys.argv[0]
probe_ID = sys.argv[1]
query_name = sys.argv[2]

ATLAS_API_KEY=""  # 0c51be25-dfac-4e86-9d0d-5fef89ea4670

# Atlas API specification from the probe selection website
probe_dict = { "probes": 
                [
                    {
                        "type": "asn",
                        "value": 24521,
                        "requested": 1
                    }, # ...
                ] }

# Get the the probe count
values = list(probe_dict.values())[0]
probe_count = len(values)
print(f"probe_count: {probe_count}")

# Store the extracted probe id's
probe_ids = []

# Extract the probe ID's from the selected probes in dictionary format
for index in range(probe_count):
    probe_ids.append(values[index]['value'])
    print(f"values: {values[index]['value']}")

# For each probe id, send a query from the probe and build the query with a counter value
# Counter value must be equal or greater than probe count
counter = 0    
for id in probe_ids:
    # Multithreading?
    with concurrent.futures.ProcessPoolExecutor() as executor:
            # Using list comprehention to build the results list
            # submit() schedules the callable to be executed and returns a 
            # future object representing the execution of the callable.
            results = [executor.submit(build_and_send_query_mp, [current_resolver_ip,
                                                                 current_packetloss_rate,
                                                                 counter_min,
                                                                 counter_max,
                                                                 sleep_time])
                        for current_resolver_ip in resolver_ip_addresses]
                query_name = ".ripe-atlas" + counter + ".packetloss.syssec-research.mmci.uni-saarland.de"
                send_query_from_probe(id, query_name)
                counter += 1        
        
    # Show the finished processes' outputs
    for f in concurrent.futures.as_completed(results):
        print(f.result())    
    