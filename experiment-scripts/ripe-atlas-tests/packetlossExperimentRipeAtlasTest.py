from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
from ripe.atlas.sagan import DnsResult
from pprint import pprint
from datetime import datetime
import sys
import concurrent.futures

ATLAS_API_KEY=""  # 0c51be25-dfac-4e86-9d0d-5fef89ea4670

# Atlas API specification from the probe selection website https://ihr.iijlab.net/ihr/en-us/metis/selection
probe_dict = { "probes": 
                [
                    {
                        "type": "asn",
                        "value": 24521,
                        "requested": 1
                    }, # ...
                ] }
                
# Store the extracted probe id's in a list
as_ids = []                

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
        f"  Sleeping for {sleep_time} seconds to let the probes upload their results."
    )
    print("  Remaining time:")
    # Output how many seconds left to sleep
    for i in range(sleep_time, 0, -1):
        print(f"{i}")
        time.sleep(1)
        # Delete the last output line of the console
        # to show the remaining time without creating new lines
        print("\033[A                             \033[A")
        

# Builds the query name string that the probe will send to the resolver 
# from the given counter value
# Query structure: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
def build_query_name_from_counter(counter):
    if counter is not None and len(str(counter)) > 0:
        return ".ripe-atlas-" + str(counter) + ".packetloss.syssec-research.mmci.uni-saarland.de"


# Create a source from asn_id and send a query with domain_name as query name
def send_query_from_probe(asn_id, counter):

    print(f"  Building query name from current counter value: {counter}")  
    # Build the query name from the counter value
    query_name = build_query_name_from_counter(counter)  
    print(f"    Built query name: {query_name}") 

    print(f"  Creating DNS Query") 
    dns = Dns(
        key=ATLAS_API_KEY,
        description = f"Ege Girit Packetloss Experiment {counter}",
        protocol = "UDP",
        af = "4",
        
        # Enable more values as results
        include_abuf = True,
        include_qbuf = True,
        ttl = True,
        
        # Configure the DNS query
        query_class = "IN",
        query_type = "A",
        # Domain name: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de
        query_argument = query_name,
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
    
    print(f"  Creating source from given asn_ID: {asn_id}")
    # Probe ID as parameter
    source1 = AtlasSource(    
        "type": "asn",
        "value": asn_ID,
        "requested": 1    
        )

    print(f"  Creating request from source")
    # Create request from given probe ID
    atlas_request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=ATLAS_API_KEY,
        measurements=[dns],
        sources=[source1],
        # Always set this to true
        # The measurement will only be run once
        is_oneoff=True
    )
    
    print(f"  Starting measurement")
    # Start the measurement
    (is_success, response) = atlas_request.create()
    is_success, response

    # %%
    kwargs = {
        "msm_id": response["measurements"][0]
    }

    # Wait for the probes to upload their results before asking for the results
    sleep_for_seconds(300)

    # No needed on authoritative Server
    # Results can be downloaded later using measurement ID's
    print(f"  Creating results")
    # Create results
    is_success, results = AtlasResultsRequest(**kwargs).create()
    is_success

    print(f"  Results:")
    # Print results
    for result in results:
        print(DnsResult.get(result))

    # %%
    m = DnsResult.get(results[0])

    # %%
    m.measurement_id

    # %%
    m.build_responses()
    
    # TODO: Save results/reports in a file?


# Extract the asn values from the global probe_dict variable 
# and store them in the global list as_ids
def extract_asn_values():
    print("Reading the asn values")  

    global as_ids

    # Get the the probe count
    values = list(probe_dict.values())[0]
    probe_count = len(values)
    
    # Exit program if no probes found
    if probe_count <= 0:
        print(f"No probes found: {probe_count}")
        sys.exit()
        
    print(f"Probe count: {probe_count}")

    # Extract the asn values from the given probes
    for index in range(probe_count):
        as_ids.append(values[index]['value'])
        print(f"Values: {values[index]['value']}")        
        

print(" == Experiment starting ==")

# Extracts the asn values in as_ids list
extract_asn_values()

# For each asn ID in as_ids, send a query from that probe and build the query with a counter value.
# Counter value must be equal or greater than probe count.
# Make sure the domain name is valid (A records are in authoritative server) for the given counter values.
counter = 0
for id in as_ids:
    # Example query: *.ripe-atlas-<counter>.packetloss.syssec-research.mmci.uni-saarland.de                                   
    send_query_from_probe(id, counter)
    counter += 1

print(" == Experiment ended ==")     



# Multithreading code?

# All the counter values
# counters = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,]
# for id in as_ids:
#     # Multithreading to reduce runtime?
#     with concurrent.futures.ProcessPoolExecutor() as executor:
#             # Using list comprehention to build the results list
#             # submit() schedules the callable to be executed and returns a 
#             # future object representing the execution of the callable.
#             # TODO: How to pass multiple arguments to the function using submit?
#             results = [executor.submit(send_query_from_asn, [id, counter]) for counter in counters]
#       
#     # Show the finished processes' outputs
#     for f in concurrent.futures.as_completed(results):
#         print(f.result())     
    