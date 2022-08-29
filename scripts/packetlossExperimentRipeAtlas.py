from ripe.atlas.cousteau import Dns, AtlasSource, AtlasCreateRequest, AtlasResultsRequest
from ripe.atlas.sagan import DnsResult
from pprint import pprint
from datetime import datetime

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

ATLAS_API_KEY=""  # 0c51be25-dfac-4e86-9d0d-5fef89ea4670

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
    query_argument = "ns1.packetloss.syssec-research.mmci.uni-saarland.de",  
    use_macros = True,
    
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

# Define from where the probes should be selected, how many probes you want
source = AtlasSource(
    type="area",
    # Valid options are
    # "WW": World Wide
    # "West"
    # "North-Central"
    # "South-Central"
    # "North-East"
    # "South-East"
    value="WW",
    requested=5,
    # Maybe also use "system-ipv4-stable-30d"
    # For IPv6 use
    # "system-resolves-aaaa-correctly","system-ipv6-works","system-ipv6-stable-1d","system-ipv6-stable-30d"
    tags_include=["system-resolves-a-correctly","system-ipv4-works","system-ipv4-stable-1d"]
)

# Delete?
source1 = AtlasSource(
    type="country",
    value="NL",
    requested=5,
    tags_include=["system-resolves-a-correctly","system-ipv4-works","system-ipv4-stable-1d"]
)

# Create the request from the given sources
atlas_request = AtlasCreateRequest(
    start_time=datetime.utcnow(),
    key=ATLAS_API_KEY,
    measurements=[dns],
    sources=[source, source1],
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

# %%