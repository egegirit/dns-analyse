import pyshark

# read the PCAP file
capture = pyshark.FileCapture('tcpdump_log_client_bond0_50.pcap')

# initialize a set to store the unique query names
query_names = set()

# initialize dictionaries to store query and response packets
query_packets = {}
response_packets = {}

# the response code to filter for
response_code = 'NOERROR'

# iterate through each packet in the capture
for packet in capture:
    # check if the packet is a DNS packet
    if packet.dns:  # and packet.transport_layer == 'UDP'
        # check if the packet is a query or response
        if packet.dns.flags_response == '0':
            # store the query packet and its timestamp
            query_packets[packet.dns.id] = [packet.sniff_timestamp, packet.rcode]
            # add the query name to the set of unique names
            query_names.add(packet.dns.qry_name)
        else:
            # check if the packet has the specified response code
            if packet.dns.rcode == response_code:
                # store the response packet and its timestamp
                response_packets[packet.dns.id] = packet.sniff_timestamp

# iterate through the query and response packets and calculate the latency
for id, query_time in query_packets.items():
    response_time = response_packets[id][0]
    latency = response_time - query_time
    print(f'DNS packet with ID {id} had a latency of {latency}')
    print(f" RCODE of packet: {response_packets[id][0]}")

# print the unique query names
# print(query_names)
