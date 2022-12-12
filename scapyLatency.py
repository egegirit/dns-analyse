from scapy.all import *

# Name of the pcap file to read


# Initialize dictionaries to store DNS queries and responses
queries = {}
responses = {}

latencies_by_pl_and_rcode = {}
query_duplicate_by_pl = {}
rcodes_by_pl = {}

packetloss_rates = [0, 10, 90, 95]

for current_pl_rate in packetloss_rates:

    pcap_file_name = "tcpdump_log_client_bond0_" + str(current_pl_rate) + ".pcap"

    # Iterate over the packets and extract DNS queries and responses
    index = 1
    for packet in PcapReader(pcap_file_name):
        # print(f"Packet {index}")
        if packet.haslayer(DNS):
            query_name = packet[DNSQR].qname.decode("utf-8")
            rcode = packet.getlayer(DNS).rcode
            packet_time = packet.time
            is_response_packet = packet.getlayer(DNS).qr
            dns_id = packet[DNS].id
            dst_port = packet[IP].dst
            src_port = packet[IP].src

            # DNS query
            if is_response_packet == 0:
                # Only add it to the queries dictionary if it's not a duplicate
                if (dns_id, query_name, is_response_packet) not in queries:
                    queries[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                # Count query duplicate by packetloss rate
                else:
                    # print(f"Query duplicate: {query_name}, {dns_id}")
                    if current_pl_rate not in query_duplicate_by_pl:
                        query_duplicate_by_pl[current_pl_rate] = 0
                    else:
                        query_duplicate_by_pl[current_pl_rate] += 1
            # DNS response
            elif is_response_packet == 1:
                # Check if we found a corresponding response packet to a query
                if (dns_id, query_name, 0) in queries:
                    latency = float(packet_time - queries[dns_id, query_name, 0][0])
                    # Delete the query from dictionary because we calculated its latency
                    del queries[dns_id, query_name, 0]

                    # Store the latency directly using the rcode and current packetloss rate
                    # Create the latency keys if not created before
                    if (current_pl_rate, rcode) not in latencies_by_pl_and_rcode:
                        latencies_by_pl_and_rcode[current_pl_rate, rcode] = []
                    else:
                        latencies_by_pl_and_rcode[current_pl_rate, rcode].append(latency)

                    # Count the RCODEs of the packets of the pl rate
                    if (current_pl_rate, rcode) not in rcodes_by_pl:
                        rcodes_by_pl[current_pl_rate, rcode] = 0
                    else:
                        rcodes_by_pl[current_pl_rate, rcode] += 1

                # The response packet has no corresponding query packet for now (and probably will not have any?)
                # Add the response to the list
                elif (dns_id, query_name, is_response_packet) not in responses:
                    responses[dns_id, query_name, is_response_packet] = [packet_time, rcode]
                # The response packet has no corresponding query to it and this packet is a duplicate
                else:
                    print(f"Duplicate response packet detected for {query_name}, {dns_id}")

        index += 1
    queries = {}
    responses = {}

print(f"Unanswered query count/query packet count that doesn't have response: {len(queries)}")
print(f"Responses that doesn't have corresponding queries: {len(responses)}\n")
print(f"rcodes_by_pl: {rcodes_by_pl}")
print(f"query_duplicate_by_pl: {query_duplicate_by_pl}")
# print(f"latencies_by_pl_and_rcode: {latencies_by_pl_and_rcode}")

print(f"query_duplicate_by_pl: {list(latencies_by_pl_and_rcode.keys())}\n")

# keys_of_latency = list(latencies_by_pl_and_rcode.keys())
# rcode_0_keys = []
# rcode_2_keys = []
# rcode_5_keys = []
# for key in keys_of_latency:
#     # Get only latencies of RCODE = 0
#     if key[1] == 0:
#         rcode_0_keys.append(key)
#     # ServFail
#     elif key[1] == 2:
#         rcode_2_keys.append(key)
#     # Refused
#     elif key[1] == 5:
#         rcode_5_keys.append(key)
#

#
# for key in rcode_0_keys:
#     print(f"latencies_by_pl_and_rcode[{key}]: {latencies_by_pl_and_rcode[key]}")
#
# print(f"\n")
# print(f"latencies_by_pl_and_rcode[0, 0]: {latencies_by_pl_and_rcode[0, 0]}")

keys_of_latency = list(latencies_by_pl_and_rcode.keys())
rcode_0_keys = []
rcode_2_keys = []
rcode_5_keys = []
for key in keys_of_latency:
    # Get only latencies of RCODE = 0
    if key[1] == 0:
        rcode_0_keys.append(key)
    # ServFail
    elif key[1] == 2:
        rcode_2_keys.append(key)

print(f"rcode_0_keys: {rcode_0_keys}")
print(f"rcode_2_keys: {rcode_2_keys}\n")

ok_latencies = {}
servfail_latencies = {}
index = 0
for key in rcode_0_keys:
    # print(f"latencies_by_pl_and_rcode[{key}]: {latencies_by_pl_and_rcode[key]}")
    ok_latencies[key[0]] = latencies_by_pl_and_rcode[key]
    index += 1

index = 0
for key in rcode_2_keys:
    # print(f"latencies_by_pl_and_rcode[{key}]: {latencies_by_pl_and_rcode[key]}")
    servfail_latencies[key[0]] = latencies_by_pl_and_rcode[key]

print(f"OK:\n")
print(f"{ok_latencies}")
print(f"Fail:\n")
print(f"{servfail_latencies}")
