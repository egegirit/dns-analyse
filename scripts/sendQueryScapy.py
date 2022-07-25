import time
from datetime import datetime
from scapy.all import *
from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP

###############################################################
### Run packet capture program before executing this script ###
###############################################################

# Time to wait between the queries
sleep_time = 1

# Packetloss rate (real packetloss rate is configured manually on the server, this is only the file name)
packetloss_rate = "00"
# The file name to save the outputs
log_file_name = "packetlossTest" + packetloss_rate + ".txt"

# Determines how many times the program sends the query
execute_count = 100

# Set the parameters of the dns request
dns_request_dest_ip = "192.168.1.33"  # IP Address of dns resolver
dns_request_src_port = RandShort()
dns_request_dest_port = 53
dns_request_rd = 1  # Recursion desired
dns_request_qr = 0  # message is a query (0), or a response (1)
dns_request_qname = "nameserver1.intranet.lol"  
dns_trans_id = 0  # Increments after every send


def send_queries(sleep_time, log_file_name, execute_count):
    if log_file_name == "":
        print("Invalid log file name")
        return
    if sleep_time < 0:
        print("Invalid sleep time")
        return
    if execute_count < 0:
        print("Invalid execution count")
        return

    # Create the log file in append mode
    f = open(log_file_name, "a")

    # datetime object containing current date and time
    now = datetime.now()
    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
    # Write the current date and time to the file
    f.write(f"\nDate and time: {dt_string} \n")
    f.write(f"Query Tests for: {dns_request_qname} \n")
    f.write(f"Test parameters: (sleep time = {sleep_time}, execution count = {execute_count}) \n")

    # Send query for execute_count times, starting from 0, execute_count excluded
    for i in range(0, execute_count):
        # Print the current test number
        print(f"**** {i+1}. Query ****")

        # Increment DNS transaction ID (starts from 1, first query has the ID 1)
        global dns_trans_id
        dns_trans_id = dns_trans_id + 1
        print(f"  New DNS transaction ID: {dns_trans_id}")

        # Create the dns request
        dns_request = IP(dst=dns_request_dest_ip) / UDP(sport=dns_request_src_port, dport=dns_request_dest_port) / \
                      DNS(id=dns_trans_id, rd=dns_request_rd, qr=dns_request_qr, qd=DNSQR(qname=dns_request_qname))
        print(f"  DNS Request created")

        # Measure the (approximate) time between sending and receiving
        # Note: the latency will be recorded and analysed outside this program
        start_time = time.time()

        # Send DNS Query and receive response 
        dns_response = sr1(dns_request)
        measured_time = time.time() - start_time
        print(f"  DNS Response received")
        print(f"  DNS Response time: {measured_time}")

        print("---------- Summary ----------")
        print(dns_response.summary())
        # print("---------- Name ----------")
        # print('name:', dns_response.payload.payload.name)
        print('name:', dns_response[DNS].name)
        # print(repr(dns_response.payload.payload))
        print(repr(dns_response[DNS]))
        # print("---------- Layers ----------")
        # print('layers:', dns_response.payload.payload.ancount)
        print('layers:', dns_response[DNS].ancount)
        # print("---------- IP Addresses ----------")
        for x in range(dns_response[DNS].ancount):
            print(dns_response[DNSRR][x].rdata)

        print("---------- End Test ----------")

        # Write output to file
        f.write("\n" + f"{i+1}. Query Response time: {measured_time}\n")
        # f.write(dns_response.payload.payload + "\n")  # Convert to string

        # Sleep for a while
        print(f"  Waiting for {sleep_time} seconds...\n")
        time.sleep(sleep_time)

    f.close()


send_queries(sleep_time, log_file_name, execute_count)
