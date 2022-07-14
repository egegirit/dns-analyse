import json

# Specify the packet loss rate of the current experiment here
# With X% packet loss
packetLossRate = "W0PL"
# Create a log file in append mode
log_file_name = "dnsPackets" + packetlossRate + ".json"
f = open(log_file_name, "a")

# Opening JSON file
file = open('data.json')

data = json.load(file)
# print(len(data))  # Number of packets captured and saved in the file
# print(data[0])  # Contents of the first packet in JSON format
# print(data[1]['_source']['layers']['dns']['dns.time'])  # 0.044423000

packetCount = len(data)
print(f"Number of packets: {packetCount}")

# Extract all the DNS related parts of the JSON file to make the analysing easier
for i in range(0, packetCount):
    # print(data[i]['_source']['layers']['dns'])
    # To get the dns_time, the packet must have an "Answers" section
    if 'dns' in data[i]['_source']['layers']:
        dns_content = data[i]['_source']['layers']['dns']
        print(dns_content)
        f.write(str(dns_content) + "\n")

# This code only extracts the DNS times of the DNS answers.
# for i in range(0, packetCount):
#    # print(data[i]['_source']['layers']['dns'])
#    # To get the dns_time, the packet must have an "Answers" section
#    if 'Answers' in data[i]['_source']['layers']['dns']:
#        # print("Found")
#        dns_id = data[i]['_source']['layers']['dns']['dns.id']
#        dns_time = data[i]['_source']['layers']['dns']['dns.time']
#        # Print output and write to file
#        print(f"(DNS ID: {dns_id}, DNS Time: {dns_time})\n")
#        f.write(f"(DNS ID: {dns_id}, DNS Time: {dns_time})")

# Closing file
file.close()
