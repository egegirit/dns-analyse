import time
from datetime import datetime
import dns.resolver
import dns.reversename

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

dns_request_qname = "nameserver1.intranet.lol"  

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

    global answers

    # Send query for execute_count times, starting from 0, execute_count excluded
    for i in range(0, execute_count):
        # Print the current test number
        print(f"**** {i+1}. Query ****")

        # Note: the latency will be recorded and analysed outside this program
        start_time = time.time()

        try:
            answers = dns.resolver.query(dns_request_qname, 'A', raise_on_no_answer=False)
        except:
            print("DNS Exception occured!")   
            answers = None         
        
        measured_time = time.time() - start_time
        print(f"  DNS Response received")
        print(f"  DNS Response time: {measured_time}")
        
        if answers is not None:
            for answer in answers:
                print(answer)
            print("RRset:")
            if answers.rrset is not None:
                print(answers.rrset)            

        # # Write output to file
        f.write("\n" + f"{i+1}. Query Response time: {measured_time}\n")
        
        # Sleep for a while
        print(f"  Waiting for {sleep_time} seconds...\n")
        time.sleep(sleep_time)

    f.close()


send_queries(sleep_time, log_file_name, execute_count)
