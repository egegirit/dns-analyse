#!/bin/bash
# Execute this script as root with sudo!

import subprocess
import socket
import sys
import time
import sendQueriesWithPacketloss as dns_script

port = 12345             # reserve a port on your computer (can be anything)
host_ip = "192.168.1.32" # IP of authoritative name server 

packetloss_rates = [0, 10, 20, 30, 40, 50, 60, 70, 80, 85, 90, 95]  # Packetloss rates to test
interface_name = "ens33:1"  # Name of the network interface on the authoritative name server 
  
for current_packetloss_rate in packetloss_rates:  

  # Create TCP connection
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket successfully created")
  except socket.error as err:
    print(f"Socket creation failed with error {err}")

  # Pick the next packetloss rate
  print(f"Current Packetloss Rate: {current_packetloss_rate}")

  # Set current packetloss on authoritative server 
  # by executing a shell script on the server.  
  # Command for x percent Packetloss: sudo tc qdisc add dev enp0s3 root netem loss x%
  packetloss_command = "sudo tc qdisc add dev " + interface_name + " root netem loss " + str(current_packetloss_rate) + "%"

  # Connect to the server
  s.connect((host_ip, port))    
  print(f"  Connected")  
  # Send the packetloss command
  s.send(packetloss_command.encode('utf-8'))
  print(f"  {current_packetloss_rate}% Packetloss rate simulated.")  
  
  # Can be deleted
  log_file_name = "packetlossTest" + str(current_packetloss_rate) + ".txt"
  
  print("** Sending DNS queries **")
  dns_script.send_queries(1, log_file_name, 100)  
  print(f"** DNS query sending finished **")
  
  # Disable packetloss rules on auth server by sending signal to auth server 
  # to disable:
  disable_packetloss_1 = "sudo tc qdisc del dev " + interface_name + " root"
  print(f"  Sending disable packetloss command (1): {disable_packetloss_1}")
  s.send(disable_packetloss_1.encode('utf-8'))
  print(f"  Sent disable packetloss (1)")
  
  time.sleep(1)
  
  # Testing
  # Send Command (3)
  disable_packetloss_2 = "sudo tc -s qdisc ls dev " + interface_name
  print(f"  Sending disable packetloss command (2): {disable_packetloss_2}")
  s.send(disable_packetloss_2.encode('utf-8'))
  print(f"  Sent disable packetloss (2)")
  
  s.close()
  print(f"  Socket closed")
    

# Resolver: 192.168.1.33
# Auth:     192.168.1.32
# TLD:      192.168.1.31
# Root:     192.168.1.30
# Client:   192.168.1.9
