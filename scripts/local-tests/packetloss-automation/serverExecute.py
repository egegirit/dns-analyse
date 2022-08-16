#!/bin/bash
# Execute this script as root with sudo

import subprocess
import socket
import sys

try:
    # Socket for accepting communications, not for communicating.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# AF_INET refers to the address-family ipv4. 
    # The SOCK_STREAM means connection-oriented TCP protocol. 
    print("Socket successfully created")
except socket.error as err:
    print("Socket creation failed with error %s" %(err))

# reserve a port on your computer (can be anything)
port = 12345   

host_ip = "192.168.1.9" # "192.168.1.9"

s.bind(("", port))
s.listen(5)
# Multiple connections are handled with multithreading (not implemented here)
while True:
    # Create new socket for communicating
    comm_socket, address = s.accept()
    print(f"Connected to: {address}")
    
    # Receive command
    message = comm_socket.recv(4096).decode('utf-8')  # byte stream
    print(f"  Command received: {message}")
    
    # Execute received command
    print(f"  Executing: {message}")
    process = subprocess.Popen(message, shell=True, stdout=subprocess.PIPE)
    # Wait for script to end
    process.wait()
    print(f"  Execution finished")
    
    # Send that execution finished
    # comm_socket.send(f"  Executed command: {message}".encode('utf-8'))
        
    # Receive command (2)
    message = comm_socket.recv(4096).decode('utf-8')  # byte stream
    print(f"  Command received (2): {message}")
    # Execute received command
    print(f"  Executing (2): {message}")
    process = subprocess.Popen(message, shell=True, stdout=subprocess.PIPE)
    # Wait for script to end
    process.wait()
    print(f"  Execution finished (2)")    
    
    # Testing
    # Receive command (3)
    message = comm_socket.recv(4096).decode('utf-8')  # byte stream
    print(f"  Command received (3): {message}")
    # Execute received command
    print(f"  Executing (3): {message}")
    process = subprocess.Popen(message, shell=True, stdout=subprocess.PIPE)
    # Wait for script to end
    process.wait()
    print(f"  Execution finished (3)") 
    
    comm_socket.close()
    print(f"  Socket closed")
    
# Resolver: 192.168.1.33
# Auth:     192.168.1.32
# TLD:      192.168.1.31
# Root:     192.168.1.30
# Client:   192.168.1.9
