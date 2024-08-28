#!/usr/bin/env python3

import subprocess
import sys

# Check if correct number of arguments are provided
if len(sys.argv) != 4:
    print("Usage: python scan_script.py <interface> <IP> <outputFileName>")
    sys.exit(1)

# Extract interface and IP address from command-line arguments
interface = sys.argv[1]
ip_address = sys.argv[2]
name = sys.argv[3]

# Run masscan
masscan_output = subprocess.run(['masscan', '-p', '1-65535', '--interface', interface, '--rate', '1000', ip_address], capture_output=True, text=True).stdout

# Check if masscan found open ports
if "Discovered open port" in masscan_output:
    # Extract port numbers
    port_numbers = [line.split()[3].split("/")[0] for line in masscan_output.split('\n') if "Discovered open port" in line]
    
    # Combine port numbers with commas
    port_numbers_str = ','.join(port_numbers)
    
    # Print port numbers
    print("Open ports found:", port_numbers_str)
    
    # Create nmap command
    nmap_command = f"nmap -sV -sC -Pn -p {port_numbers_str} -oA {name} {ip_address}"
    
    # Run nmap command
    print("Running command:", nmap_command)
    subprocess.run(nmap_command, shell=True)
else:
    print("No open ports found.")

print("Usage: don't forget to run it as root/admin")