# Packet Sniffer

## Description
This Python script is a simple packet sniffer that captures network traffic on a specified interface, filters HTTP packets, and prints relevant information such as TCP connection details and HTTP request data. It utilizes the Scapy library for packet manipulation and analysis.

## Features
- Sniffs packets on a specified network interface.
- Filters HTTP packets.
- Prints TCP connection information.
- Prints HTTP request details including URL, method, and raw data.

## Dependencies
- Python 3.x
- Scapy
- Colorama

## Installation
1. Clone or download the repository to your local machine.
2. Install dependencies:
   ```bash
   pip install scapy colorama
Usage
Run the script packet_sniffer.py with Python, specifying the network interface to sniff packets on:

python packet_sniffer.py <interface>
Replace <interface> with the name of the network interface (e.g., eth0).

If no interface is specified, the script will sniff packets on all available interfaces.

Output
The script prints information about TCP connections and HTTP requests to the console, including source and destination IP addresses, port numbers, URL, HTTP method, and raw data.
