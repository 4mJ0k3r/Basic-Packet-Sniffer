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
