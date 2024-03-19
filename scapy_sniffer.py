# Importing necessary libraries
from scapy.all import *
from scapy.layers.inet import IP
from scapy.layers.http import HTTPRequest
from colorama import init, Fore

# Initializing colorama for colored output
init()

# Defining color codes for output
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW
reset = Fore.RESET


# Function to sniff packets on the network interface
def sniff_packets(iface):
    # Checking if a network interface is specified
    if iface:
        # Sniffing packets with a filter for destination port 80 (HTTP), printing processed packets
        sniff(filter='dst port 80', prn=process_packets, iface=iface, store=False)
    else:
        # Sniffing all packets and printing processed packets
        sniff(prn=process_packets, store=False)


# Function to process each sniffed packet
def process_packets(packet):
    # Checking if the packet has a TCP layer
    if packet.haslayer(TCP):
        # Extracting source and destination IP addresses and port numbers
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        # Printing TCP connection information
        print(f"{blue}[+] {src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port}{reset}")

    # Checking if the packet has an HTTPRequest layer
    if packet.haslayer(HTTPRequest):
        # Extracting URL and HTTP method from the packet
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()

        # Printing HTTP request information
        print(f"{green}[+] {src_ip} is making an HTTP request to {url} with method {method}{reset}")
        print(f"[+] HTTP Data")
        print(f"{yellow} {packet[HTTPRequest].show()}")

        # Checking if the packet has a RAW layer
        if packet.haslayer[RAW]:
            # Printing useful raw data
            print(f"{red}[+] Useful raw data: {packet.getlayer(Raw).load.decode()}{reset}")


# Calling the sniff_packets function with the network interface 'eth0'
sniff_packets('eth0')
