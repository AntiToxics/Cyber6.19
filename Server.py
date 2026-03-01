""""
Server.py
Author : Gilad Elran
Date : 1/3/2026
Description : This script performs a TCP SYN scan to identify open ports on a remote host.
            It targets a specific IP and a specific Port range and looks for SYN+ACK responses
"""



from scapy.all import *
from scapy.layers.inet import TCP, IP

FLAG_SYN = "S"
FLAG_SYN_ACK = "SA"
SPORT = 8694
AVAILABLE_PORTS = []


def handle_ping(dst_ip):
    """
    :args: dst_ip -> string
    - Sends a SYN packet to each port from 20 to 1024
    - Checks if a response with SYN+ACK flags is received
    - If yes, it adds the port to the AVAILABLE_PORTS list
    - prints all the available ports
    :return:
    """

    for dport in range(24, 1025):
        pkt = IP(dst=dst_ip) / TCP(dport=dport, sport=SPORT, flags=FLAG_SYN)
        response = sr1(pkt, timeout=0.5, verbose=0)
        print(f"Scanning port: {dport}")
        if response and response.haslayer(TCP):
            if response[TCP].flags == FLAG_SYN_ACK:
                AVAILABLE_PORTS.append(dport)

    print("-------All of the available ports-------")
    if AVAILABLE_PORTS:
        for port in AVAILABLE_PORTS:
            print(f"Port {port} is open")
    else:
        print("No available ports")


def main():
    """
     Main function that gets the wanted IP from the user and calls
     the function handle_ping()
    """
    dst_ip = input("Enter the destination IP: ")
    handle_ping(dst_ip)


if __name__ == "__main__":
    main()
