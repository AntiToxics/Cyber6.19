""""
Server.py
Author : Gilad Elran
Date : 1/3/2026
Description : This script performs a TCP SYN scan to identify open ports on a remote host.
            It targets a specific IP and a specific Port range and looks for SYN+ACK responses
"""


from scapy.all import *
from scapy.layers.inet import TCP, IP
import logging

FLAG_SYN = "S"
FLAG_SYN_ACK = "SA"
SPORT = 8694
AVAILABLE_PORTS = []
TIMEOUT = 0.5

def handle_ping(dst_ip):
    """
    :args: dst_ip -> string
    - Sends a SYN packet to each port from 20 to 1024
    - Checks if a response with SYN+ACK flags is received
    - If yes, it adds the port to the AVAILABLE_PORTS list
    - prints all the available ports
    :return:
    """
    try:
        logging.info("Starting to scan")
        for dport in range(24, 1025):
            try:
                pkt = IP(dst=dst_ip) / TCP(dport=dport, sport=SPORT, flags=FLAG_SYN)
                response = sr1(pkt, timeout= TIMEOUT, verbose=0)
                print(f"Scanning port: {dport}")
                if response and response.haslayer(TCP):
                    if response[TCP].flags == FLAG_SYN_ACK:
                        AVAILABLE_PORTS.append(dport)
            except Exception as e:
                logging.error(f"Error scanning port {dport}: {e}")
                print("Error while scanning")
                
        logging.info("Scanning complete")
        print("-------All of the available ports-------")
        if AVAILABLE_PORTS:
            for port in AVAILABLE_PORTS:
                print(f"Port {port} is open")
        else:
            print("No available ports")
    except Exception as e:
        logging.critical(f"Critical error during scan: {e}")



def main():
    """
     Main function that gets the wanted IP from the user and calls
     the function handle_ping()
    """

    dst_ip = input("Enter the destination IP: ")
    logging.info(f"About to scan IP: {dst_ip}")
    handle_ping(dst_ip)
    logging.info("Program ended")


if __name__ == "__main__":
    # Logging setup
    logging.basicConfig(
        filename='Server.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    main()
