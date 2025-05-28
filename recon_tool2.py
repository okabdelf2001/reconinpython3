#!/usr/bin/env python  # Specifies the environment to use for running the Python script.

# uses the scapy library(module) to create, send, sniff, dissect and manipulate network packets.
import scapy.all as scapy  # Imports all modules and functions from Scapy for advanced packet crafting.

# argparse is a Command-line parsing library
import argparse  # Imports argparse for parsing command-line arguments.

# We are defining get-arguments
def get_arguments():  # Function to parse and return command-line arguments.
    parser = argparse.ArgumentParser()  # Creates a new ArgumentParser object.
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range.")  # Adds a command-line argument for the target IP or IP range.
    options = parser.parse_args()  # Parses the command-line arguments.
    if not options.target:  # Checks if the target option was provided.
        parser.error("[.] Please specify a target ip / ip range, use --help for more information. (--target 10.102.1/24 or --target 192.168.0.1/24 )")  # Displays an error if the target IP was not given.
    return options  # Returns the parsed arguments object if correct arguments are provided.

def scan(ip):  # Function to perform an ARP scan on the specified IP or subnet.
    arp_request = scapy.ARP(pdst=ip)  # Creates an ARP request packet for the given IP/subnet.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Creates an Ethernet frame with the destination MAC address set to broadcast.
    arp_request_broadcast = broadcast/arp_request  # Combines the Ethernet frame with the ARP request packet.
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # Sends the packet and receives responses; [0] gets the list of answered packets.
    clients_list = []  # Initializes an empty list to store discovered clients.
    for element in answered_list:  # Iterates over each response in the answered list.
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}  # Extracts IP and MAC address from the ARP reply and stores them in a dictionary.
        clients_list.append(client_dict)  # Adds the client information to the list.
    return clients_list  # Returns the list of discovered clients.

def print_result(results_list):  # Function to print the scan results in a clean table format.
    print("IP\t\t\tMAC Address\n--------------------------------------------------")  # Prints the table headers.
    for client in results_list:  # Iterates through each client in the result list.
        print(client["ip"] + "\t\t" + client["mac"])  # Prints the IP and MAC address of each discovered client.

# get arguments from command line
options = get_arguments()  # Calls the function to parse and store command-line arguments.

# use arguments from command line
scan_result = scan(options.target)  # Calls the scan function with the provided target and stores the results.

print_result(scan_result)  # Calls the print function to display the scan results.

# Written by Omar Abdelfattah
