#!/usr/bin/env python

# uses the scapy library(module) to create, send, sniff, dissect and manipulate network packets.
import scapy.all as scapy
# argparse is a Command-line parsing library
import argparse

# We are defining get-arguments
def get_arguments():
    #
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[.] Please specify a target ip / ip range, use --help for more information. (--target 10.102.1/24 or --target 192.168.0.1/24 )")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) [0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------------")
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


# get arguments from command line
options = get_arguments()
# use arguments from command line
scan_result = scan(options.target)
print_result(scan_result)
