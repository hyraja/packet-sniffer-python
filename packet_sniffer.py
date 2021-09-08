#!/usr/bin/python3
import subprocess  # Create another processs
from datetime import datetime
from scapy.all import *
import sys
print("Use Sudo")
# Packet sniffer script using scapy

net_iface = input("Enter interface name: ")

# promisceous mode transfer the interface data packets to cpu to processs and you capture from there
# creating another process to run command
subprocess.call(["ifconfig", net_iface, "promisc"])

num_of_pkt = int(input("Enter the packet count you want to capture : "))

time_sec = int(input("Enter the time how long(in sec) run to capture : "))

proto = input("Enter the protocol( arp | icmp | all ) : ")

# sniff function call it and pass every packet in byte format


def logs(packet):

    print('-'*20)
    # packet.show()
    source_mac = f'SRC_MAC: {str(packet[0].src)}'
    destination_mac = f'DEST_MAC : {str(packet[0].dst)}'
    # type_of_ip = f'IP Type : IPv{str(packet[0].version)}'
    print(source_mac, destination_mac)
    print('-'*20)


if proto == "all":
    sniff(iface=net_iface, count=num_of_pkt,
          timeout=time_sec, prn=logs)  # sniffing packet
elif proto == "arp":
    sniff(iface=net_iface, count=num_of_pkt,
          timeout=time_sec, prn=logs)  # sniffing packet
elif proto == "icmp":
    sniff(iface=net_iface, count=num_of_pkt,
          timeout=time_sec, prn=logs)  # sniffing packet
else:
    print("Wrong protocol")
