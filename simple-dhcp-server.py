#!/usr/bin/env python3
import socket
from scapy.all import *
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import UDP, IP
from scapy.layers.l2 import Ether
import argparse


def dhcp_server(interface, server_ip, client_ip):

    server_port = 67

    # Create a UDP socket for DHCP communication
    dhcp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    dhcp_socket.bind(('', server_port))
    print(f"DHCP server listening on port {server_port}")

    # Loop to handle incoming DHCP requests
    while True:
        print("Waiting to receive DISCOVER packet...")
        # Receive a DHCP request from a client
        dhcp_request, client_address = dhcp_socket.recvfrom(1024)
        print(f"Received packet on DHCP port from {client_address[0]}:{client_address[1]}")

        # Parse the DHCP request packet
        dhcp_packet =  BOOTP(dhcp_request)
        dhcp_options = dhcp_packet['DHCP options'].options
        if not dhcp_options:
            print(f"Invalid DHCP packet from {client_address[0]}:{client_address[1]}")
            continue
        dhcp_message_type = [opt[1] for opt in dhcp_options if opt[0] == 'message-type'][0]
        client_mac_address = dhcp_packet.chaddr.rstrip(b'\x00')
        transaction_id = dhcp_packet.xid

        # Assign an IP address to the client
        if dhcp_message_type == 1:  # DHCP Discover
            print("DHCP DISCOVER received")
            # Create a DHCP offer packet
            dhcp_offer = Ether(src=get_if_hwaddr(interface), dst=client_mac_address) / IP(src=server_ip,
                                                                                       dst=client_ip) / UDP(
                sport=67, dport=68) / BOOTP(op=2, xid=transaction_id, yiaddr=client_ip, siaddr=server_ip,
                                            chaddr=client_mac_address) / DHCP(
                options=[('message-type', 'offer'), ('subnet_mask', '255.255.255.0'), ('renewal_time', 60),
                         ('lease_time', 3600), ('server_id', '10.10.10.10'), 'end'])

            # Send the DHCP offer packet to the client
            sendp(dhcp_offer, iface=interface, verbose=0)
            print(f"DHCP OFFER sent to {client_address[0]}:{client_address[1]}")

        elif dhcp_message_type == 3:  # DHCP Request
            print("DHCP REQUEST received")
            # Create a DHCP acknowledgement packet
            dhcp_ack = Ether(src=get_if_hwaddr(interface), dst=client_mac_address) / IP(src=server_ip,
                                                                                     dst=client_ip) / UDP(
                sport=67, dport=68) / BOOTP(op=2, xid=transaction_id, yiaddr=client_ip, siaddr=server_ip,
                                            chaddr=client_mac_address) / DHCP(
                options=[('message-type', 'ack'), ('renewal_time', 60),
                         ('lease_time', 3600), ('server_id', '10.10.10.10'), ('subnet_mask', '255.255.255.0'), 'end'])

            # Send the DHCP acknowledgement packet to the client
            sendp(dhcp_ack, iface=interface, verbose=0)
            print(f"Sent DHCP acknowledgement to {client_address[0]}:{client_address[1]}")



def parse_args():
    parser = argparse.ArgumentParser(
                    prog='simple-dhcp-server',
                    description='A script that does the DORA dance with a device to assign it an IP',
                    epilog='This is NOT a fully working DHCP server')

    parser.add_argument('interface', help="The name of the network interface i.e. 'eth0'", action='store')
    parser.add_argument('server_ip', help="The IP address of your network interface", action='store')
    parser.add_argument('client_ip', help="The IP address to give to the requesting device", action='store')

    args = parser.parse_args()

    return args


if __name__ == "__main__":
    #interface = 'enx00e04c0a04da'
    #server_ip = '10.10.10.10'
    #client_ip = '10.10.10.150'
    args = parse_args()
    interface = args.interface
    server_ip = args.server_ip
    client_ip = args.client_ip

    dhcp_server(interface, server_ip, client_ip)
