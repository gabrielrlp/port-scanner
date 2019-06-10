import socket, sys
from struct import *
from _thread import *
import threading

# IPv6 type from ethernet header
PROTOCOL_TYPE_IPV6 = 0x86dd

## This is for the TCP flags statements
# 000010
FLAGS_SYN = 2
# 010010 
FLAGS_SYN_ACK = 18
# 000001
FLAGS_FIN = 1
# 000100
FLAGS_RST = 4
# 010000
FLAGS_ACK = 16

def threaded(listen, address):
    """
    Thread that waits for either TCP Connect Attack or TCP Half-opening Attack
    """
    print("Started thread...")
    while True:
        # We should put this packet receiving code inside a single function for reusability
        # Receive packet
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]

        # Get ethernet header
        eth_header = packet[0:14]

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):
            print("Received IPv6 packet inside thread.")

            # Get TCP header
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])

            # Get TCP flags
            flags = int(tcp_header[5])

            # TODO: GET ATTACKER ADDRESS 

            # Should check address as well
            if(flags == FLAGS_ACK):
                print("!! RECEIVED A TCP CONNECT ATTACK FROM ADDRESS X !!")
                break
            elif(flags == FLAGS_RST):
                print("!! RECEIVED A TCP HALF OPENING ATTACK FROM ADDRESS X !!")
                break

    print("Exiting thread...")

def get_attacker_mac_address(eth_header):
    """
    Helper function to get a src mac address
    """

    # Unpack
    unpacked_eth_header = unpack('!6B6BH', eth_header)

    # Get attacker MAC address
    raw_attacker_mac_address = unpacked_eth_header[6:12]

    # Stringfy mac address
    attacker_mac_address = ""
    for m in raw_attacker_mac_address:
        attacker_mac_address = attacker_mac_address + format(m, '02x') + ":"

    # Remove last ':'
    attacker_mac_address = attacker_mac_address[:-1]

    return attacker_mac_address

def listener():
    """
    This listener represents the main attack detection component.
    """
    # Creates raw socket
    listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    print("Starting Listener...")
    while True:
        # We should put this packet receiving code inside a single function for reusability
        # Receive packet
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]

        # Get ethernet header
        eth_header = packet[0:14]

        # Get attacker MAC address
        attacker_mac_address = get_attacker_mac_address(eth_header)

        #print("MAC: ", attacker_mac_address)

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):

            # Get TCP header
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])

            # Get TCP flags
            flags = int(tcp_header[5])

            # TODO: GET ATTACKER ADDRESS
            source_address = packet[22:38]
            print("attacker", source_address)

            mocked_address = "testing123"

            # TCP Connect Attack and Half-opening handling
            if (flags == FLAGS_SYN):
                # Starts new thread that waits for ACK or RST 
                start_new_thread(threaded, (listen, mocked_address,))

            # Stealth scan / TCP FIN handling
            elif (flags == FLAGS_FIN):
                print("!! RECEIVED STEALTH SCAN/TCP FIN FROM ADDRESS X !!")

            # SYN/ACK attack handling
            elif (flags == FLAGS_SYN_ACK):
                print("!! RECEIVED SYN/ACK ATTACK FROM ADDRESS X !!")
        
if __name__ == "__main__":
    listener()