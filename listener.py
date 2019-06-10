import socket, sys
from struct import *
from _thread import *
import threading
from datetime import timedelta

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

def threaded(listen, src_address, target_port):
    """
    Thread that waits for either TCP Connect Attack or TCP Half-opening Attack
    """
    print("Started thread...")

    # Timeout 10 sec? 60 sec?
    wait_until = datetime.now() + timedelta(seconds=10)
    break_loop = False
    while not break_loop:
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

            # TODO: GET ATTACKER IP ADDRESS

            # Get attacker MAC address
            attacker_mac_address = get_attacker_mac_address(eth_header)

            # Get port number
            port = int(tcp_header[1])

            # Checking types of attack 
            if (attacker_mac_address == src_address and port == target_port):
                if(flags == FLAGS_ACK):
                    print("!! RECEIVED A TCP CONNECT ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
                    break
                elif(flags == FLAGS_RST):
                    print("!! RECEIVED A TCP HALF OPENING ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
                    break
        
        # Timeout stop condition
        if wait_until < datetime.now():
            break_loop = True

    print("Exiting thread...")

def get_attacker_mac_address(eth_header):
    """
    Helper function to get a readable 'src mac address' from bytes
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

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):

            # Get TCP header
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])

            # Get TCP flags
            flags = int(tcp_header[5])

            # TODO: GET ATTACKER IP ADDRESS
            # source_address = packet[22:38]
            # print("attacker", source_address)

            # Get possible attacker MAC address
            attacker_mac_address = get_attacker_mac_address(eth_header)
            print("Receiving IPv6 packet from MAC address: {}".format(attacker_mac_address))

            # Get target port
            target_port = int(tcp_header[1])

            # TCP Connect Attack and Half-opening handling
            if (flags == FLAGS_SYN):
                # Starts new thread that waits for ACK or RST
                start_new_thread(threaded, (listen, attacker_mac_address, target_port,))

            # Stealth scan / TCP FIN handling
            elif (flags == FLAGS_FIN):
                print("!! RECEIVED STEALTH SCAN/TCP FIN FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))

            # SYN/ACK attack handling
            elif (flags == FLAGS_SYN_ACK):
                print("!! RECEIVED SYN/ACK ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
        
if __name__ == "__main__":
    listener()