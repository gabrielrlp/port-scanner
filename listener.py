import socket, time
from struct import *
from utils import sendeth, bcolors
from _thread import *
import threading
from datetime import timedelta

################
# HELPER STUFF #
################

class Store(object):
    def __init__(self, addr, port, type):
        self.addr = ''
        self.port = 0
        self.type = 0

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

# IPv6 next header for TCP
IP_NEXT_HEADER_TCP = 17 

# Interval timeout
WAIT_TIMEOUT_SEC = 5

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
        raw_packet = listen.recvfrom(128)
        packet = raw_packet[0]

        # Get ethernet header
        eth_header = packet[0:14]

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):

            # Get IP header, ignoring src address and dest address
            ip_header = unpack('!IHBB', packet[14:22])

            # Get transport type; we want TCP
            transport_type = ip_header[2]

            # Check for TCP only
            if (transport_type == IP_NEXT_HEADER_TCP):

                # Get TCP header
                tcp_header = unpack('!HHLLBBHHH', packet[54:74])

                # Get TCP flags
                flags = int(tcp_header[5])

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
                    # Starts new thread that check if this is an attack
                    start_new_thread(threaded, (listen, attacker_mac_address, target_port,))

                    #print("!! RECEIVED STEALTH SCAN/TCP FIN FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))

                # SYN/ACK attack handling
                elif (flags == FLAGS_SYN_ACK):
                    # Starts new thread that check if this is an attack
                    start_new_thread(threaded, (listen, attacker_mac_address, target_port,))

                    #print("!! RECEIVED SYN/ACK ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))

def threaded(listen, src_address, target_port):
    """
    Thread that waits for either TCP Connect Attack or TCP Half-opening Attack
    """
    print("Started thread...")

    store_list = []

    # Timeout 10 sec? 60 sec?
    wait_until = datetime.now() + timedelta(seconds=WAIT_TIMEOUT_SEC)
    break_loop = False
    while not break_loop:
        # We should put this packet receiving code inside a single function for reusability
        # Receive packet
        raw_packet = listen.recvfrom(128)
        packet = raw_packet[0]

        # Get ethernet header
        eth_header = packet[0:14]

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):
            print("Received IPv6 packet inside thread.")

            # Get IP header, ignoring src address and dest address
            ip_header = unpack('!IHBB', packet[14:22])

            # Get transport type; we want TCP
            transport_type = ip_header[2]

            # Check for TCP only
            if (transport_type == IP_NEXT_HEADER_TCP):

                # Get TCP header
                tcp_header = unpack('!HHLLBBHHH', packet[54:74])

                # Get TCP flags
                flags = int(tcp_header[5])

                # Get attacker MAC address
                attacker_mac_address = get_attacker_mac_address(eth_header)

                # Get port number
                port = int(tcp_header[1])

                # We need the same src address and target port that received a SYN
                # This is for the tcp connect and tcp half opening cases
                if (attacker_mac_address == src_address and port == target_port):
                    
                    # Checking types of attack; i.e. tcp connect and half opening
                    #if(flags == FLAGS_ACK):

                    # Fuck this shit
                    store_list.append(Store(attacker_mac_address, port, flags))

                        #print("!! RECEIVED A TCP CONNECT ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
                    #elif(flags == FLAGS_RST):

                        # Fuck this shit
                        #store_list.append(Store(attacker_mac_address, port, flags))

                        #print("!! RECEIVED A TCP HALF OPENING ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
        
        # Timeout stop condition; check if attack happened and if it did, which type
        if wait_until < datetime.now():
            
            # This creates a dict with the <key> as the port number and <value> as the number of its occurrences in a list
            #counter_elements = [[x,store_list.port.count(x)] for x in set(store_list.port)]
            
            threshold = 3

            for key, value in counter_elements.items(): 
                if(value >= threshold):
                    print("attack happened"):

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


        
if __name__ == "__main__":
    listener()
