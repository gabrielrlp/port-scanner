import socket, sys
from struct import *
from _thread import *
import threading

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

def threaded(listen):
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

            if(flags == FLAGS_ACK):
                print("!! RECEIVED A TCP CONNECT ATTACK !!")
                break
            elif(flags == FLAGS_RST):
                print("!! RECEIVED A TCP HALF OPENING ATTACK !!")
                break

    print("Exiting thread...")

def listener():
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
            print(flags)

            # This listener should warn which type of attack it is receiving
            # TCP connect attack
            # expected: SYN and later an ACK
            # TCP half-opening
            # expected: SYN and later an RST

            if (flags == FLAGS_SYN):
                # await ACK or RST
                start_new_thread(threaded, (listen,))

            # Stealth scan ou TCP FIN
            # expected: FIN
            elif (flags == FLAGS_FIN):
                print('stealth scan ou tcp fin')

            # SYN/ACK
            # expected: SYN/ACK
            elif (flags == FLAGS_SYN_ACK):
                print('syn / ack')
        
if __name__ == "__main__":
    listener()