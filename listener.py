import socket, sys
from struct import *

PROTOCOL_TYPE_IPV6 = 0x86dd

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

def listener():
    listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    print("Starting Listener")
    while True:
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]
        # Now we need to unpack the packet. It will be an TCP packet
        # We want to pull out and compare only these three

        # This is the TCP header. Normal length is 20 bytes.

        # Get ethernet header
        eth_header = packet[0:14]

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]
    
        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])
            flags = int(tcp_header[5])
            print(flags)

            urg = tcp_header[5] >> 5 & 1
            ack = tcp_header[5] >> 4 & 1
            psh = tcp_header[5] >> 3 & 1
            rst = tcp_header[5] >> 2 & 1
            syn = tcp_header[5] >> 1 & 1
            fin = tcp_header[5] >> 0 & 1

            # This listener should warn which type of attack it is receiving
    
            # TCP connect attack
            # expected: SYN and later an ACK
            # TCP half-opening
            # expected: SYN and later an RST

            if (flags == FLAGS_SYN):
                print('esperar pacote com ack(tcp connect) ou rst(tcp half-opening)')
                print('aha2: ', bin(flags))
                # await ACK or RST
                # thread
                # fork

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