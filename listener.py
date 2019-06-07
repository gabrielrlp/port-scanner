import socket, sys
from struct import *

def listener():
    listen = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print("Starting Listener")
    while True:
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]
        # Now we need to unpack the packet. It will be an TCP packet
        # We want to pull out and compare only these three

        # This is the TCP header. Normal length is 20 bytes.
        tcp_header = unpack('!HHLLBBHHH', packet[0:20])
        print(tcp_header)

if __name__ == "__main__":
    listener()
