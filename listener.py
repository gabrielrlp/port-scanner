import socket, sys

def listener():
    listen = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
    print("Starting Listener")
    while True:
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]
        print(packet)
        # Now we need to unpack the packet. It will be an IP/TCP packet
        # We are looking for SYN-ACKs from our SYN scan
        # Fields to check: IP - src addr; TCP - src port, flags
        # We want to pull out and compare only these three
        # Heres the math for unpacking: B=1, H=2, L=4, 4s=4  (those are bytes)

        # This is the IP header, not including Destination Address. Normal length is 40 bytes.
        # We're parsing as little as possible
        print(len(packet))
        # ip_header = unpack('!IHBB',packet[0:24])

if __name__ == "__main__":
    listener()