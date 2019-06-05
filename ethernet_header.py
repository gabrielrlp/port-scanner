import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

class EthernetHeader:
    """
    doc
    """
    def __init__(self, dst_mac, src_mac, type):
        """
        :param dst_mac: (48-bits) This is 6-Byte field which contains the MAC address of machine for 
                which data is destined.
        :param src_mac: (48-bits) This is a 6-Byte field which contains the MAC address of source machine. 
                As Source Address is always an individual address (Unicast), the least significant 
                bit of first byte is always 0.
        :param eth_type: (16-bits) The ethertype.
        """
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.type = type
        self.packet_format = '!6B6BH'
    
    def assembly(self):
        packet = pack(
            self.packet_format,
            self.dst_mac[0], self.dst_mac[1], self.dst_mac[2], self.dst_mac[3], self.dst_mac[4], self.dst_mac[5],
            self.src_mac[0], self.src_mac[1], self.src_mac[2], self.src_mac[3], self.src_mac[4], self.src_mac[5],
            self.type
        )

        return packet