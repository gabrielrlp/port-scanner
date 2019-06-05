import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

class IPHeader:
    """
    doc
    """
    def __init__(self, version, traffic_class, flow_label, payload_len, next_header, hop_limit, src_address, dst_address):
        """
        Construct the IPv6 header.
        :param version: (4-bits) It represents the version of Internet Protocol, i.e. 0110.
        :param traffic_class: (8-bits) These 8 bits are divided into two parts. 
                    The most significant 6 bits are used for Type of Service to let the 
                    Router Known what services should be provided to this packet. 
                    The least significant 2 bits are used for Explicit Congestion Notification (ECN).
        :param flow_label: (20-bits) This label is used to maintain the sequential flow of the packets 
                belonging to a communication. The source labels the sequence to help the router 
                identify that a particular packet belongs to a specific flow of information. 
                This field helps avoid re-ordering of data packets. It is designed for 
                streaming/real-time media.
        :param payload_len: (16-bits) This field is used to tell the routers how much information a particular 
                    packet contains in its payload. Payload is composed of Extension Headers and Upper 
                    Layer data. With 16 bits, up to 65535 bytes can be indicated; 
                    but if the Extension Headers contain Hop-by-Hop Extension Header, then the payload may 
                    exceed 65535 bytes and this field is set to 0.
        :param next_header: (8-bits) This field is used to indicate either the type of Extension Header, 
                    or if the Extension Header is not present then it indicates the Upper Layer PDU. 
                    The values for the type of Upper Layer PDU are same as IPv4’s.
        :param hop_limit: (8-bits) This field is used to stop packet to loop in the network infinitely. 
                This is same as TTL in IPv4. The value of Hop Limit field is decremented by 
                1 as it passes a link (router/hop). When the field reaches 0 the packet is discarded.
        :param src_address: (128-bits) This field indicates the address of originator of the packet.
        :param dst_address: (128-bits) This field provides the address of intended recipient of the packet.
        """
        self.version = version
        self.traffic_class = traffic_class
        self.flow_label = flow_label
        self.payload_len = payload_len
        self.next_header = next_header
        self.hop_limit = hop_limit
        self.src_address = src_address
        self.dst_address = dst_address
        self.src_address_ipv6 = socket.inet_pton(socket.AF_INET6, self.src_address)
        self.dst_address_ipv6 = socket.inet_pton(socket.AF_INET6, self.dst_address)
        self.packet_format = '!IHBB'

    def assembly(self):
        ver_traffic_flow = (self.version << 8) + self.traffic_class
        ver_traffic_flow = (ver_traffic_flow << 20) + self.flow_label

        packet = pack(
            self.packet_format,
            ver_traffic_flow,
            self.payload_len,
            self.next_header,
            self.hop_limit
        )
        
        packet = packet + self.src_address_ipv6 + self.dst_address_ipv6

        return packet