import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

class TCPHeader:
    """
    doc
    """
    def __init__(self, src_port, dst_port, seq_num, ack_seq, header_len, fin, syn, rst, psh, ack, urg, window, checksum, urg_ptr):
        """
        Construct the TCP header.
        :param src_port: (16-bits) Identifies the sending port.
        :param dst_port: (16-bits) Identifies the receiving port.
        :param seq_num: (32-bits) Has a dual role:
                    - If the SYN flag is set (1), then this is the initial sequence number. 
                        The sequence number of the actual first data byte and the acknowledged 
                        number in the corresponding ACK are then this sequence number plus 1.
                    - If the SYN flag is clear (0), then this is the accumulated sequence number 
                        of the first data byte of this segment for the current session.
        :param ack_seq: (32-bits) If the ACK flag is set then the value of this field is the next sequence 
                    number that the sender of the ACK is expecting. 
                    This acknowledges receipt of all prior bytes (if any). 
                    The first ACK sent by each end acknowledges the other end's initial 
                    sequence number itself, but no data.
        :param header_len: (4-bits) Specifies the size of the TCP header in 32-bit words. 
                    The minimum size header is 5 words and the maximum is 15 words thus 
                    giving the minimum size of 20 bytes and maximum of 60 bytes, 
                    allowing for up to 40 bytes of options in the header. 
                    This field gets its name from the fact that it is also the offset 
                    from the start of the TCP segment to the actual data.
        :param fin: (1-bit) (aka control bit) Last packet from sender.
        :param syn: (1-bit) (aka control bit) Synchronize sequence numbers. 
                        Only the first packet sent from each end should have this flag set. 
                    Some other flags and fields change meaning based on this flag, 
                    and some are only valid when it is set, and others when it is clear.
        :param rst: (1-bit) (aka control bit) Reset the connection
        :param psh: (1-bit) (aka control bit) Push function. Asks to push the buffered data to the receiving application.
        :param ack: (1-bit) (aka control bit) Indicates that the Acknowledgment field is significant. 
                    All packets after the initial SYN packet sent by the client should have this flag set.
        :param urg: (1-bit) (aka control bit) Indicates that the Urgent pointer field is significant
        :param window: (16-bits) The size of the receive window, which specifies the number of window size units
                (by default, bytes) (beyond the segment identified by the sequence number in 
                the acknowledgment field) that the sender of this segment is currently willing to receive
        :param checksum: (16-bits) The 16-bit checksum field is used for error-checking of the header, the Payload 
                and a Pseudo-Header. The Pseudo-Header consists of the Source IP Address, 
                the Destination IP Address, the protocol number for the TCP-Protocol (0x0006) 
                and the length of the TCP-Headers including Payload (in Bytes).
        :param urg_ptr: (16-bits) If the URG flag is set, then this 16-bit field is an offset from the 
                    sequence number indicating the last urgent data byte.
        """
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_seq = ack_seq
        self.header_len = header_len
        self.fin = fin
        self.syn = syn
        self.rst = rst
        self.psh = psh
        self.ack = ack
        self.urg = urg
        self.window = window
        self.checksum = checksum
        self.urg_ptr = urg_ptr
        self.packet_format = '!HHLLBBHHH'

    def assembly(self):
        tcp_flags = (self.fin)      + \
                    (self.syn << 1) + \
                    (self.rst << 2) + \
                    (self.psh << 3) + \
                    (self.ack << 4) + \
                    (self.urg << 5)

        packet = pack(
            self.packet_format,
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_seq,
            (self.header_len << 4) + 0,
            tcp_flags,
            socket.htons(self.window),
            self.checksum,
            self.urg_ptr
        )
        
        return packet