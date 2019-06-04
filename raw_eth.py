# Packet binary data https://docs.python.org/2/library/struct.html
# TCP Header https://www.gatevidyalay.com/wp-content/uploads/2018/09/TCP-Header-Format.png
# IPv6 Header http://ipv6.br/post/cabecalho/

import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

def sendeth(eth_frame, interface = "eth0"):
	"""Send raw Ethernet packet on interface."""
	s = socket.socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))
	return s.send(eth_frame)

def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = (ord(msg[i]) << 8) + (ord(msg[i+1]))
		s = s + w

	s = (s >> 16) + (s & 0xffff)
	s = ~s & 0xffff

	return s

def make_eth_header(dst_mac, src_mac, eth_type):
	"""
	Construct the Ethernet header.
	:param dst_mac: (48-bits) This is 6-Byte field which contains the MAC address of machine for 
					which data is destined.
	:param src_mac: (48-bits) This is a 6-Byte field which contains the MAC address of source machine. 
					As Source Address is always an individual address (Unicast), the least significant 
					bit of first byte is always 0.
	:param eth_type: (16-bits) The ethertype.
	"""
	packet_format = '!6B6BH'
	eth_header = pack(packet_format,
					  dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5],
					  src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
					  eth_type)
	return eth_header

def make_ipv6_header(version, traffic_class, flow_label, payload_len, next_header, hop_limit, src_address, dst_address):
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
	packet_format = '!BBHHBB16s16s'
	ipv6_header = pack(packet_format,
					   (version << 4) + 0,
					   traffic_class,
					   (flow_label << 16) + 0,
					   payload_len,
					   next_header,
					   hop_limit,
				       socket.inet_pton(socket.AF_INET6, src_address),
					   socket.inet_pton(socket.AF_INET6, dst_address))
	return ipv6_header

def make_tcp_header(src_port, dst_port, seq_num, ack_seq, header_len, fin, syn, rst, psh, ack, urg, window, check, urg_ptr):
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
	:param check: (16-bits) The 16-bit checksum field is used for error-checking of the header, the Payload 
				  and a Pseudo-Header. The Pseudo-Header consists of the Source IP Address, 
				  the Destination IP Address, the protocol number for the TCP-Protocol (0x0006) 
				  and the length of the TCP-Headers including Payload (in Bytes).
	:param urg_ptr: (16-bits) If the URG flag is set, then this 16-bit field is an offset from the 
					sequence number indicating the last urgent data byte.
	"""
	packet_format = '!HHLLBBHHH'
	tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
	tcp_header = pack(packet_format,
					  src_port,
					  dst_port,
					  seq_num,
					  ack_seq,
					  (header_len << 4) + 0,
					  tcp_flags,
					  socket.htons(window),
					  check,
					  urg_ptr)


if __name__ == "__main__":
	# src=fe:ed:fa:ce:be:ef, dst=52:54:00:12:35:02, type=0x0800 (IP)
	dst_mac = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
	src_mac = [0x00, 0x0a, 0x11, 0x11, 0x22, 0x22]	
	# Ethernet header
	eth_header = make_eth_header(dst_mac, src_mac, 0x0800)
	
	source_ip = '192.168.1.101'
	dest_ip = '192.168.1.1'			# or socket.gethostbyname('www.google.com')

	ip_header = make_ipv6_header(6,						# version
								 0,						# traffic class
								 1,						# flow label
								 20 + 20,				# payload length
								 socket.IPPROTO_TCP,	# next header
								 255,					# hop limit
								 source_ip,				# source address
								 dest_ip)				# destination address

	tcp_header = make_tcp_header(1234,	# source port
								 80,	# destination port
								 0,		# sequence number
								 0,		# ack sequence
								 5,		# header length
								 0,		# fin
								 1,		# syn
								 0,		# rst
								 0,		# psh
								 0,		# ack
								 0,		# urg
								 5840,	# window
								 0,		# checksum
								 0)		# urg ptr

	############################# CONTINUAR ##################################
	 
	# pseudo header fields
	source_address = socket.inet_aton( source_ip )
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header)
	 
	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
	psh = psh + tcp_header;
	 
	tcp_checksum = checksum(psh)
	 
	# make the tcp header again and fill the correct checksum
	tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
	 
	# final full packet - syn packets dont have any data
	packet = eth_header + ip_header + tcp_header
	r = sendeth(packet, "enp1s0")
	
	print("Sent %d bytes" % r)
