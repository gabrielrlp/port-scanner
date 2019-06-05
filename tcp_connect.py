# Packet binary data https://docs.python.org/2/library/struct.html
# TCP Header https://www.gatevidyalay.com/wp-content/uploads/2018/09/TCP-Header-Format.png
# IPv6 Header http://ipv6.br/post/cabecalho/
import socket, sys
from socket import AF_PACKET, SOCK_RAW
from struct import *

from ethernet_header import EthernetHeader
from ip_header import IPHeader
from tcp_header import TCPHeader

def sendeth(eth_frame, interface = 'enp4s0'):
	"""Send raw Ethernet packet on interface."""
	s = socket.socket(AF_PACKET, SOCK_RAW)
	s.bind((interface, 0))
	return s.send(eth_frame)

def checksum(msg):
	s = 0
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w = (msg[i] << 8) + (msg[i+1])
		s = s + w

	s = (s >> 16) + (s & 0xffff)
	s = ~s & 0xffff

	return s

if __name__ == "__main__":
	# d8:cb:8a:cc:6a:c4
	dst_mac = [0xd8, 0xcb, 0x8a, 0xcc, 0x6a, 0xc4]
	src_mac = [0xd8, 0xcb, 0x8a, 0xcc, 0x6a, 0xc4]		
	# Ethernet header
	eth_header = EthernetHeader(
		dst_mac = dst_mac,
		src_mac = src_mac,
		type = 0x86dd
	)
	eth_packet = eth_header.assembly()
	
	src_ip = 'fe80::9994:b4ab:3ea0:a988'
	dst_ip = 'fe80::9994:b4ab:3ea0:a988'
	# ip header
	ip_header = IPHeader(
		version = 6,
		traffic_class = 0,
		flow_label = 1,
		payload_len = 20,
		next_header = socket.IPPROTO_TCP,
		hop_limit = 255,
		src_address = src_ip,
		dst_address = dst_ip
	)
	ip_packet = ip_header.assembly()

	tcp_header = TCPHeader(
		src_port = 1234,
		dst_port = 80,
		seq_num = 0,
		ack_seq = 0,
		header_len = 5,
		fin = 0,
		syn = 1,
		rst = 0,
		psh = 0,
		ack = 0,
		urg = 0,
		window = 5840,
		checksum = 0,
		urg_ptr = 0
	)
	tcp_packet = tcp_header.assembly()

	# pseudo header fields
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_packet)

	psh = ip_header.src_address_ipv6 + ip_header.dst_address_ipv6 + pack('!BBH', placeholder, protocol, tcp_length)
	psh = psh + tcp_packet
	# make the tcp header again and fill the correct checksum
	tcp_header.checksum = checksum(psh)
	tcp_packet = tcp_header.assembly()	
	 
	# final full packet - syn packets dont have any data
	packet = eth_packet + ip_packet + tcp_packet
	r = sendeth(packet, 'enp0s31f6')
	
	print("Sent %d bytes" % r)
