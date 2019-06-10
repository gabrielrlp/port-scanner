import argparse
from multiprocessing import Process
from tcp_connect import TCPConnect
from tcp_half_opening import TCPHalfOpening
from tcp_fin import TCPFin
from syn_ack import SYNACK

# Arguments Parsing Settings
parser = argparse.ArgumentParser()

DEFAULT_SRC_PORT = 1234

# Main arguments for configuration
parser.add_argument('--smac', help="the source MAC address (aa:bb:cc:dd:ee:ff)", required=True)
parser.add_argument('--dmac', help="the destination MAC address (aa:bb:cc:dd:ee:ff)", required=True)
parser.add_argument('--sip', help="the source IP address (aaaa:bbbb:cccc:dddd:eeee)", required=True)
parser.add_argument('--dip', help="the destination IP address (aaaa:bbbb:cccc:dddd:eeee)", required=True)
parser.add_argument('--interface', '--i', help="the interface to be used", default='enp0s3')
parser.add_argument('--port', '--p', type=int, nargs='+', help="the port to be scanned", required=True)
parser.add_argument('--tcp-connect', action='store_true')
parser.add_argument('--tcp-half-opening', action='store_true')
parser.add_argument('--tcp-fin', action='store_true')
parser.add_argument('--syn-ack', action='store_true')
# Debug configurations
parser.add_argument('--debug', '--d', help="enter in the debug mode", default=False)

if __name__ == "__main__":
	args = parser.parse_args()	

	# Parse the Source and Destination MAC address
	src_mac = [(int(v, 16)) for v in args.smac.split(':')]
	dst_mac = [(int(v, 16)) for v in args.dmac.split(':')]
	procs = []

	if len(args.port) >= 1:
		for p in range(args.port[0], args.port[-1] + 1):
			# TCP Connect
			if args.tcp_connect:
				tcp_connect = TCPConnect(
					src_mac = src_mac,
					dst_mac = dst_mac,
					src_ip = args.sip,
					dst_ip = args.dip,
					interface = args.interface,
					src_port = DEFAULT_SRC_PORT,
					dst_port = p)
				proc = Process(target=tcp_connect.start)
			# TCP Half-Opening
			elif args.tcp_half_opening:
				tcp_half_opening = TCPHalfOpening(
					src_mac = src_mac,
					dst_mac = dst_mac,
					src_ip = args.sip,
					dst_ip = args.dip,
					interface = args.interface,
					src_port = DEFAULT_SRC_PORT,
					dst_port = p)
				proc = Process(target=tcp_half_opening.start)
			# TCP Fin
			elif args.tcp_fin:
				tcp_fin = TCPFin(
					src_mac = src_mac,
					dst_mac = dst_mac,
					src_ip = args.sip,
					dst_ip = args.dip,
					interface = args.interface,
					src_port = DEFAULT_SRC_PORT,
					dst_port = p)
				proc = Process(target=tcp_fin.start)
			# SYN/ACK
			elif args.syn_ack:
				syn_ack = SYNACK(
					src_mac = src_mac,
					dst_mac = dst_mac,
					src_ip = args.sip,
					dst_ip = args.dip,
					interface = args.interface,
					src_port = DEFAULT_SRC_PORT,
					dst_port = p)
				proc = Process(target=syn_ack.start)
			else:
				print('[INFO] Error - Please specify a scan type')
				raise

			procs.append(proc)
			proc.start()

	else:
		print('[INFO] Error - Invalid port or range')

	for proc in procs:
		proc.join()