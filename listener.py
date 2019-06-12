import argparse, socket, time, threading
import numpy as np

from struct import *
from _thread import *
from threading import Lock
from suspect import Suspect
from utils import bcolors

from scipy.stats import mode

# Arguments Parsing Settings
parser = argparse.ArgumentParser()

# Main arguments for configuration
parser.add_argument('--smac', help="the source MAC address (aa:bb:cc:dd:ee:ff)", required=True)
parser.add_argument('--std', type=float, help='...', default=10.0)
parser.add_argument('--suspect-threshold', '--st', type=int, help='...', default=5)

class Listener:
    def __init__(self, args):
        self.args = args
        self.suspect_table = []
        self.flags_dict = {
            1 : 'FIN',
            2 : 'SYN',
            4 : 'RST',
            16: 'ACK',
            18: 'SYN/ACK'
        }
        self.prot_type_ipv6 = 0x86dd
        self.ip_next_header_tcp = 6
        self.mutex = Lock()

    def listen(self):
        # Creates raw socket
        listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

        print("Starting Listener...")

        # Starts parallel thread to check the storage table every X seconds
        start_new_thread(self.suspect_monitor,(args,))

        while True:
            # Receive packet
            raw_packet = listen.recv(128)

            self.mutex.acquire()

            # Get ethernet header
            eth_header = raw_packet[0:14]

            # Get protocol type; 0x86dd for IPv6
            protocol_type = unpack('!6B6BH', eth_header)[12]

            # Check for IPv6 only
            if (protocol_type == int(self.prot_type_ipv6)):
                # Get IP header, ignoring src address and dest address
                ip_header = unpack('!IHBB', raw_packet[14:22])

                # Get transport type; we want TCP
                transport_type = ip_header[2]

                # Check for TCP only
                if (transport_type == self.ip_next_header_tcp):
                    # Get TCP header
                    tcp_header = unpack('!HHLLBBHHH', raw_packet[54:74])

                    # Get TCP flags
                    flags = int(tcp_header[5])

                    # Get possible suspect MAC address
                    suspect_mac_address = ':'.join(format(a, '02x') for a in eth_header[6:12])
                    suspect_ip_address = socket.inet_ntop(socket.AF_INET6, raw_packet[22:38])                    

                    if suspect_mac_address != args.smac:
                        # Get target port
                        target_port = int(tcp_header[1])

                        # ARMAZENA NA TABELA
                        for s in self.suspect_table:
                            if suspect_mac_address == s.mac_address:
                                s.update_ports(target_port, flags, time.time())
                                break
                        else:
                            s = Suspect(ip_address=suspect_ip_address,
                                        mac_address=suspect_mac_address, 
                                        port=target_port,
                                        flags=flags, 
                                        timestamp=time.time())
                            self.suspect_table.append(s)
            self.mutex.release()    

    def suspect_monitor(self, args):
        """
        Thread that waits for either TCP Connect Attack or TCP Half-opening Attack
        """
        while True:
            self.mutex.acquire()
            # iterate through table 
            # checks every 5 seconds
            if len(self.suspect_table) > 0:
                # para cada porta
                for s in self.suspect_table:
                    if len(s.ports) > 0:
                        times = [p.timestamp for p in s.ports]
                        flags = [p.state for p in s.ports]
                        if len(times) > args.suspect_threshold and np.std(times) < args.std:
                            mode_flag = mode(flags)
                            print(bcolors.WARNING + '[WARNING]' + bcolors.ENDC + ' Possible network attack detected')
                            print('[INFO] Suspect IPv6 address: {}'.format(s.ip_address))
                            print('[INFO] Suspect MAC address: {}'.format(s.mac_address))
                            print('[INFO] Possible attack: {}'.format(self.flags_dict[mode_flag[0][0]]))
                            # Reset suspect ports
                            s.ports = []
            # Mutex release
            self.mutex.release()
            time.sleep(1)
        
if __name__ == "__main__":
    args = parser.parse_args()

    l = Listener(args=args)
    l.listen()