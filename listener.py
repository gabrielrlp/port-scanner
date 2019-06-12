import argparse
import socket, time
from struct import *
from _thread import *
import threading
from threading import Lock
from datetime import timedelta
import datetime
import numpy as np

# Arguments Parsing Settings
parser = argparse.ArgumentParser()

# Main arguments for configuration
parser.add_argument('--smac', help="the source MAC address (aa:bb:cc:dd:ee:ff)", required=True)
parser.add_argument('--var', type=float, help='...', default=1.0)
parser.add_argument('--monitor-sleep', '--ms', type=int, help='...', default=1)

# test
table_store = []

class Port:
    def __init__(self, port, flags, time):
        self.port = port
        self.access_time = time
        self.state = flags
        self.update_state(flags)
    def update_state(self, flags):
        self.state = flags

class Store:
    def __init__(self, address, port, flags, timestamp):
        self.attacker_address = address
        p = Port(port, flags, timestamp)
        self.ports = []
        self.ports.append(p)
        self.port_updated = False

    def update_ports(self, port, flags, timestamp):
        # testar se a porta ja existe
        for p in self.ports:
            #print("port: ", p.port, " state: ", p.state, "time: ", p.access_time)
            # se existir, atualizar com o ultimo timestamp
            if p.port == port:
                p.access_time = timestamp
                p.update_state(flags)
                self.port_updated = True
                break
        if self.port_updated == False:
            # se nao existir, criar uma nova
            p = Port(port, flags, timestamp)
            self.ports.append(p)
        self.port_updated = False

# IPv6 type from ethernet header
PROTOCOL_TYPE_IPV6 = 0x86dd

## This is for the TCP flags statements
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

# IPv6 next header for TCP
IP_NEXT_HEADER_TCP = 6


def listener(args):
    global table_store
    """
    This listener represents the main attack detection component.
    """
    # Creates raw socket
    listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    print("Starting Listener...")

    # Starts parallel thread to check the storage table every X seconds
    start_new_thread(checker_thread,(args,))

    while True:
        # We should put this packet receiving code inside a single function for reusability
        # Receive packet
        raw_packet = listen.recvfrom(128)
        packet = raw_packet[0]

        # Get ethernet header
        eth_header = packet[0:14]

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):
            # Get IP header, ignoring src address and dest address
            ip_header = unpack('!IHBB', packet[14:22])

            # Get transport type; we want TCP
            transport_type = ip_header[2]

            # Check for TCP only
            if (transport_type == IP_NEXT_HEADER_TCP):
                # Get TCP header
                tcp_header = unpack('!HHLLBBHHH', packet[54:74])

                # Get TCP flags
                flags = int(tcp_header[5])

                # Get possible attacker MAC address
                attacker_mac_address = get_attacker_mac_address(eth_header)
                #print("-----------------------------------------------")
                #print("Receiving IPv6 packet from MAC address: {}".format(attacker_mac_address))
                if attacker_mac_address != args.smac:
                    # Get target port
                    target_port = int(tcp_header[1])

                    ip_exists = False
                    # ARMAZENA NA TABELA
                    for item in table_store:
                        print(attacker_mac_address, item.attacker_address)
                        if attacker_mac_address == item.attacker_address:
                            item.update_ports(target_port, flags, datetime.datetime.now().time())
                            ip_exists = True
                            break
                    if ip_exists == False:
                        s = Store(attacker_mac_address, target_port, flags, datetime.datetime.now().time())
                        table_store.append(s)

                for s in table_store:
                    #print('store: {}'.format(s.attacker_address))
                    for p in s.ports:
                        #print('port: {}'.format(p.port))
                        pass

                            # # TCP Connect Attack and Half-opening handling
                            # if (flags == FLAGS_SYN):
                            #     # Starts new thread that waits for ACK or RST
                            #     start_new_thread(threaded, (listen, attacker_mac_address, target_port,))

                            # # Stealth scan / TCP FIN handling
                            # elif (flags == FLAGS_FIN):
                            #     # Starts new thread that check if this is an attack
                            #     start_new_thread(threaded, (listen, attacker_mac_address, target_port,))

                            #     #print("!! RECEIVED STEALTH SCAN/TCP FIN FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))

                            # # SYN/ACK attack handling
                            # elif (flags == FLAGS_SYN_ACK):
                            #     # Starts new thread that check if this is an attack
                            #     start_new_thread(threaded, (listen, attacker_mac_address, target_port,))

                            #     #print("!! RECEIVED SYN/ACK ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))

def checker_thread(args):
    """
    Thread that waits for either TCP Connect Attack or TCP Half-opening Attack
    """
    global table_store
    while True:
        print('--')
        # iterate through table 
        # checks every 5 seconds
        if len(table_store) > 0:
            # para cada porta
            for s in table_store:
                times = []
                for p in s.ports:
                    # parser do time
                    seconds = float(str(p.access_time).split(':')[2])
                    times.append(seconds)
                if len(times) > 0 and np.var(times) < args.var:
                    print('attack!!!')
                    # check state
        table_store = []
        time.sleep(args.monitor_sleep)

def get_attacker_mac_address(eth_header):
    """
    Helper function to get a readable 'src mac address' from bytes
    """

    # Unpack
    unpacked_eth_header = unpack('!6B6BH', eth_header)

    # Get attacker MAC address
    raw_attacker_mac_address = unpacked_eth_header[6:12]

    # Stringfy mac address
    attacker_mac_address = ""
    for m in raw_attacker_mac_address:
        attacker_mac_address = attacker_mac_address + format(m, '02x') + ":"

    # Remove last ':'
    attacker_mac_address = attacker_mac_address[:-1]

    return attacker_mac_address


        
if __name__ == "__main__":
    args = parser.parse_args()
    listener(args)
