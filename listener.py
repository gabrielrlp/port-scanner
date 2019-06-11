import socket, sys
from struct import *
from _thread import *
import threading
from datetime import timedelta
from datetime import datetime
import tkinter as tk

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

# Window configuration
WND_RESOLUTION = "800x600"
WND_TITLE      = "ListenerV6"

SHUTDOWN = False

IPV6_LIST_IN = []

#####################
class listenerWindow:
    def __init__(self, master):
        self.master = master
        self.master.title(WND_TITLE)
        self.master.geometry(WND_RESOLUTION)
        self.listernerThread = threading.Thread(target = listener);
        self.w, self.h = WND_RESOLUTION.split("x",1)
        self.w, self.h = int(self.w), int(self.h)

        self.frmMain = tk.Frame(master, width = self.w, height = self.h, bg = 'white')
        self.frmDisplay = tk.Frame(self.frmMain, width = (self.w-260), height = (self.h-60), bg = 'white smoke', highlightthickness = 1, highlightbackground = 'grey')

        self.btnCloseApp = tk.Button(self.frmMain, text="Exit", command = self.quitListener, height = 2, width = 6, bg = 'white', activebackground = 'white smoke' )


        self.frmMain.place(x = 0, y = 0)
        self.frmDisplay.place( x = 250, y = 50 )
        self.btnCloseApp.place(x = 10, y = (self.h-50))


    def quitListener(self):
        global SHUTDOWN
        SHUTDOWN = 1
        self.listernerThread.join()
        self.master.quit()


def threaded(listen, src_address, target_port):
    """
    Thread that waits for either TCP Connect Attack or TCP Half-opening Attack
    """
    print("Started thread...")

    # Timeout 10 sec? 60 sec?
    wait_until = datetime.now() + timedelta(seconds=10)
    break_loop = False
    while not break_loop:
        # We should put this packet receiving code inside a single function for reusability
        # Receive packet
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]

        # Get ethernet header
        eth_header = packet[0:14]

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):
            print("Received IPv6 packet inside thread.")

            # Get TCP header
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])

            # Get TCP flags
            flags = int(tcp_header[5])

            # TODO: GET ATTACKER IP ADDRESS

            # Get attacker MAC address
            attacker_mac_address = get_attacker_mac_address(eth_header)

            # Get port number
            port = int(tcp_header[1])

            # Checking types of attack 
            if (attacker_mac_address == src_address and port == target_port):
                if(flags == FLAGS_ACK):
                    print("!! RECEIVED A TCP CONNECT ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
                    break
                elif(flags == FLAGS_RST):
                    print("!! RECEIVED A TCP HALF OPENING ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
                    break
        
        # Timeout stop condition
        if wait_until < datetime.now():
            break_loop = True

    print("Exiting thread...")

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

def listener():
    """
    This listener represents the main attack detection component.
    """
    global SHUTDOWN
    # Creates raw socket
    listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    print("Starting Listener...")
    while not SHUTDOWN:
        # We should put this packet receiving code inside a single function for reusability
        # Receive packet
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]
        # Get ethernet header
        eth_header = packet[0:14]

        #Next header
        print(packet.hex()[40:42])

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        # Check for TCP IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):

            # Get TCP header
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])

            # Get TCP flags
            flags = int(tcp_header[5])

            # TODO: GET ATTACKER IP ADDRESS
            source_address = packet[22:38].hex()
            #rint(source_address)
            #sa1 = source_address[0:4]
            #sa2 = source_address[4:8]
            #sa3 = source_address[8:12]
            #sa4 = source_address[12:16]
            #sa5 = source_address[16:20]
            #sa6 = source_address[24:28]
            #sa7 = source_address[28:32]

            sa = (source_address[ 0: 4]+"::"+
                  source_address[ 4: 8]+":"+
                  source_address[ 8:12]+":"+
                  source_address[12:16]+":"+
                  source_address[16:20]+":"+
                  source_address[24:28]+":"+
                  source_address[28:32])

            #print(sa)


            #print(sa1)
            #print(sa2)
            #print(sa3)
            #print(sa4)
            #print(sa5)
            #print(sa6)
            #print(sa7)

            #print("attacker{}", format(source_address))

            # Get possible attacker MAC address
            attacker_mac_address = get_attacker_mac_address(eth_header)
            print(" IPv6 packet from IP, MAC: {} - {}".format(sa,attacker_mac_address))

            # Get target port
            target_port = int(tcp_header[1])

            # TCP Connect Attack and Half-opening handling
            #if (flags == FLAGS_SYN):
                # Starts new thread that waits for ACK or RST
                #start_new_thread(threaded, (listen, attacker_mac_address, target_port,))

            # Stealth scan / TCP FIN handling
            #elif (flags == FLAGS_FIN):
                #print("!! RECEIVED STEALTH SCAN/TCP FIN FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))

            # SYN/ACK attack handling
            #elif (flags == FLAGS_SYN_ACK):
                #print("!! RECEIVED SYN/ACK ATTACK FROM MAC ADDRESS {} on port {} !!".format(attacker_mac_address, target_port))
    
        

if __name__ == "__main__":
    root = tk.Tk()
    window = listenerWindow(root)
    window.listernerThread.start()
    root.mainloop()
    #listener()