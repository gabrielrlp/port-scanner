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

# Packet example:
# 00 a41f72f59050                          DMAC
# 06 a41f72f59050                          SMAC
# 12 86dd                                  TYPE (IPV6)
# 14 60                                    VERSION 6
# 15 000001                                FLOW
# 18 0014                                  PAYLOAD LENGHT
# 20 06                                    NEXT HEADER
# 21 ff                                    HOP
# 22 fe80000000000000a61f72fffef59050      SIP
# 38 fe80000000000000a61f72fffef59050      DIP
# 54 04d2                                  SPORT
# 56 0016                                  DPORT
# 58 00000000                              SEQUENCE NUMBER
# 62 00000000                              ACK NUMBER
# 66 5001                                  HLEN / FLAGS
# 68 d016                                  WINDOW VALUE
# 70 8d18                                  CHEKSUM
# 72 0000                                  URGENT POINTER

# Stores IPV6 TCP packets
class packetStorage:
    # Initializer
    def __init__(self, packet, time):
        self.packet      = packet
        self.timestamp   = time
        self.avginterval = 0
        self.smac        = self.packet[ 0: 6].hex()
        self.dmac        = self.packet[ 6:12].hex()
        self.sip         = self.packet[22:38].hex()
        self.dip         = self.packet[38:54].hex()

        self.sport = []
        self.sport.append(self.packet[54:56].hex())
        self.dport = []
        self.dport.append(self.packet[56:58].hex())

    # Checks if IP is already stored, returns true if it is
    def checkIfIpStored(self, packet):
        global IPV6_LIST_IN
        if IPV6_LIST_IN == []:
            return False
        elif self.sip == packet[22:38].hex():
            return True
        return False

    # Checks if port was already used
    def checkIfPortStored(self, packet):
        global IPV6_LIST_IN
        for p in self.dport:
            print(p,packet[56:58].hex())
            if p == packet[56:58].hex():
                return True
        return False

        

#####################
class listenerWindow:
    def __init__(self, master):
        self.master = master
        self.master.title(WND_TITLE)
        self.master.geometry(WND_RESOLUTION)
        self.listernerThread = threading.Thread(target = self.listener)
        self.w, self.h = WND_RESOLUTION.split("x",1)
        self.w, self.h = int(self.w), int(self.h)

        self.lblPacketList = []

        self.frmMain = tk.Frame(master, width = self.w, height = self.h, bg = 'white')
        self.frmDisplay = tk.Frame(self.frmMain, width = (self.w-260), height = (self.h-60), bg = 'white smoke', highlightthickness = 1, highlightbackground = 'grey')

        self.btnCloseApp = tk.Button(self.frmMain, text="Exit", command = self.quitListener, height = 2, width = 6, bg = 'white', activebackground = 'white smoke' )

        self.frmMain.place(x = 0, y = 0)
        self.frmDisplay.place( x = 250, y = 50 )
        self.btnCloseApp.place(x = 10, y = (self.h-50))


    def updateLblList(self):
        # If empty list
        #if self.lblPacketList == []:
            #self.lblPacketList.append( tk.Label( self.frmDisplay, text = "24323", width = (67) ))
            #self.lblPacketList[0].place(x = 0, y = 0)

        # Check for all stored packets
        if len(IPV6_LIST_IN) != len(self.lblPacketList):

            for p in IPV6_LIST_IN:

                if p.sip() == 

            # Update labels

            


            #for lbl in self.lblPacketList:

                #if self.lblPacketList[0].cget("text") == 
                #print( self.lblPacketList[0].cget("text") )




    def quitListener(self):
        global SHUTDOWN
        SHUTDOWN = 1
        self.listernerThread.join()
        self.master.quit()


    def listener(self):
        """
        This listener represents the main attack detection component.
        """

        global SHUTDOWN
        global IPV6_LIST_IN

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

            # Get protocol type; 0x86dd for IPv6
            protocol_type = unpack('!6B6BH', eth_header)[12]

            #Next header
            next_header = (packet.hex()[40:42])

            # Check if TCP IPv6
            if (protocol_type == int(PROTOCOL_TYPE_IPV6) and next_header == "06"):

                # Add packet to list
                # Check for port
                if IPV6_LIST_IN == []:
                    IPV6_LIST_IN.append( packetStorage(packet, datetime.now()))
                else:
                    for p in IPV6_LIST_IN:
                        if not p.checkIfIpStored(packet):
                            IPV6_LIST_IN.append( packetStorage(packet, datetime.now()))
                        if not p.checkIfPortStored(packet):
                            p.dport.append(packet[56:58].hex())
                            print(p.sip, " -> ", p.dport)
                            break

                self.updateLblList()

                #print(IPV6_LIST_IN)

                # Get TCP header
                tcp_header = unpack('!HHLLBBHHH', packet[54:74])
                # Get TCP flags
                flags = int(tcp_header[5])
                # Get source IPv6 address and store in list
                source_address = packet[22:38].hex()

                # Source address to string
                sa = (source_address[ 0: 4]+"::"+
                      source_address[ 4: 8]+":" +
                      source_address[ 8:12]+":" +
                      source_address[12:16]+":" +
                      source_address[16:20]+":" +
                      source_address[24:28]+":" +
                      source_address[28:32])
                # Get source MAC address
                source_mac = get_source_mac(eth_header)
                #print("TCP IPv6 packet from IP, MAC: {} {}".format(sa,source_mac))

                # Get target port
                target_port = int(tcp_header[1])

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
            source_mac = get_source_mac(eth_header)

            # Get port number
            port = int(tcp_header[1])

            # Checking types of attack 
            if (source_mac == src_address and port == target_port):
                if(flags == FLAGS_ACK):
                    print("!! RECEIVED A TCP CONNECT ATTACK FROM MAC ADDRESS {} on port {} !!".format(source_mac, target_port))
                    break
                elif(flags == FLAGS_RST):
                    print("!! RECEIVED A TCP HALF OPENING ATTACK FROM MAC ADDRESS {} on port {} !!".format(source_mac, target_port))
                    break
        
        # Timeout stop condition
        if wait_until < datetime.now():
            break_loop = True

    print("Exiting thread...")

def get_source_mac(eth_header):
    """
    Helper function to get a readable 'src mac address' from bytes
    """

    # Unpack
    unpacked_eth_header = unpack('!6B6BH', eth_header)

    # Get attacker MAC address
    raw_source_mac = unpacked_eth_header[6:12]

    # Stringfy mac address
    source_mac = ""
    for m in raw_source_mac:
        source_mac = source_mac + format(m, '02x') + ":"

    # Remove last ':'
    source_mac = source_mac[:-1]

    return source_mac

def listener(wnd):
    """
    This listener represents the main attack detection component.
    """

    global SHUTDOWN
    global IPV6_LIST_IN

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

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]

        #Next header
        next_header = (packet.hex()[40:42])

        # Check if TCP IPv6
        if (protocol_type == int(PROTOCOL_TYPE_IPV6) and next_header == "06"):

            # Add packet to list
            # Check for port
            if IPV6_LIST_IN == []:
                IPV6_LIST_IN.append( packetStorage(packet, datetime.now()))
            else:
                for p in IPV6_LIST_IN:
                    if not p.checkIfIpStored(packet):
                        IPV6_LIST_IN.append( packetStorage(packet, datetime.now()))
                    if not p.checkIfPortStored(packet):
                        p.dport.append(packet[56:58].hex())
                        print(p.sip, " -> ", p.dport)
                        break

            #print(IPV6_LIST_IN)

            # Get TCP header
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])
            # Get TCP flags
            flags = int(tcp_header[5])
            # Get source IPv6 address and store in list
            source_address = packet[22:38].hex()
            
            # Source address to string
            sa = (source_address[ 0: 4]+"::"+
                  source_address[ 4: 8]+":" +
                  source_address[ 8:12]+":" +
                  source_address[12:16]+":" +
                  source_address[16:20]+":" +
                  source_address[24:28]+":" +
                  source_address[28:32])
            # Get source MAC address
            source_mac = get_source_mac(eth_header)
            #print("TCP IPv6 packet from IP, MAC: {} {}".format(sa,source_mac))

            # Get target port
            target_port = int(tcp_header[1])

            # TCP Connect Attack and Half-opening handling
            #if (flags == FLAGS_SYN):
                # Starts new thread that waits for ACK or RST
                #start_new_thread(threaded, (listen, source_mac, target_port,))

            # Stealth scan / TCP FIN handling
            #elif (flags == FLAGS_FIN):
                #print("!! RECEIVED STEALTH SCAN/TCP FIN FROM MAC ADDRESS {} on port {} !!".format(source_mac, target_port))

            # SYN/ACK attack handling
            #elif (flags == FLAGS_SYN_ACK):
                #print("!! RECEIVED SYN/ACK ATTACK FROM MAC ADDRESS {} on port {} !!".format(source_mac, target_port))
    
        

if __name__ == "__main__":
    root = tk.Tk()
    window = listenerWindow(root)
    window.listernerThread.start()
    root.mainloop()
    #listener()