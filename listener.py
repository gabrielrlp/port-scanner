import socket, sys, random, string
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
WND_RESOLUTION = "1280x680"
WND_TITLE      = "ListenerV6"

SHUTDOWN = False

PACKET_QUEUE = []
IPV6_LIST_IN = []

# Debug flags
DEBUG_RANDOM_IPS = 1

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


class packetStorage:
    def __init__(self, packet, time, display):
        """
        Stores several information about an ip packet
        """
        self.packet = packet
        # Stores datetime object
        self.time = time
        self.avginterval = 0
        self.smac = self.packet[ 0: 6].hex()
        self.dmac = self.packet[ 6:12].hex()
        self.sip  = self.packet[22:38].hex()
        self.dip  = self.packet[38:54].hex()

        self.sport = []
        self.sport.append(self.packet[54:56].hex())
        self.dport = []
        self.dport.append(self.packet[56:58].hex())

        if DEBUG_RANDOM_IPS: self.sip  = self.randomString(len(self.sip))

        self.frm_line = tk.Frame(display, width = 1280-476, height = 20, bg = 'white smoke')
        #"fe80::0000:0000:0000:a61f:a61f:a61f"
        self.lbl_ip = tk.Label(self.frm_line, width = 35, text = self.formatIpString(self.sip), bg = 'white smoke')
        self.var_dport_len = tk.IntVar()
        self.var_dport_len.set(len(self.dport))
        self.lbl_dport_len = tk.Label(self.frm_line, width = 5, textvariable = self.var_dport_len, bg = 'gainsboro')
        
        # Labels and variables that represent the number of times that 'X' flag was used by 'Y' IPv6.
        self.var_syn_len = tk.IntVar()
        self.var_syn_len.set(0)
        self.lbl_syn_count = tk.Label(self.frm_line, width = 5, textvariable = self.var_syn_len, bg = 'white smoke')
        self.var_ack_len = tk.IntVar()
        self.var_ack_len.set(0)
        self.lbl_ack_count = tk.Label(self.frm_line, width = 5, textvariable = self.var_ack_len, bg = 'gainsboro')
        self.var_rst_len = tk.IntVar()
        self.var_rst_len.set(0)
        self.lbl_rst_count = tk.Label(self.frm_line, width = 5, textvariable = self.var_rst_len, bg = 'white smoke')
        self.var_fin_len = tk.IntVar()
        self.var_fin_len.set(0)
        self.lbl_fin_count = tk.Label(self.frm_line, width = 5, textvariable = self.var_fin_len, bg = 'gainsboro')
        # Displays the time that the packet was processed
        self.var_timestamp = tk.StringVar()
        self.var_timestamp.set(str(time).split(' ',1)[1])
        self.lbl_timestamp = tk.Label(self.frm_line, width = 16, textvariable = self.var_timestamp, bg = 'white smoke')
        # Displays the average time interval between each packet sent
        self.var_avg_interval = tk.StringVar()
        self.var_avg_interval.set("0.0")
        self.lbl_avg_intervarl= tk.Label(self.frm_line, width = 21, textvariable = self.var_avg_interval, bg = 'gainsboro')

        self.frm_line.place(     x = 0,        y = 0)
        self.lbl_ip.place(       x = 5,        y = 0)
        self.lbl_dport_len.place(x = 289,      y = 0)
        self.lbl_syn_count.place(x = 289+44,   y = 0)
        self.lbl_ack_count.place(x = 289+44*2, y = 0)
        self.lbl_rst_count.place(x = 289+44*3, y = 0)
        self.lbl_fin_count.place(x = 289+44*4, y = 0)
        self.lbl_timestamp.place(x = 289+44*5, y = 0)
        self.lbl_avg_intervarl.place( x = 642, y = 0)

        self.updateFlags(packet[66:68].hex())


    def addPort(self, port):
        self.dport.append(port)
        self.var_dport_len.set(len(self.dport))


    def updateFlags(self, flags):
        if int(flags)&FLAGS_SYN:
            self.var_syn_len.set(self.var_syn_len.get()+1)
        if int(flags)&FLAGS_ACK:
            self.var_ack_len.set(self.var_ack_len.get()+1)
        if int(flags)&FLAGS_RST:
            self.var_rst_len.set(self.var_rst_len.get()+1)
        if int(flags)&FLAGS_FIN:
            self.var_fin_len.set(self.var_fin_len.get()+1)


    def updateTimestamp(self, time):
        """
        Updates time related values when a packet is received
        """
        # Calculates old timestamp in seconds
        old_time  = self.time.microsecond / 1000000000
        old_time += self.time.second
        old_time += self.time.minute * 60
        old_time += self.time.hour * 360
        # Calculates new timestamp in seconds
        new_time  = time.microsecond / 1000000000
        new_time += time.second
        new_time += time.minute * 60
        new_time += time.hour * 360
        # Calculates the difference between old timestamp and new timestamp
        new_dif_time = new_time - old_time
        # Initial value check
        if self.var_avg_interval.get() == "0.0":
            out = "{0:.9f}".format(new_dif_time)
            self.var_avg_interval.set(out)
        else:
            new_avg_time = (new_dif_time + float(self.var_avg_interval.get()) / 2)
            out = "{0:.9f}".format(new_avg_time)
            self.var_avg_interval.set(out)
        # Update old timestamp
        self.time = time


    def randomString(self, stringLength):
        """Generate a random string of fixed length """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(stringLength))


    def formatIpString(self, ip):
        sa = (ip[ 0: 4]+"::"+
              ip[ 4: 8]+":" +
              ip[ 8:12]+":" +
              ip[12:16]+":" +
              ip[16:20]+":" +
              ip[24:28]+":" +
              ip[28:32])
        return sa


    # Checks if IP is already stored, returns true if it is
    def checkIfIpStored(self, packet):
        global IPV6_LIST_IN
        # Check if ipv6 list is empty
        if IPV6_LIST_IN == []:
            return False
        elif self.sip == packet[22:38].hex():
            return True
        return False



    # Checks if dport was already used by given ip packet
    def checkIfPortStored(self, packet):
        global IPV6_LIST_IN
        for p in self.dport:
            if p == packet[56:58].hex():
                return True
        return False


class listenerWindow:
    def __init__(self, master):
        """
        Defines the window and main functionalities of the software
        """
        self.master = master
        # Flag for incoming packet
        self.var_new_packet = tk.BooleanVar()
        self.var_new_packet.set(False)
        self.var_new_packet.trace('w', self.handlePacketQueue)
        # Basic window configuration
        self.master.title(WND_TITLE)
        self.master.geometry(WND_RESOLUTION)
        self.w, self.h = WND_RESOLUTION.split("x",1)
        self.w, self.h = int(self.w), int(self.h)
        # Thread that represents the listener
        self.listernerThread = threading.Thread(target = self.listener)
        # Main frame, parent of all widgets
        self.frmMain = tk.Frame(master, width = self.w, height = self.h, bg = 'white')
        # Meaning of each field on the window connections display
        #subtitles  ="                                    Port                              Last             Average        \n"
        #subtitles +="                 IPv6               range #SYN  #ACK #RST  #FIN     Timestamp          interval        "
        subtitles  ="                                    Port                              Last        Average interval     \n"
        subtitles +="                 IPv6               range #SYN  #ACK #RST  #FIN     Timestamp     between  packets     "
        self.lbl_subtitles = tk.Label(self.frmMain, width = 100, text = subtitles, bg = 'white', anchor = tk.W, justify = tk.LEFT, highlightthickness = 3, highlightbackground = 'silver' )
        # Display frame, where informations about connections are displayed
        self.frm_display = tk.Frame(self.frmMain, width = (self.w-470), height = (self.h-60), bg = 'white smoke', highlightthickness = 3, highlightbackground = 'silver')
        # Button to exit the software
        self.btnCloseApp = tk.Button(self.frmMain, text="Exit", command = self.quitListener, height = 2, width = 6, bg = 'white', activebackground = 'white smoke' )
        # Placement of widgets
        self.frmMain.place(x = 0, y = 0)
        self.lbl_subtitles.place( x = 10, y = 10)
        self.frm_display.place( x = 10, y = 50 )
        self.btnCloseApp.place(x = 1195, y = (self.h-55))


    def updateLabelGrid(self):
        """
        Updates the placement of lines on the connections display
        """
        aux = 0;
        for pckt in IPV6_LIST_IN:
            pckt.frm_line.pack_forget()
            pckt.frm_line.place(x = 0, y = (0 + 20*aux))
            aux += 1


    def quitListener(self):
        """
        Raise SHUTDOWN flag, close listener thread and shut down tkinter window.
        """

        global SHUTDOWN
        SHUTDOWN = 1
        self.listernerThread.join()
        self.master.quit()



    def handlePacketQueue(self, *args):
        """
        Callback for the new packet flag. Process packets on queue
        """
        if self.var_new_packet.get():
            while len(PACKET_QUEUE) > 0:
                # Selects a packet to proccess and removes it from the list
                packet = PACKET_QUEUE.pop()
                time = datetime.now()
                # If there no objects on list, immediately creates ones
                if IPV6_LIST_IN == []:
                    IPV6_LIST_IN.append(packetStorage(packet, time, self.frm_display))
                else:
                    for p in IPV6_LIST_IN:
                        # If a packet of this source is not present on the list, create a storage object for it
                        if not p.checkIfIpStored(packet):
                            IPV6_LIST_IN.append(packetStorage(packet, time, self.frm_display))
                            break# DOUBLE TEST THIS BREAK
                        # If source already has a storage object and this port was not previously used, add port
                        #to list and update flags/timestamp
                        elif not p.checkIfPortStored(packet):
                            p.addPort((packet[56:58].hex()))
                            p.updateFlags(packet[66:68].hex())
                            p.updateTimestamp(time)
                            break
                        # In most cases, repeated packets will end up here. Update flags/timestamp
                        else:
                            p.updateFlags(packet[66:68].hex())
                            p.updateTimestamp(time)
                self.updateLabelGrid()

            self.var_new_packet.set(False)


    def listener(self):
        """
        This listener represents the main attack detection component.
        """
        global SHUTDOWN
        global IPV6_LIST_IN
        # Creates raw socket
        listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

        # Main loop
        while not SHUTDOWN:
            # We should put this packet receiving code inside a single function for reusability

            # Receive packet
            raw_packet = listen.recvfrom(65565)
            packet = raw_packet[0]

            # Get ethernet header
            eth_header = packet[0:14]

            # Get protocol type; 0x86dd for IPv6
            protocol_type = unpack('!6B6BH', eth_header)[12]

            next_header = (packet.hex()[40:42])
            #self.var_new_packet.set(False)
            # Check if TCP IPv6
            if (protocol_type == int(PROTOCOL_TYPE_IPV6) and next_header == "06"):
                # Add packet to queue
                PACKET_QUEUE.append(packet)
                self.var_new_packet.set(True)


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

def lisssstener(wnd):
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
    root.option_add("*Font", "courier 10")
    window = listenerWindow(root)
    window.listernerThread.start()
    root.mainloop()
    #listener()