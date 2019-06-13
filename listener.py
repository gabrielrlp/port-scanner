import socket, sys, random, string
from struct import *
from _thread import *
import threading
from datetime import timedelta
from datetime import datetime
import tkinter as tk

## IPv6 type from ethernet header
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

## Limits and tresholds
# Number of different ports that have to be scanned to be cosireder harmfull
DPORT_LIMIT = 5
SPORT_LIMIT = 5
# Socket stream interval threshold for fast stream warning
STREAM_INTERVAL_LIMIT = 0.01
# Show warning after this number of repeated flags
SYN_LIMIT   = 5
FIN_LIMIT   = 5
ACK_LIMIT   = 5
RST_LIMIT   = 5
# After this period(seconds), warning flags will be reseted
FLAG_TIMEOUT= 10

## General
# Window configuration
WND_RESOLUTION = "1280x680"
WND_TITLE      = "ListenerV6"
# If raised, will shut down everything
SHUTDOWN = False
# Stores packets to be processed
PACKET_QUEUE = []
# List of objects that represents received IPv6 TCP packets
IPV6_LIST_IN = []
# Debug flags
DEBUG_RANDOM_IPS = 0


class packet_storage:
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

        # List of ports that this ip came from
        self.sport = []
        self.sport.append(self.packet[54:56].hex())
        # List of ports targeted by this ip
        self.dport = []
        self.dport.append(self.packet[56:58].hex())

        self.lockWarningFlags = False
        self.showDPortWarning = True
        self.showSYNWarning = True
        self.showFINWarning = True
        self.showACKWarning = True
        self.showRSTWarning = True
        self.showStreamWarning = True
        self.showSPortWarning = True

        # Fast test for multiple display lines
        if DEBUG_RANDOM_IPS: self.sip  = self.randomString(len(self.sip))

        self.frm_line = tk.Frame(display, width = 1280-476, height = 20, bg = 'white smoke')
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

        self.update_flags(packet[66:68].hex())


    def add_port(self, port):
        """
        Add port to list
        """
        self.dport.append(port)
        self.var_dport_len.set(len(self.dport))


    def update_flags(self, flags):
        """
        Updates flag counter and idle lock
        """
        self.lockWarningFlags = False
        if int(flags)&FLAGS_SYN:
            self.var_syn_len.set(self.var_syn_len.get()+1)
        if int(flags)&FLAGS_ACK:
            self.var_ack_len.set(self.var_ack_len.get()+1)
        if int(flags)&FLAGS_RST:
            self.var_rst_len.set(self.var_rst_len.get()+1)
        if int(flags)&FLAGS_FIN:
            self.var_fin_len.set(self.var_fin_len.get()+1)


    def update_timestamp(self, time):
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
        """
        Returns a random string of fixed length. Debug puposes
        """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(stringLength))


    def formatIpString(self, ip):
        """
        Returns a formated IPv6 string from packet
        """
        sa = (ip[ 0: 4]+"::"+
              ip[ 4: 8]+":" +
              ip[ 8:12]+":" +
              ip[12:16]+":" +
              ip[16:20]+":" +
              ip[24:28]+":" +
              ip[28:32])
        return sa


    # Checks if IP is already stored, returns true if it is
    def check_if_ip_stored(self, packet):
        global IPV6_LIST_IN
        # Check if ipv6 list is empty
        if IPV6_LIST_IN == []:
            return False
        elif self.sip == packet[22:38].hex():
            return True
        return False



    # Checks if dport was already used by given ip packet
    def check_if_port_stored(self, packet):
        global IPV6_LIST_IN
        for p in self.dport:
            if p == packet[56:58].hex():
                return True
        return False


class listener_window:
    def __init__(self, master):
        """
        Defines the window and main functionalities of the software
        """
        self.master = master
        # Flag for incoming packet
        self.var_new_packet = tk.BooleanVar()
        self.var_new_packet.set(False)
        self.var_new_packet.trace('w', self.handle_packet_quere)
        # Basic window configuration
        self.master.title(WND_TITLE)
        self.master.geometry(WND_RESOLUTION)
        self.w, self.h = WND_RESOLUTION.split("x",1)
        self.w, self.h = int(self.w), int(self.h)
        # Thread that represents the listener
        self.listener_thread = threading.Thread(target = self.listener)
        # Thread that represents the connection monitor
        self.monitor_thread = threading.Thread(target = self.connection_monitor)
        # Main frame, parent of all widgets
        self.frm_main = tk.Frame(master, width = self.w, height = self.h, bg = 'white')
        # Meaning of each field on the window connections display
        subtitles  ="                                    Port                              Last        Average interval     \n"
        subtitles +="                 IPv6               range #SYN  #ACK #RST  #FIN     Timestamp     between  packets     "
        self.lbl_subtitles = tk.Label(self.frm_main, width = 100, text = subtitles, bg = 'white', anchor = tk.W, justify = tk.LEFT, highlightthickness = 3, highlightbackground = 'silver' )
        # Display frame, where informations about connections are displayed
        self.frm_display = tk.Frame(self.frm_main, width = (self.w-470), height = (self.h-336), bg = 'white smoke', highlightthickness = 3, highlightbackground = 'silver')
        # Frame where text warnings are displayed
        self.frm_console = tk.Frame(self.frm_main, width = (self.w-470), height = (280), bg = 'white', highlightthickness = 3, highlightbackground = 'silver')
        self.scr_console = tk.Scrollbar(self.frm_console)
        self.txt_console = tk.Text(self.frm_console, width = 112, height = 19, font = ("courier", "9"))
        # Button to exit the software
        self.btn_close = tk.Button(self.frm_main, text="Exit", command = self.quit_listener, height = 2, width = 6, bg = 'white', activebackground = 'white smoke' )
        # Placement of widgets
        self.frm_main.place(x = 0, y = 0)
        self.lbl_subtitles.place( x = 10, y = 10)
        self.frm_display.place( x = 10, y =  50 )
        self.frm_console.place( x = 10, y = 392 )
        #self.txt_console.place( x =  0, y =   0 )
        self.txt_console.pack(side = tk.LEFT, fill = tk.Y)
        self.scr_console.pack(side = tk.RIGHT, fill = tk.Y)
        self.scr_console.config(command = self.txt_console.yview)
        self.txt_console.config(yscrollcommand = self.scr_console.set)
        self.btn_close.place(x = 1195, y = (self.h-55))


    def update_label_grid(self):
        """
        Updates the placement of lines on the connections display
        """
        aux = 0;
        for pckt in IPV6_LIST_IN:
            pckt.frm_line.pack_forget()
            pckt.frm_line.place(x = 0, y = (0 + 20*aux))
            aux += 1


    def quit_listener(self):
        """
        Raise SHUTDOWN flag, close listener thread and shut down tkinter window.
        """

        global SHUTDOWN
        SHUTDOWN = 1
        self.listener_thread.join()
        self.master.quit()



    def handle_packet_quere(self, *args):
        """
        Callback for the new packet flag. Process packets on queue
        """
        global SHUTDOWN, IPV6_LIST_IN
        if self.var_new_packet.get():
            while len(PACKET_QUEUE) > 0:
                # Selects a packet to proccess and removes it from the list
                if SHUTDOWN:
                    break
                packet = PACKET_QUEUE.pop()
                time = datetime.now()
                # If there no objects on list, immediately creates ones
                if IPV6_LIST_IN == []:
                    IPV6_LIST_IN.append(packet_storage(packet, time, self.frm_display))
                else:
                    for p in IPV6_LIST_IN:
                        # If a packet of this source is not present on the list, create a storage object for it
                        if not p.check_if_ip_stored(packet):
                            IPV6_LIST_IN.append(packet_storage(packet, time, self.frm_display))
                            break# DOUBLE TEST THIS BREAK
                        # If source already has a storage object and this port was not previously used, add port
                        #to list and update flags/timestamp
                        elif not p.check_if_port_stored(packet):
                            p.add_port((packet[56:58].hex()))
                            p.update_flags(packet[66:68].hex())
                            p.update_timestamp(time)
                            break
                        # In most cases, repeated packets will end up here. Update flags/timestamp
                        else:
                            p.update_flags(packet[66:68].hex())
                            p.update_timestamp(time)
                self.update_label_grid()

            self.var_new_packet.set(False)


    def echo(self, text):
        self.txt_console.insert(tk.END, text)


    def listener(self):
        """
        This listener represents the main attack detection component.
        """
        global SHUTDOWN
        global IPV6_LIST_IN
        # Creates raw socket
        listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

        self.monitor_thread.start()

        # Main loop
        while not SHUTDOWN:
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

        self.monitor_thread.join()


    def connection_monitor(self):
        """
        Thread responsible for controlling warning flags and connection information
        """

        global SHUTDOWN, DPORT_LIMIT, STREAM_INTERVAL_LIMIT, IPV6_LIST_IN, FLAG_TIMEOUT
        global SYN_LIMIT, ACK_LIMIT, FIN_LIMIT, RST_LIMIT, SPORT_LIMIT

        while not SHUTDOWN:
            # Calculates present time in seconds
            time = datetime.now()
            new_time  = time.microsecond / 1000000000
            new_time += time.second
            new_time += time.minute * 60
            new_time += time.hour * 360
            # For all packet objects
            for p in IPV6_LIST_IN:
                # Calculates old packet time in seconds
                old_time  = p.time.microsecond / 1000000000
                old_time += p.time.second
                old_time += p.time.minute * 60
                old_time += p.time.hour * 360
                # If packet was not recently updated, reset warning flags
                if (new_time - old_time) > FLAG_TIMEOUT:
                    # Lock warnings until next packet is received
                    p.lockWarningFlags = True
                    # Reset flags
                    p.showDPortWarning = True
                    p.showSYNWarning = True
                    p.showFINWarning = True
                    p.showACKWarning = True
                    p.showRSTWarning = True
                    p.showStreamWarning = True
                    p.showSPortWarning = True
                # Prevents idle packets
                if not p.lockWarningFlags:
                    # Check for multiple port scanning
                    if len(p.dport) > DPORT_LIMIT:
                        if p.showDPortWarning:
                            self.echo("Warning: "+p.formatIpString(p.sip)+" scanning multiple ports.\n" );
                            p.showDPortWarning = False
                    # Check for suspicions behavior(changing source port)
                    if len(p.sport) > SPORT_LIMIT:
                        if p.showSPortWarning:
                            self.echo("Warning: "+p.formatIpString(p.sip)+" suspicious behavior. Multiple packets from different ports.\n" );
                            p.showSPortWarning = False                        
                    # Checks for fast stream of packets
                    if float(p.var_avg_interval.get()) < STREAM_INTERVAL_LIMIT:
                        if p.showStreamWarning:
                            self.echo("Warning: "+p.formatIpString(p.sip)+" sending packet stream with average interval of "+p.var_avg_interval.get()+" seconds.\n")
                            p.showStreamWarning = False
                    # Check for types of attacks                    
                    if p.var_syn_len.get() > SYN_LIMIT:
                        if p.showSYNWarning:
                            self.echo("Warning: "+p.formatIpString(p.sip)+" sent over "+str(SYN_LIMIT)+" SYN packets. Possible TCP Connect attack.\n")
                            # TCP Connect
                            # TCP Half Openning
                            p.showSYNWarning = False
                    if p.var_fin_len.get() > FIN_LIMIT:
                        if p.showFINWarning:
                            # TCP Fin(Stealth Scan
                            self.echo("Warning: "+p.formatIpString(p.sip)+" sent over "+str(FIN_LIMIT)+" FIN packets. Possible TCP Stealth Scan attack.\n")
                            p.showFINWarning = False
                    if p.var_ack_len.get() > ACK_LIMIT:
                        if p.showACKWarning:
                            # TCP SYN/ACK
                            self.echo("Warning: "+p.formatIpString(p.sip)+" sent over "+str(ACK_LIMIT)+" ACK packets. Possible SYN/ACK attack.\n")
                            p.showACKWarning = False
                    if p.var_rst_len.get() > RST_LIMIT:
                        if p.showRSTWarning:
                            # TCP Half Openning
                            self.echo("Warning: "+p.formatIpString(p.sip)+" sent over "+str(RST_LIMIT)+" RST packets. Possible TCP Half Openning attack.\n")
                            p.showRSTWarning = False


if __name__ == "__main__":
    root = tk.Tk()
    root.option_add("*Font", "courier 10")
    window = listener_window(root)
    window.listener_thread.start()
    root.mainloop()