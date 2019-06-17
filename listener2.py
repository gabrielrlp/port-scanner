# Authors:
import socket, sys, random, string
from packetStorage import *
from globalVars import *
from struct import *
from _thread import *
import threading
from datetime import timedelta
from datetime import datetime
# Tkinter documentation http://effbot.org/tkinterbook/
import tkinter as tk


class listener_window:
    def __init__(self, master):
        """
        Defines the window and main functionalities of the software
        """
        master.bind('<Escape>', self.quit_listener)
        master.protocol("WM_DELETE_WINDOW", self.quit_listener)
        self.master = master
        # Flag for incoming packet
        self.var_new_packet = tk.BooleanVar()
        self.var_new_packet.set(False)
        self.var_new_packet.trace('w', self.handle_packet_queue)
        # Basic window configuration
        self.master.title(WND_TITLE)
        self.master.geometry(WND_RESOLUTION)
        self.w, self.h = WND_RESOLUTION.split("x",1)
        self.w, self.h = int(self.w), int(self.h)
        self.display_width = self.w-414
        # Thread that represents the listener
        self.listener_thread = threading.Thread(target = self.listener)
        # Thread that represents the connection monitor
        self.monitor_thread = threading.Thread(target = self.connection_monitor)
        # Main frame, parent of all widgets
        self.frm_main = tk.Frame(master = master,
                                 width = self.w,
                                 height = self.h,
                                 bg = 'white')
        # Meaning of each field on the window connections display
        upper_line  = "                                    Port"
        upper_line += "  #SYN"
        upper_line += "                            Last"
        upper_line += "         Average interval"
        upper_line += "     \n"
        lower_line  = "                IPv6"
        lower_line += "               range"
        lower_line += " /ACK"
        lower_line += " #SYN"
        lower_line += "  #ACK"
        lower_line += " #RST"
        lower_line += "  #FIN"
        lower_line += "     Timestamp"
        lower_line += "      between"
        lower_line += "  packets"
        subtitles = upper_line + lower_line
        #subtitles  ="                                    Port  #SYN          "
        #subtitles +="                  Last         Average interval     \n"
        #subtitles +="                IPv6               range /ACK #SYN  #ACK"
        #subtitles +=" #RST  #FIN     Timestamp      between  packets     "
        self.lbl_subtitles = tk.Label(master = self.frm_main, 
                                      width = 107, 
                                      text = subtitles, bg = 'white',
                                      justify = tk.LEFT, anchor = tk.W,
                                      highlightthickness = 3, 
                                      highlightbackground = 'silver')
        # Display frame, where informations about connections are displayed
        self.frm_display = tk.Frame(master = self.frm_main,
                                    width = self.display_width,
                                    height = (self.h - 336),
                                    bg = 'white smoke',
                                    highlightthickness = 3,
                                    highlightbackground = 'silver')
        # Frame where text warnings are displayed
        self.frm_console = tk.Frame(master = self.frm_main,
                                    width = self.display_width, height = 280,
                                    bg = 'white',
                                    highlightthickness = 3,
                                    highlightbackground = 'silver')
        self.scr_console = tk.Scrollbar(self.frm_console)
        self.txt_console = tk.Text(master = self.frm_console,
                                   width = 120, height = 19,
                                   font = ("courier", "9"))
        # Button to exit the software
        self.btn_close = tk.Button(self.frm_main, text="Exit",
                                   command = self.quit_listener,
                                   height = 2, width = 6,
                                   bg = 'white',
                                   activebackground = 'white smoke' )
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
        Sorts and updates the placement of lines on the connections display
        """
        ## TODO: test sort modes
        global PACKET_OBJECT_LIST, SORT_MODE, SHUTDOWN
        # Sort by number of unique ports scaned
        if SORT_MODE == SORT_DICT["PORT_RANGE"]:
            key = lambda packet_storage: packet_storage.dport_len
            PACKET_OBJECT_LIST.sort(key=key, reverse = True)
        # Sort by number of warning flags raised
        elif SORT_MODE == SORT_DICT["DANGEROUSNESS"]:
            key = lambda packet_storage: packet_storage.warning_counter
            PACKET_OBJECT_LIST.sort(key=key, reverse = True)

        aux = 0;
        for pckt in PACKET_OBJECT_LIST:
            if SHUTDOWN:
                break
            ## TODO: sort here???
            # Remove lines from display
            pckt.frm_line.pack_forget()
            # Calculates border color based on the warning counter
            if pckt.var_warning_counter.get() > 0xff:
                c = "#ff0000"
            else:
                c = hex(pckt.var_warning_counter.get())
                c = c.ljust(8, '0')
                c = "#{:>6}".format(c[2:])
            # Sets border color and places line back on display
            pckt.frm_line.config(highlightbackground = c)
            pckt.frm_line.place(x = 0, y = (0 + 20*aux))
            aux += 1


    def quit_listener(self):
        """
        Raise SHUTDOWN flag, close listener thread and
        shut down tkinter window.
        """
        global SHUTDOWN
        SHUTDOWN = 1
        self.listener_thread.join()
        self.master.quit()


    # Checks if IP is already stored, returns true if it is
    def check_if_ip_stored(self, packet):
        global PACKET_OBJECT_LIST
        # Check if ipv6 list is empty
        if PACKET_OBJECT_LIST == []:
            return False
        for p in PACKET_OBJECT_LIST:
            if p.sip == packet[22:38].hex():
                return True
        return False


    def handle_packet(self, packet, time):
        """
        Process packets on queue.
        """
        global PACKET_OBJECT_LIST
        # If there no objects on list, immediately creates ones.
        if PACKET_OBJECT_LIST == []:
            PACKET_OBJECT_LIST.append((packet_storage(packet,
                                                      time,
                                                      self.frm_display)))
        else:
            # If a packet of this source is not present on the list,
            #create a storage object for it.
            if not self.check_if_ip_stored(packet):
                PACKET_OBJECT_LIST.append((packet_storage(packet,
                                                          time,
                                                          self.frm_display)))
                return# DOUBLE TEST THIS BREAK
            else:
                for p in PACKET_OBJECT_LIST:
                    # If source already has a storage object and this port was
                    #not previously used,  add port  to list and  update flags
                    #and timestamp
                    if p.sip == packet[22:38].hex():
                        if not p.check_if_port_stored(packet):
                            p.add_port((packet[56:58].hex()))
                            p.update_flags(packet[67:68].hex())
                            p.update_timestamp(time)
                        # In most cases, repeated packets will end up here.
                        #Update flags/timestamp
                        else:
                            p.update_flags(packet[67:68].hex())
                        p.update_timestamp(time)
                        return


    def handle_packet_queue(self, *args):
        """
        Callback for var_new_flag.
        """
        global SHUTDOWN, PACKET_OBJECT_LIST
        if self.var_new_packet.get():
            while len(PACKET_QUEUE) > 0:
                # Selects a packet to proccess and removes it from the list
                if SHUTDOWN:
                    break

                packet = PACKET_QUEUE.pop()

                time = datetime.now()

                self.handle_packet(packet, time)

                self.update_label_grid()

            self.var_new_packet.set(False)


    def echo(self, text):
        self.txt_console.insert(tk.END, text)


    def listener(self):
        """
        This listener represents the main attack detection component.
        """
        global SHUTDOWN
        global PACKET_OBJECT_LIST
        # Creates raw socket
        listen = socket.socket(socket.AF_PACKET,
                               socket.SOCK_RAW,
                               socket.htons(3))
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
            if (protocol_type == int(PROTOCOL_TYPE_IPV6) and
                  next_header == "06"):

                # ip randomizer
                #packet = str(packet)
                #packet = packet[3:25]
                #       + str((random.randint(0,2)))[0]
                #       + packet[26:-1]
                #length = len(packet)
                #packet = packet.encode(encoding = 'UTF-8')

                # Add packet to queue
                PACKET_QUEUE.append(packet)
                self.var_new_packet.set(True)

        self.monitor_thread.join()


    def connection_monitor(self):
        """
        Thread responsible for controlling warning flags and connection
        information
        """

        global SHUTDOWN, DPORT_LIMIT, STREAM_INTERVAL_LIMIT
        global PACKET_OBJECT_LIST, FLAG_TIMEOUT, SYN_LIMIT
        global ACK_LIMIT, FIN_LIMIT, RST_LIMIT, SPORT_LIMIT

        while not SHUTDOWN:
            # Calculates present time in seconds
            time = datetime.now()
            new_time  = time.microsecond / 1000000000
            new_time += time.second
            new_time += time.minute * 60
            new_time += time.hour * 360
            # For all packet objects
            for p in PACKET_OBJECT_LIST:
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
                    p.showSYNACKWarning = True
                    p.showSYNWarning = True
                    p.showFINWarning = True
                    p.showACKWarning = True
                    p.showRSTWarning = True
                    p.showStreamWarning = True
                    p.showSPortWarning = True
                    if RESET_FLAGS_TIMEOUT:
                        p.var_synack_len.set(0)
                        p.var_syn_len.set(0)
                        p.var_ack_len.set(0)
                        p.var_fin_len.set(0)
                        p.var_rst_len.set(0)

                # Prevents idle packets
                if not p.lockWarningFlags:
                    # Check for multiple port scanning
                    if len(p.dport) > DPORT_LIMIT and p.showDPortWarning:
                        self.echo(p.formatIpString(p.sip)
                                + " scanning multiple ports.\n" );
                        p.showDPortWarning = False
                    # Check for suspicions behavior(changing source port)
                    if len(p.sport) > SPORT_LIMIT and p.showSPortWarning:
                        self.echo(p.formatIpString(p.sip
                                + " suspicious behavior. Multiple packets"
                                + " from different ports.\n" ))
                        p.showSPortWarning = False                        
                    # Checks for fast stream of packets
                    if (float(p.var_avg_interval.get()) < STREAM_INTERVAL_LIMIT
                            and (p.var_avg_interval.get()!="0.0")
                            and (p.showStreamWarning)):
                        self.echo(p.formatIpString(p.sip)
                                + " sending packet stream with average"
                                + " interval of " + p.var_avg_interval.get()
                                + " seconds.\n")
                        p.showStreamWarning = False
                    # Check for types of attacks                    
                    # SYNACK    
                    if (p.var_synack_len.get() > SYNACK_LIMIT
                            and p.showSYNACKWarning): 
                        self.echo(p.formatIpString(p.sip) + " sent over "
                                + str(SYNACK_LIMIT)
                                + " SYN packets. Possible SYNACK attack.\n")    
                        p.showSYNACKWarning = False
                    # TCP Fin(Stealth Scan
                    if (p.var_fin_len.get() > FIN_LIMIT 
                            and p.showFINWarning):
                        self.echo(p.formatIpString(p.sip) + " sent over "
                                + str(FIN_LIMIT)
                                + " FIN packets. Possible TCP Stealth"
                                + " Scan attack.\n")
                        p.showFINWarning = False
                    if p.var_syn_len.get() > SYN_LIMIT:
                        if p.showSYNWarning:
                            self.echo(p.formatIpString(p.sip) + " sent over "
                                    + str(SYN_LIMIT) + " SYN packets.\n")
                            p.showSYNWarning = False
                        # TCP Half Openning
                        if (p.var_rst_len.get() > RST_LIMIT
                                and p.showRSTWarning):
                            self.echo(p.formatIpString(p.sip) + " sent over "
                                    + str(RST_LIMIT)
                                    + " RST packets. Possible TCP Half"
                                    + " Openning attack.\n")
                            p.showRSTWarning = False
                        # TCP connect
                        if (p.var_ack_len.get() > ACK_LIMIT
                                and p.showACKWarning):
                            self.echo(p.formatIpString(p.sip) + " sent over "
                                    + str(ACK_LIMIT)
                                    + " ACK packets. Possible TCP Connect"
                                    + " attack.\n")
                            p.showACKWarning = False

                    # Calculates the 'warning count score'
                    this_warning_count = 0
                    p.dport_len = p.var_dport_len.get()
                    if not(p.showDPortWarning):
                        this_warning_count += p.dport_len
                    this_warning_count += (10*p.showSYNACKWarning +
                                           10*p.showSYNWarning +
                                           10*p.showFINWarning +
                                           10*p.showACKWarning +
                                           10*p.showRSTWarning +
                                           10*p.showStreamWarning +
                                           25*p.showSPortWarning)
                    p.warning_count = this_warning_count
                    p.var_warning_counter.set(this_warning_count)


if __name__ == "__main__":
    print("check tcp connect and half oppenning. check sort modes. check SHUTDOWN values for threads")
    root = tk.Tk()
    root.option_add("*Font", "courier 10")
    window = listener_window(root)
    window.listener_thread.start()
    root.mainloop()