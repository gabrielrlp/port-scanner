import tkinter as tk

from globalVars import *

class packet_storage:
    def __init__(self, packet, time, display):
        """
        Stores several information about an ip packet
        """
        # Stores raw packet
        self.packet = packet
        # Stores datetime object
        self.time = time
        # MAC and IP
        self.smac = self.packet[ 0: 6].hex()
        self.dmac = self.packet[ 6:12].hex()
        self.sip  = self.packet[22:38].hex()
        self.dip  = self.packet[38:54].hex()
        self.dport_len = 0
        # Defines whats used as commom variable (not ready)
        self.index = self.sip


        # List of ports that this entity
        self.sport = []
        self.sport.append(self.packet[54:56].hex())
        # List of ports reached by this entity
        self.dport = []
        self.dport.append(self.packet[56:58].hex())

        self.lockWarningFlags = False
        self.showDPortWarning = True
        self.showSYNACKWarning= True
        self.showSYNWarning = True
        self.showFINWarning = True
        self.showACKWarning = True
        self.showRSTWarning = True
        self.showStreamWarning = True
        self.showSPortWarning = True
        # Score that defines how dangerous this source is.
        self.warning_counter = 0
        self.var_warning_counter = tk.IntVar()
        self.var_warning_counter.set(self.warning_counter)

        # Fast test for multiple display lines
        if DEBUG_RANDOM_IPS: self.sip  = self.randomString(len(self.sip))

        self.frm_line = tk.Frame(display, width = 1280-436, height = 22, 
                                 bg = 'white smoke', highlightthickness = 1,
                                 highlightbackground = "#000000")
        self.lbl_ip = tk.Label(self.frm_line, width = 35, height = 1, 
                               text = self.formatIpString(self.index), 
                               bg = 'white smoke')
        self.dport_len = 1;
        self.var_dport_len = tk.IntVar()
        self.var_dport_len.set(len(self.dport))
        self.lbl_dport_len = tk.Label(self.frm_line, width = 5, height = 1,
                                      textvariable = self.var_dport_len, 
                                      bg = 'gainsboro')
        
        # Labels and variables that represent the number of times that 'X'
        #flag was used by 'Y' IPv6.
        self.var_synack_len = tk.IntVar()
        self.var_synack_len.set(0)
        self.lbl_synack_count = tk.Label(self.frm_line, width = 5, height = 1,
                                         textvariable = self.var_synack_len, 
                                         bg = 'white smoke')
        self.var_syn_len = tk.IntVar()
        self.var_syn_len.set(0)
        self.lbl_syn_count = tk.Label(self.frm_line, width = 5, height = 1,
                                      textvariable = self.var_syn_len,
                                      bg = 'white smoke')
        self.var_ack_len = tk.IntVar()
        self.var_ack_len.set(0)
        self.lbl_ack_count = tk.Label(self.frm_line, width = 5, height = 1,
                                      textvariable = self.var_ack_len, 
                                      bg = 'gainsboro')
        self.var_rst_len = tk.IntVar()
        self.var_rst_len.set(0)
        self.lbl_rst_count = tk.Label(self.frm_line, width = 5, height = 1,
                                      textvariable = self.var_rst_len,
                                      bg = 'white smoke')
        self.var_fin_len = tk.IntVar()
        self.var_fin_len.set(0)
        self.lbl_fin_count = tk.Label(self.frm_line, width = 5, height = 1,
                                      textvariable = self.var_fin_len,
                                      bg = 'gainsboro')
        # Displays the time that the packet was processed
        self.var_timestamp = tk.StringVar()
        self.var_timestamp.set(str(time).split(' ',1)[1])
        self.lbl_timestamp = tk.Label(self.frm_line, width = 16, height = 1,
                                      textvariable = self.var_timestamp,
                                      bg = 'white smoke')
        # Displays the average time interval between each packet sent
        self.var_avg_interval = tk.StringVar()
        self.var_avg_interval.set("0.0")
        self.lbl_avg_intervarl = tk.Label(self.frm_line, width = 19,
                                          height = 1,
                                          textvariable=self.var_avg_interval,
                                          bg = 'gainsboro')

        self.frm_line.place(     x = 0,        y = 0)
        self.lbl_ip.place(       x = 5,        y = 0)
        self.lbl_dport_len.place(x = 289,      y = 0)
        self.lbl_synack_count.place( x = 289+44, y = 0)
        self.lbl_syn_count.place(x = 289+44*2, y = 0)
        self.lbl_ack_count.place(x = 289+44*3, y = 0)
        self.lbl_rst_count.place(x = 289+44*4, y = 0)
        self.lbl_fin_count.place(x = 289+44*5, y = 0)
        self.lbl_timestamp.place(x = 289+44*6, y = 0)
        self.lbl_avg_intervarl.place( x = 686, y = 0)

        self.update_flags(packet[67:68].hex())


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
        if flags == FLAGS_SYNACK:
            self.var_synack_len.set(self.var_synack_len.get()+1)
        elif flags == FLAGS_SYN:
            self.var_syn_len.set(self.var_syn_len.get()+1)
        elif flags == FLAGS_ACK:
            self.var_ack_len.set(self.var_ack_len.get()+1)
        if flags == FLAGS_RST:
            self.var_rst_len.set(self.var_rst_len.get()+1)
        if flags == FLAGS_FIN:
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
            new_avg_time = (new_dif_time+float(self.var_avg_interval.get())/2)
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


    # Checks if dport was already used by given ip packet
    def check_if_port_stored(self, packet):
        for p in self.dport:
            if p == packet[56:58].hex():
                return True
        return False
