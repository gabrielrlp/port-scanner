import tkinter as tk

from globalVars import *

global u_SEC, MINUTE, HOUR

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
        # List that holds the last flags received
        self.flag_list = []

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
        self.tcp_connect_count = 0
        self.tcp_half_openning_count = 0
        # Score that defines how dangerous this source is.
        self.warning_counter = 0
        self.dport_len = 1;

        # Fast test for multiple display lines
        if DEBUG_RANDOM_IPS: self.sip  = self.randomString(len(self.sip))

        ## var_:TkinterVariables: are objects that have their values acessed by
        #get() and set().  They can have their own callbacks writen and bond to
        #them via trace('x', callback),  where 'x' is 'r' or 'w',  for read and 
        #write mode, respectively, and callback is a function.
        # Tkinter variable that represents the dangerousness score.
        self.var_warning_counter = tk.IntVar()
        # Tkinter  variable  that  represents  the  number of  different  ports
        #scanned
        self.var_dport_len = tk.IntVar()
        # Tkinter variables that represents the number of times  that 'X'  flag
        #was used by 'Y' IPv6.
        self.var_synack_len = tk.IntVar()
        self.var_syn_len = tk.IntVar()
        self.var_ack_len = tk.IntVar()
        self.var_rst_len = tk.IntVar()
        self.var_fin_len = tk.IntVar()
        # Tkinter variable that represents the timestamp displayed.
        self.var_timestamp = tk.StringVar()
        # Tkinter variable that represents the average interval between packets
        #displayed.
        self.var_avg_interval = tk.StringVar()

        # Set their default values
        self.var_warning_counter.set(self.warning_counter)
        self.var_dport_len.set(len(self.dport))
        self.var_synack_len.set(0)
        self.var_syn_len.set(0)
        self.var_ack_len.set(0)
        self.var_rst_len.set(0)
        self.var_fin_len.set(0)
        self.var_timestamp.set(str(time).split(' ',1)[1])
        self.var_avg_interval.set("0.0")

        ## Creates frames and labels that will display information.
        # Frame(line) that holds the widgets created bellow.
        self.frm_line = tk.Frame(master = display,
                                 width = 1280-436, height = 22, 
                                 bg = 'white smoke',
                                 highlightthickness = 1,
                                 highlightbackground = "#000000")

        # Displays IPv6.
        self.lbl_ip = tk.Label(self.frm_line, width = 35, height = 1, 
                               text = self.formatIpString(self.index), 
                               bg = 'white smoke')

        # Displays number of different ports scanned.
        self.lbl_dport_len = tk.Label(master = self.frm_line,
                                      width = 5, height = 1,
                                      textvariable = self.var_dport_len, 
                                      bg = 'gainsboro')

        # Displays number of SYNACK packets received.
        self.lbl_synack_count = tk.Label(master = self.frm_line,
                                         width = 5, height = 1,
                                         textvariable = self.var_synack_len, 
                                         bg = 'white smoke')

        # Displays number of SYN packets received.
        self.lbl_syn_count = tk.Label(master = self.frm_line,
                                      width = 5, height = 1,
                                      textvariable = self.var_syn_len,
                                      bg = 'white smoke')

        # Displays number of ACK packets received.
        self.lbl_ack_count = tk.Label(master = self.frm_line,
                                      width = 5, height = 1,
                                      textvariable = self.var_ack_len, 
                                      bg = 'gainsboro')

        # Displays number of RST packets received.
        self.lbl_rst_count = tk.Label(master = self.frm_line,
                                      width = 5, height = 1,
                                      textvariable = self.var_rst_len,
                                      bg = 'white smoke')

        # Displays number of FIN packets received.
        self.lbl_fin_count = tk.Label(master = self.frm_line,
                                      width = 5, height = 1,
                                      textvariable = self.var_fin_len,
                                      bg = 'gainsboro')

        # Displays the time that the packet was processed or modified.
        self.lbl_timestamp = tk.Label(master = self.frm_line,
                                      width = 16, height = 1,
                                      textvariable = self.var_timestamp,
                                      bg = 'white smoke')
        # Displays the average time interval between each packet received.
        self.lbl_interval = tk.Label(master = self.frm_line,
                                     width = 19,
                                     height = 1,
                                     textvariable = self.var_avg_interval,
                                     bg = 'gainsboro')

        # Places widgets on screen
        self.frm_line.place( x = 0, y = 0)
        self.lbl_ip.place( x = 5, y = 0)
        self.lbl_dport_len.place(x = 289, y = 0)
        self.lbl_synack_count.place( x = 289+44, y = 0)
        self.lbl_syn_count.place(x = 289+44*2, y = 0)
        self.lbl_ack_count.place(x = 289+44*3, y = 0)
        self.lbl_rst_count.place(x = 289+44*4, y = 0)
        self.lbl_fin_count.place(x = 289+44*5, y = 0)
        self.lbl_timestamp.place(x = 289+44*6, y = 0)
        self.lbl_interval.place(x = 686, y = 0)

        self.update_flags(packet[67:68].hex())


    def add_port(self, port):
        """
        Add port to list.
        """
        self.dport.append(port)
        self.var_dport_len.set(len(self.dport))


    def update_flags(self, flags):
        """
         Updates flag counter and idle lock.
        """
        self.flag_list.append(0, flags)
        # Enable warnings.
        self.lockWarningFlags = False
        # Update counters.
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
         Updates time related values when a packet is received.
        """
        # Stored timestamp in seconds.
        old_time  = self.time.microsecond*u_SEC
        old_time += self.time.second
        old_time += self.time.minute*MINUTE
        old_time += self.time.hour*HOUR
        # New timestamp in seconds.
        new_time  = time.microsecond*u_SEC
        new_time += time.second
        new_time += time.minute*MINUTE
        new_time += time.hour*HOUR
        # Difference between stored timestamp and new timestamp.
        new_dif_time = new_time - old_time
        # Initial value check.
        if self.var_avg_interval.get() == "0.0":
            out = "{0:.9f}".format(new_dif_time)
            self.var_avg_interval.set(out)
        else:
            new_avg = (new_dif_time + float(self.var_avg_interval.get()) / 2)
            out = "{0:.9f}".format(new_avg)
            self.var_avg_interval.set(out)
        # Update stored timestamp to new timestamp.
        self.time = time


    def randomString(self, stringLength):
        """
         Returns a random string of fixed length. Debug puposes.
        """
        letters = string.ascii_lowercase
        return ''.join(random.choice(letters) for i in range(stringLength))


    def formatIpString(self, ip):
        """
         Returns a formated IPv6 string from packet.
        """
        sa = (ip[ 0: 4] + "::" +
              ip[ 4: 8] + ":"  +
              ip[ 8:12] + ":"  +
              ip[12:16] + ":"  +
              ip[16:20] + ":"  +
              ip[24:28] + ":"  +
              ip[28:32])
        return sa


    def check_if_port_stored(self, packet):
        """
         Checks if dport was already used by ip of given packet.
        """
        for p in self.dport:
            if SHUTDOWN:
                break
            if p == packet[56:58].hex():
                return True
        return False


    def check_tcp_connect(self):
        """
         Check flag array for TCP Connect attack.
         Returns True if attack is detected.
        """
        for i in range(len(self.flag_list)-1):
            if SHUTDOWN:
                break
            # Look for SYN flag
            if self.flag_list[i] == FLAGS_SYN:
                # If next flag is ACK, TCP connection detected.
                if self.flag_list[i+1] == FLAGS_ACK:
                    # Remove flags from list.
                    self.tcp_connect_count += 1
                    self.flag_list[i].pop()
                    self.flag_list[i].pop()
                    return True
        return False


    def check_tcp_half_openning(self):
        """
         Check flag array for TCP Half openning attack.
         Returns True if attack is detected.
        """
        for i in range(len(self.flag_list)-1):
            if SHUTDOWN:
                break
            # Look for SYN flag
            if self.flag_list[i] == FLAGS_SYN:
                # If next flag is RST, TCP half openning detected.
                if self.flag_list[i+1] == FLAGS_RST:
                    # Remove flags from list
                    self.tcp_half_openning_count += 1
                    self.flag_list[i].pop()
                    self.flag_list[i].pop()
                    return True
        return False