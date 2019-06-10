import socket, sys
import tkinter as tk
from struct import *

PROTOCOL_TYPE_IPV6 = 0x86dd
WND_RESOLUTION     = "800x600"
WND_TITLE          = "ListenerV6"


# definir inteiros, nao adianta pai, nao via funcionar o bitwise. pe no chao, joga facil, cautelinha
#SYN = 
#SYN_ACK =
#FIN =
#RST = 
#ACK =

class listenerWindow:
    def __init__(self, master):
        self.master = master
        master.title(WND_TITLE)
        master.geometry(WND_RESOLUTION)
        self.w, self.h = WND_RESOLUTION.split("x",1)
        self.w, self.h = int(self.w), int(self.h)

        self.frmMain = tk.Frame(master, width = self.w, height = self.h, bg = 'white')
        self.frmDisplay = tk.Frame(self.frmMain, width = (self.w-260), height = (self.h-60), bg = 'white smoke', highlightbackground = 'grey50')

        self.btnCloseApp = tk.Button(self.frmMain, text="Exit", command=master.quit, height = 2, width = 6, bg = 'white', activebackground = 'white smoke' )


        self.frmMain.place(x = 0, y = 0)
        self.frmDisplay.place( x = 250, y = 50 )
        self.btnCloseApp.place(x = 10, y = (self.h-50))

def listener():
    listen = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    print("Starting Listener")
    while True:
        raw_packet = listen.recvfrom(65565)
        packet = raw_packet[0]
        # Now we need to unpack the packet. It will be an TCP packet
        # We want to pull out and compare only these three

        # This is the TCP header. Normal length is 20 bytes.

        # Get ethernet header
        eth_header = packet[0:14]

        # Get protocol type; 0x86dd for IPv6
        protocol_type = unpack('!6B6BH', eth_header)[12]
    
        # Check for IPv6 only
        if (protocol_type == int(PROTOCOL_TYPE_IPV6)):
            tcp_header = unpack('!HHLLBBHHH', packet[54:74])
            flags = int(tcp_header[5])
            #print(flags)

            #dst port
            print(tcp_header[1])


            urg = tcp_header[5] >> 5 & 1
            ack = tcp_header[5] >> 4 & 1
            psh = tcp_header[5] >> 3 & 1
            rst = tcp_header[5] >> 2 & 1
            syn = tcp_header[5] >> 1 & 1
            fin = tcp_header[5] >> 0 & 1

            # This listener should warn which type of attack it is receiving
    
            # TCP connect attack
            # expected: SYN and later an ACK
            # TCP half-opening
            # expected: SYN and later an RST
            if ((flags & 0b10) == int(0b10)):
                # print('esperar pacote com ack(tcp connect) ou rst(tcp half-opening)')
                print('aha2: ', bin(flags))
                # await ACK or RST
                # thread
                # fork

            # Stealth scan ou TCP FIN
            # expected: FIN
            elif (flags & 0b1 == int(0b1)):
                print('stealth scan ou tcp fin')

            # SYN/ACK
            # expected: SYN/ACK
            elif (flags & 0b10010 == int(0b10010)):
                print('syn / ack')
        
if __name__ == "__main__":
    root = tk.Tk()
    window = listenerWindow(root)
    root.mainloop()
    #listener()