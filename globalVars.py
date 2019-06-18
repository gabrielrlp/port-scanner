###############################################################################
#                            Dont change this:                                #
###############################################################################
# Window configuration
WND_RESOLUTION = "1000x680"
WND_TITLE      = "uaireshark"
# If raised, will shut down everything
SHUTDOWN = False
# Stores packets to be processed
PACKET_QUEUE = []
# List of objects that represents received IPv6 TCP packets
PACKET_OBJECT_LIST = []

## IPv6 type from ethernet header
PROTOCOL_TYPE_IPV6 = 0x86dd
# 000010
FLAGS_SYN = "02"
# 010010 
FLAGS_SYNACK = "12"
# 000001
FLAGS_FIN = "01"
# 000100
FLAGS_RST = "04"
# 010000
FLAGS_ACK = "10"

## Constants
u_SEC = 1/100000000
n_SEC = 1/100000
m_SEC = 1/100
MINUTE = 60
HOUR = 360
###############################################################################
#                           You can change this:                              #
###############################################################################
# INT: number of different ports required to raise port scan warning flags
DPORT_LIMIT = 5
SPORT_LIMIT = 5
# FLOAT(seconds): if the  interval between received packets is lower than this,
#flood flags will be raised.
STREAM_INTERVAL_LIMIT = 0.01
# INT: raise warning flags  for the respectives after given number of flags are
# received.
# Ideally,  by the time we  detect  an excess of  syn packets,  we have not yet
#received the next ACK or   RST. So if you want to  detect a TCP connect or TCP
#half  opennening  when your SYN count  reaches the exact  limit, the value for
#ACK_LIMIT and RST_LIMIT should be SYN_LIMIT-1.
SYNACK_LIMIT = 5
SYN_LIMIT = 5
FIN_LIMIT = 5
ACK_LIMIT = SYN_LIMIT-1
RST_LIMIT = SYN_LIMIT-1
# INT: length of list that stores last flags received
FLAG_LIST_LEN = 5

##Flags for packet timeout:
# Timeout  is  the time  it takes,  in seconds, to  discard information about a
#packet in the storage.
# INT: after this period(seconds), warning flags will be reseted.
FLAG_TIMEOUT = 10
# BOOL: if set to true,  FLAG_TIMEOUT =  (FLAG_TIMEOUT + warning_counter). Each
#packet stored will have it's own timeout value.
FLAG_CALCULATE_TIMEOUT = True
# BOOL: set flag(SYN, ACK) counters to 0 after timeout.
RESET_FLAGS_TIMEOUT = True

##Sort mode for PACKET_OBJECT_LIST:
# INT, 1 = Sort by number of uniques ports scanned(port range);
#      2 = Sort by dangerousness(number of warnings raised, port range).
SORT_DICT =	{"NONE": 0,
  			 "PORT_RANGE": 1,
  			 "DANGEROUSNESS": 2}
SORT_MODE = 1
# Debug flags
DEBUG_RANDOM_IPS = 0