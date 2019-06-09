# TCP Port Scanning using IPv6

## Available scanners
### TCP Connect
- An SYN message is sent to a port
- If the port is open, an SYN/ACK will be received
- The handshake's phase is concluded with an ACK
### TCP Half-Opening
- An SYN message is sent to a port
- If the port is open, an SYN/ACK will be received
- An RST packet is sent to close the connection
### Stealth scan or TCP FIN
- An FIN message is sent to a port
- If the port is close, an RST will be received; else the port is open
### SYN/ACK
- An SYN message is sent to a port
- If the port is open, an RST will be received; else the port is close

## Arguments
We're using the **argparse** library which give us a simple way to input data in our code. Therefore, bellow you can see the flags available:

|      **arg**     | **required** |           **example**           |              **description**             |
|:----------------:|:------------:|:-------------------------------:|:----------------------------------------:|
|       smac       |      yes     |     --smac aa:bb:cc:dd:ee:ff    |          The source MAC address          |
|       dmac       |      yes     |     --dmac aa:bb:cc:dd:ee:ff    |        The destination MAC address       |
|        sip       |      yes     | --sip aaaa::bbbb:cccc:dddd:eeee |          The source IPv6 address         |
|        dip       |      yes     | --dip aaaa::bbbb:cccc:dddd:eeee |       The destination IPv6 address       |
|   interface, i   |      no      |            -i enp0s4            |     The network interface to be used     |
|      port, p     |      yes     |             -p 20 80            | The unique port (or range) to be scanned |
|    tcp-connect   |      no      |          --tcp-connect          |      Select the TCP Connect scanner      |
| tcp-half-opening |      no      |        --tcp-half-opening       |    Select the TCP Half-Opening scanner   |
|      tcp-fin     |      no      |            --tcp-fin            |        Select the TCP FIN scanner        |
|      syn-ack     |      no      |            --syn-ack            |        Select the SYN/ACK scanner        |

## Getting started
```bash
sudo python3 port_scan.py \
  --smac aa:bb:cc:dd:ee:ff \
  --dmac aa:bb:cc:dd:ee:ff \
  --sip aaaa::bbbb:cccc:dddd:eeee \
  --dip aaaa::bbbb:cccc:dddd:eeee \
  --i enp0s4 \
  --p 20 80
  --tcp-connect
```
