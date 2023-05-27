# TCP-Mobility-Improvement-using-SDN
TCP Performance Improvement over Wireless Links using SDN

## What it does

**** Work in Progress ****

1. In this approach, we try to buffer all the packets coming to and from the mobile node in the controller.
2. When the mobile node disconnects and later reconnects to an AP, the buffered packets are then sent to the node.
3. Upon getting ack, these packets are deleted from the controller

## How to Run -

1. Install Mininet-Wifi or download its VM. (More info here https://github.com/intrig-unicamp/mininet-wifi)
2. Clone this repo
3. Run the contoller and topology scripts in different terminals
4. On Mininet-CLI type these commands 
   "sh ifconfig hwsim0 up", "xterm h1 ap1 sta1", "wireshark &"
5. On ap1 xterm run ./sta1.py
6. On h1 xterm run iperf -s 100
7. On sta1 run iperf -c -t 100
