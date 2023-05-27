#!/usr/bin/python
from scapy.all import *
import os
# import time
# os.popen("gnome-terminal")

def pkt_callback(pkt):
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
    #     print("Beacon")
    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 0:
    #     print("Association Request")
    #     # msg = "%d" % (pkt.subtype) #subtype: 0
    #     # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Association Request"
    #     packet = Ether()/IP(dst="127.0.0.1")/UDP(sport=8000, dport=6653)/"Association Request"
    #     sendp(packet, iface="con-eth0", verbose=0)

    # if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 10:
    #     print("Disassociation")
    #     # msg = "%d" % (pkt.subtype) #subtype: 10
    #     # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Disassociation"
    #     packet = Ether()/IP(dst="127.0.0.1")/UDP(sport=8000, dport=6653)/"Disassociation"
    #     sendp(packet, iface="con-eth0", verbose=0)

    # m ={"00:00:00:00:00:01":"ap1-eth2","00:00:00:00:00:02":"ap2-eth2","00:00:00:00:00:03":"ap3-eth2"}
    # m ={"00:00:00:00:00:01":"ap1-wlan1","00:00:00:00:00:02":"ap2-wlan1","00:00:00:00:00:03":"ap3-wlan1"}





    #This send the packets to interfaces which are connected to the corresponding APs'. Then from those AP's these packets are sent to the controller 
    #via packet-in. Now controller has the datapath of the AP's and can send add or delete flowmods to the APs
    m ={"00:00:00:00:00:01":"s4-eth2","00:00:00:00:00:02":"s3-eth4","00:00:00:00:00:03":"s5-eth2"}   
   

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 12:
        print("Disconnect")

        #need AP's mac addr, STA's mac addr is known, from AP's mac addr determine iface 

        print('Sender MAC address:\n', pkt[Dot11].addr2)
        print(m[(pkt[Dot11].addr1)])
        print('\nDestination MAC address:\n', pkt[Dot11].addr1)
        # msg = "%d" % (pkt.subtype) #subtype: 12
        # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Disauthentication"
        payload_data = b'Disconnect'
        packet = Ether(src=pkt[Dot11].addr2, dst=pkt[Dot11].addr1)/IP(src="10.0.0.7", dst="127.0.0.1")/UDP(sport=8000, dport=6653)/Raw(load=payload_data)
        sendp(packet, iface=m[(pkt[Dot11].addr1)], verbose=0)
        # sendp(packet, iface="s4-eth2", verbose=0)

    if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 1:
        print("Connect")

        print('Sender MAC address:\n', pkt[Dot11].addr2)
        print(m[pkt[Dot11].addr2])
        print('\nDestination MAC address:\n', pkt[Dot11].addr1)
        # msg = "%d" % (pkt.subtype) #subtype: 1
        # packet = Ether()/IP(src="10.0.0.7", dst="127.0.0.1")/TCP(sport=8000, dport=6653)/"Association Response"
        payload_data = b'Connect'
        packet = Ether(src=pkt[Dot11].addr1, dst=pkt[Dot11].addr2)/IP(src="10.0.0.7", dst="127.0.0.1")/UDP(sport=8001, dport=6653)/Raw(load=payload_data)
        sendp(packet, iface=m[pkt[Dot11].addr2], verbose=0)
        # sendp(packet, iface="s4-eth2", verbose=0)
        
        # f = open('/home/wifi/ACN/Project/alert.txt', 'w+')
        # f.write("1")
        # f.close()

# time.sleep(50)
sniff(iface="hwsim0", prn=pkt_callback)
# sniff(iface="mon0", prn=pkt_callback)