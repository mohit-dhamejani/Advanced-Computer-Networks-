""" To do
1. Print all the packet sequence numbers in the controller buffer when Ryu receive the flag.
2. Print an alert when you receive the flag
3. Print all the packets you have sent to the station. 
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.tcp_msg_dict={}
        self.tcp_dup_ack={}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        # mac to port mapping here
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # checking for associataion has occurred or not via ass_flag.
        # f=open('/home/wifi/ACN/Project/alert.txt','r')
        # self.ass_flag=f.read()
        # f.close()

        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.tcp_msg_dict.setdefault(src,{})
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:

            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                ip_header_len=ip.header_length
                total_len=ip.total_length
               	
                srcip = ip.src
                dstip = ip.dst
                protocol = ip.proto
                # if ICMP Protocol
                if protocol == in_proto.IPPROTO_ICMP:
                    
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)

                #  if TCP Protocol
                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
                    tcp_header=t.offset
                    
                    data_len=total_len-((ip_header_len+tcp_header)*4)
                    requried_ack=(t.seq + data_len )
                    data=ev.msg

                    if (srcip == "10.0.0.4" & data == "0"):
                        print("Got Association Request")

                    elif (srcip == "10.0.0.4" & data == "1"):
                        print("Got Association Response")

                    elif (srcip == "10.0.0.4" & data == "10"):
                        print("Got Dissociation Request")

                    elif (srcip == "10.0.0.4" & data == "12"):
                        print("Got Disauthentication Requesr")

                    else:

                        # creating temp to store the tcp segment
                        temp={}
                        temp[src]=src
                        temp[dst]=dst
                        #print("tcp packet send from ",src,"  =>  ",dst)
                        #print("ack we got is => ",t.ack)
                        
                        temp["src_port"]=t.src_port
                        temp["dst_port"]=t.dst_port
                        temp["msg"]=data
                        
                        self.tcp_msg_dict[src][requried_ack]=temp
                        src_to_dst=str(src)+str(dst)
                        self.tcp_dup_ack.setdefault(src_to_dst,[-3,-2,-1])
                        self.tcp_dup_ack[src_to_dst]=(self.tcp_dup_ack[src_to_dst])[1:]
                        
                        self.tcp_dup_ack[src_to_dst].append(t.ack)
                        #print("got an tcp packet with the src port has",t.src_port)
                        
                        for keys in list(self.tcp_msg_dict[dst]):
                            if(keys<t.ack):
                                self.tcp_msg_dict[dst].pop(keys)
                            else:
                                break
                        # Below is the tcp code for 3 duplicate ack.
                        if self.tcp_dup_ack[src_to_dst][0]==self.tcp_dup_ack[src_to_dst][1] and self.tcp_dup_ack[src_to_dst][1]==self.tcp_dup_ack[src_to_dst][2] and self.tcp_dup_ack[src_to_dst][2]==self.tcp_dup_ack[src_to_dst][0] and len(self.tcp_msg_dict[dst].keys())!=0:
                            actions=[parser.OFPActionOutput(port=in_port)]
                            self.temp=self.tcp_dup_ack[src_to_dst]

                            self.tcp_dup_ack[src_to_dst]=[-3,-2,-1] 
                            next_to=min(self.tcp_msg_dict[dst].keys())

                            print("Three duplicate ack =>",self.temp[0],self.temp[1],self.temp[2]," discard dup ack=>=>resend the tcp packet")
                            data=self.tcp_msg_dict[dst][next_to]["msg"]
                        # Below is the tcp code for handoff association event.   
                        elif self.ass_flag=="1":
                            actions=[parser.OFPActionOutput(port=out_port)]
                            print("********Sending the bulk packets because of handoff**********")
                            print("The number of packet present in the buffer during the handoff=>",len(self.tcp_msg_dict[dst].keys()))
                            print()
                            for next_to in self.tcp_msg_dict[dst].keys():
                                data=self.tcp_msg_dict[dst][next_to]["msg"]
                                # print(msg)
                                print("Controller is currently transmitting the packet having the sequence",t.seq)
                                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data.data)
                                datapath.send_msg(out)
                            self.ass_flag=0
                            f=open('/home/wifi/ACN/Project/alert.txt','w')
                            f.write("0")      
                            f.close()
                        else:
                            #print("No anomaly detected =>=> exhibiting normal tcp behavior")
                            actions=[parser.OFPActionOutput(port=out_port)]
                        out=parser.OFPPacketOut(datapath=datapath,in_port=ofproto.OFPP_CONTROLLER,actions=actions,data=data)
                    
                #  If UDP Protocol
                
                elif protocol == in_proto.IPPROTO_UDP:
                	
                    u = pkt.get_protocol(udp.udp)
                    print(u.data)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)            

                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER and protocol != in_proto.IPPROTO_TCP:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                elif protocol != in_proto.IPPROTO_TCP:
                    self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
