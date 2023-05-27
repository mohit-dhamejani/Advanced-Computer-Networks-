# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
        self.buffered_packets = {} #maps MAC addresses to a list of packets received from that address.

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
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

    def add_mobile_flow(self, datapath, dst_mac):
        # ofproto = datapath.ofproto
        # parser = datapath.ofproto_parser

        # match = parser.OFPMatch(in_port=in_port,
        #                         dl_dst=addrconv.mac.text_to_bin(dst))
        # mod = parser.OFPFlowMod(
        #     datapath=datapath, match=match, cookie=0,
        #     command=ofproto.OFPFC_ADD, actions=actions)
        # datapath.send_msg(mod)

        node_port = self.mac_to_port[datapath.id][dst_mac]
        match = parser.OFPMatch(dl_dst=dst_mac)
        actions = [parser.OFPActionOutput(node_port)]
        # inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # mod = parser.OFPFlowMod(datapath=datapath, match=match,
        #                         command=ofproto.OFPFC_ADD,
        #                         priority=1,
        #                         instructions=inst)
        mod = parser.OFPFlowMod(
             datapath=datapath, match=match, cookie=0,
             command=ofproto.OFPFC_ADD, actions=actions)
        datapath.send_msg(mod)

        # Send all the buffered packets to the mobile node
        if dst_mac in self.buffered_packets:
            for packet_data in self.buffered_packets[dst_mac]:
                out = parser.OFPPacketOut(
                    datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                    data=packet_data)
                datapath.send_msg(out)

        # Clear the buffered packets for the mobile node
        del self.buffered_packets[dst_mac]
        return

    def del_mobile_flow(self, datapath, dst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(dl_dst=dst)
        mod = parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)
        self.buffered_packets.setdefault(dst, [])


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
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
        dst_mac = eth.dst
        src_mac = eth.src

        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][src_mac] = in_port

        
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt and udp_pkt.src_port==8000:
            print("Disconnect packet received:")

            # match = parser.OFPMatch(dl_dst=dst_mac)
            # mod = parser.OFPFlowMod(datapath=datapath, match=match,
            #                         command=ofproto.OFPFC_DELETE,
            #                         out_port=ofproto.OFPP_ANY,
            #                         out_group=ofproto.OFPG_ANY)
            # datapath.send_msg(mod)

            self.del_mobile_flow(datapath, dst_mac)
            return

        else if udp_pkt and udp_pkt.src_port==8001:
            print("Connect packet received:")
            # Add flow rules for all traffic to the mobile node
            # node_port = self.access_ports[dst_mac][udp_pkt.dport] #Check this line!
            self.add_mobile_flow(datapath, src_mac)
            return


        if dst_mac in self.buffered_packets:
            self.buffered_packets[dst_mac].append(msg.data)

        else:
            if dst_mac in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # install a flow to avoid packet_in next time
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
                # verify if we have a valid buffer_id, if yes avoid to send both
                # flow_mod & packet_out
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
