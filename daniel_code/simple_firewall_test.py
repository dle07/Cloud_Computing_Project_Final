#HELLOOOOOOOO123
"""
An OpenFlow 1.0 Simple Firewall implementation.
"""

import logging
import os
from netaddr import IPAddress as IP 
from netaddr import IPNetwork as Net
from pprint import pprint
from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller import dpset
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import inet
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import ipv4
from ryu.controller import ofp_event
import ryu
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from utils import *

SCRIPT_PATH = os.path.dirname(os.path.abspath(__file__))
config_file = os.path.join(SCRIPT_PATH, "fw.conf")
KNOWN_HOSTS = {
    "host1":{"ip": "10.10.1.1", "mac":"", "port":"eth4"},
    "host2":{"ip":"10.10.1.3","mac":"", "port":"eth3"},
    "client":{"ip":"10.10.1.7","mac":""},
    "dummy_vm":{"ip":"10.10.1.5", "mac":"02:d7:82:ef:3b:fd"}

}
DUMMY_VM = {"ip":"10.10.1.5"}



class SimpleFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(SimpleFirewall, self).__init__(*args, **kwargs)
        self.local_net = Net('10.10.1.0/24')




    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        pkt = packet.Packet(msg.data)
        #print(self.extract_src_dst(ev)(ev))
        print("PRINTING INPUT PACKET NOW")


        pkt = packet.Packet(msg.data)
        eth_header = pkt.get_protocol(ethernet.ethernet)
        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        pprint("PRITNING ETH HEADER {}".format(eth_header))
        pprint("PRITNING IPV4 HEADER {}".format(ipv4_header))

        if eth_header:
            actions = [
                parser.OFPActionSetField(eth_dst = KNOWN_HOSTS["dummy_vm"]["mac"]),
                datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)
                       ]
            
            out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = pkt.data)
            datapath.send_msg(out)

        if ipv4_header:
            actions = [
                parser.OFPActionSetField(ipv4_dst = KNOWN_HOSTS["dummy_vm"]["ip"]),
                datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)
                       ]
            
            out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data = pkt.data)
            datapath.send_msg(out)




    '''
    a connection is defined by a four-tuple rule
    extract the rule from received packet
    '''
    def extract_rule(self, msg):
        pkt = packet.Packet(msg.data)
        print(type(pkt))
        pprint(pkt)
        rule = { 'sip':None, 'dip':None, 'sport':None, 'dport':None }
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is not None:
            rule['sip'] = ip_pkt.src
            rule['dip'] = ip_pkt.dst
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt is not None:
                rule['sport'] = str(tcp_pkt.src_port)
                rule['dport'] = str(tcp_pkt.dst_port)
            elif udp_pkt is not None:
                rule['sport'] = str(udp_pkt.src_port)
                rule['dport'] = str(udp_pkt.dst_port)
        self.logger.info("Extracted rule %s", rule)
        return rule  
    
    def extract_src_dst(self, event):
    # Assuming the event is an instance of EventOFPPacketIn
        src_dst = ()
        if isinstance(event, ofp_event.EventOFPPacketIn):
            # Access the packet data from the event
            packet = event.msg.data

            # Extract the source and destination IP addresses
            eth = packet.get_protocol(ryu.lib.packet.ethernet.ethernet)
            if eth:
                ip = eth.get_protocol(ryu.lib.packet.ipv4.ipv4)  # For IPv4 packets
                # If it's an IPv4 packet, extract the source and destination IP addresses
                if ip:
                    src_ip = ip.src
                    dst_ip = ip.dst
                    print("Source IP:", src_ip)
                    print("Destination IP:", dst_ip)
                    src_dst = (src_ip, dst_ip)
        return src_dst
    
    

       

    