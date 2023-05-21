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
from ryu.lib.packet import ethernet, ipv4
from ryu.lib.packet import ether_types
import paramiko
from datetime import timedelta
from ProactiveMigration import Migrator
import threading
import time
from threading import Thread
from time import sleep
import yaml



"""
0 ether 02:82:24:ea:60:f9  txqueuelen 1000  (Ethernet)
1 ether 02:5c:8e:9e:f9:a4  client 10.10.1.16
2 ether 02:90:94:70:9e:19  client2 10.10.1.7
3 ether 02:34:61:eb:86:34  VM1 10.10.1.11
4 ether 02:59:35:b0:86:92  Attacker 10.10.1.15
5 ether 02:0f:7b:4a:c1:13  VM3          10.10.1.13 
6 ether 02:6a:e6:24:a0:bd  DummyVM    10.10.1.14
7 ether 02:b9:cb:69:37:7e  VM2          10.10.1.12
8 ether 02:b0:8b:e3:4b:27  Proxy        10.10.1.18
"""  






# def background_task():
#     while True:
#         sleep(30)
#         print("Calling background task")
#         print(time.ctime())


# Proactive migration
# Use paramiko to ssh, move files, delete 
class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        with open("./hosts.yaml", 'r') as file:
            yaml_file = yaml.safe_load(file)
            self.yaml_file = yaml_file
        
            self.key_cred = yaml_file["key_cred"]
            self.vm_pool_list = yaml_file["vm_pool"]
            self.vms = yaml_file["vms"]   # VMS
            self.dummy_vm = yaml_file["Dummy_VM"]
            self.vm_ips = [self.vms[key]["local_ip"] for key in self.vms.keys()]
        self.datapath= None
        self.parser = None
        self.migrator=Migrator()
        self.periodic_migrator_daemon = Thread(target=self.periodically_migrate, args=(), daemon=True, name='Background')
        self.periodic_migrator_daemon.start()

    
    
    def periodically_migrate(self,):
        while True:
            sleep(30)
            print("MIGRATING AT.....{}".format(time.ctime()))
            self.migrator.migrate()  # 
            self.update_redirection_rules()
            print("\n\n\n")

    def proactively_migrate(self,):
        self.migrator.migrate()
        self.update_redirection_rules()

    #Priority = 5        
    def update_redirection_rules(self,):
        current_vm = self.migrator.getCurrentHost()
        parser = self.parser
        action_modify_headers = [
            parser.OFPActionSetField(eth_dst=self.vms[current_vm]["mac"]),
            parser.OFPActionSetField(ipv4_dst=self.vms[current_vm]["local_ip"]),
            parser.OFPActionOutput(self.vms[current_vm]["ovs_port"])   # send to port directed to dummy_vm
        ]

        for vm_ip in self.vm_ips:
            match = parser.OFPMatch(eth_type=0x0800,ipv4_dst=str(vm_ip))
            self.add_flow(self.datapata,1, match, action_modify_headers)
        return
        
    #Priority = 10
    def black_list_ip(self, ip_addr:str):
        current_vm = self.migrator.getCurrentHost()
        parser = self.parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src = str(ip_addr))

        action_modify_headers = [
            parser.OFPActionSetField(eth_dst=self.dummy_vm["mac"]),
            parser.OFPActionSetField(ipv4_dst=self.dummy_vm["local_ip"]),
            parser.OFPActionOutput(self.dummy_vm["ovs_port"])   # send to port directed to dummy_vm
        ]
        self.add_flow(self.datapata, 10, match,action_modify_headers)
        return



    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapata=datapath
        self.parser = parser
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
        self.update_redirection_rules()

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
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
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



# if (ip_pkt and ip_pkt.dst == global_addr):   # Traffic directed to 
        #     print("{} --->{}".format(ip_pkt.src,ip_pkt.dst))
        #     #modify packet header

        #     match1 = parser.OFPMatch(eth_type=0x0800, ipv4_dst = global_addr)

        #     actions_modify_headers = [
        #         parser.OFPActionSetField(eth_dst=KNOWN_HOSTS["dummy_vm"]["mac"]),
        #         parser.OFPActionSetField(ipv4_dst=KNOWN_HOSTS["dummy_vm"]["local_ip"]),
        #         parser.OFPActionOutput(KNOWN_HOSTS["dummy_vm"]["port"])]   # send to port directed to dummy_vm

        #     self.add_flow(datapath, 1, match1, actions_modify_headers)

        #     out = parser.OFPPacketOut(datapath=datapath,
        #                                 buffer_id=msg.buffer_id,
        #                                 in_port=msg.in_port
        #                                 , actions=actions,
        #                                 data=data)
        #     datapath.send_msg(out)
        #     return

        