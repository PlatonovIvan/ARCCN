# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

"""
A stupid L3 switch

For each switch:
1) Keep a table that maps IP addresses to MAC addresses and switch ports.
   Stock this table using information from ARP and IP packets.
2) When you see an ARP query, try to answer it using information in the table
   from step 1.  If the info in the table is old, just flood the query.
3) Flood all other ARPs.
4) When you see an IP packet, if you know the destination port (because it's
   in the table from step 1), install a flow for it.
"""

from pox.core import core
import pox
log = core.getLogger()

from pox.lib.packet.ethernet import ethernet
import pox.lib.packet as pkt
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib import addresses

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery as discovery

from pox.lib.revent import *


from pox.lib.revent               import *
from pox.lib.recoco               import Timer
from pox.lib.packet.ethernet      import LLDP_MULTICAST, NDP_MULTICAST
from pox.lib.packet.ethernet      import ethernet
from pox.lib.packet.lldp          import lldp, chassis_id, port_id, end_tlv
from pox.lib.packet.lldp          import ttl, system_description
import pox.openflow.libopenflow_01 as of
from pox.lib.util                 import dpidToStr
from pox.core import core


import time, copy

import Topology,  general_functions 

#import pox.openflow.discovery as discovery
import my_discovery as discovery

# Timeout for flows
FLOW_IDLE_TIMEOUT = 100
FLOW_HARD_TIMEOUT = 1000

# Timeout for ARP entries
ARP_TIMEOUT = 600 * 2

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 5

class Entry (object):
  """
  Not strictly an ARP entry.
  We use the port to determine which port to forward traffic out of.
  We use the MAC to answer ARP replies.
  We use the timeout so that if an entry is older than ARP_TIMEOUT, we
   flood the ARP request rather than try to answer it ourselves.
  """
  def __init__ (self, port, mac):
    self.timeout = time.time() + ARP_TIMEOUT
    self.port = port
    self.mac = mac

  def __eq__ (self, other):
    if type(other) == tuple:
      return (self.port,self.mac)==other
    else:
      return (self.port,self.mac)==(other.port,other.mac)
  def __ne__ (self, other):
    return not self.__eq__(other)

  def isExpired (self):
    return time.time() > self.timeout

class l3_switch (EventMixin):

  def __init__ (self, of_switch_nodes, reflexive, discovery_object):
    #print "For each switch, we map IP addresses to Entries"
    self.arpTable = {}
    #self.constant_flow_priority_table={} #dpid->priority of current rule
    #self.permanent_flow_priority_table={} #dpid->priority of current rule
    #self.outportTable={} #dpid->list of output ports NOT USED IN CURRENT VERSION
    #self.connectionTable={} #dpid->connection
    #self.macTable={} #dpid->[(port1,mac1), ..., (portn, macn)]
    self.listenTo(core)
    self.of_switch_nodes=copy.deepcopy(of_switch_nodes)
    self.reflexive=reflexive
    discovery_object.addListeners(self)

    #for i in xrange(len(self.of_switch_nodes)):
    #  print "??????????????????????/", self.of_switch_nodes[i].dpid
    #  for j in xrange(len(self.of_switch_nodes[i].entry_list)):
    #    print self.of_switch_nodes[i].entry_list[j].ip_addr, self.of_switch_nodes[i].entry_list[j].port
        
    #general_functions.Tree_Print(self.of_switch_nodes[i].rule_tree)
    #for j in xrange(len(self.of_switch_nodes[i].entry_list)):
    #  print self.of_switch_nodes[i].entry_list[j].ip_addr, self.of_switch_nodes[i].entry_list[j].port
    #  print "*********************************"
        
        
  def addr_is_gw(self, dpid, addr):
    """
    type(addr)==string
    """
    ip_addr=general_functions.addr_to_list(addr)
    for j in xrange(len(self.of_switch_nodes[dpid].entry_list)):
      if (self.of_switch_nodes[dpid].entry_list[j].ip_addr==ip_addr):
        return True
    return False

  
  def find_mac_addr(self, dpid, inport):
    if (not self.of_switch_nodes.has_key(dpid)):
      return "ff:ff:ff:ff:ff:ff"
    
    for i in xrange(len(self.of_switch_nodes[dpid].macTable)):
      if (self.of_switch_nodes[dpid].macTable[i][0]==inport):
        return self.of_switch_nodes[dpid].macTable[i][1]
      
    return "ff:ff:ff:ff:ff:ff"


  def find_input_port (self, dpid, addr):
    """
    type(addr)== string | list
    """
    if (not self.of_switch_nodes.has_key(dpid)):
      return -1
    
    if (type(addr)!=list):
      ip_addr=general_functions.addr_to_list(addr)
    else:
      ip_addr=addr

    for i in xrange(len(self.of_switch_nodes[dpid].entry_list)):
      if (general_functions.addr_belongs_to_subnet(self.of_switch_nodes[dpid].entry_list[i].ip_addr,
                                                   self.of_switch_nodes[dpid].entry_list[i].ip_mask,
                                                   ip_addr)):
        return self.of_switch_nodes[dpid].entry_list[i].port
    return -1
    

  def find_output_port(self, dpid, addr):
    """
    type(addr)== string | list
    """

    #print "addr=", addr
    #print "dpid=", dpid

    if (not self.of_switch_nodes.has_key(dpid)):
      return -1
    
    if (type(addr)!=list):
      ip_addr=general_functions.addr_to_list(addr)
    else:
      ip_addr=addr
    
    for i in xrange(len(self.of_switch_nodes[dpid].entry_list)):
      if (general_functions.addr_belongs_to_subnet(self.of_switch_nodes[dpid].entry_list[i].ip_addr,
                                                   self.of_switch_nodes[dpid].entry_list[i].ip_mask,
                                                   ip_addr)):
        return self.of_switch_nodes[dpid].entry_list[i].port
      
    for links in core.openflow_discovery.adjacency.keys():
      if (links.dpid1==dpid):
        for j in xrange(len((self.of_switch_nodes[links.dpid2].entry_list))):
          if (general_functions.addr_belongs_to_subnet(self.of_switch_nodes[links.dpid2].entry_list[j].ip_addr,
                                                             self.of_switch_nodes[links.dpid2].entry_list[j].ip_mask,
                                                             ip_addr)):
            return links.port1
    return -1

  def find_next_switch(self, dpid, addr):
    """
    type(addr)==string
    returns [dpid, inport]
    """
    ip_addr=general_functions.addr_to_list(addr)
    dpid2=0
    inport2=0
    for links in core.openflow_discovery.adjacency.keys():
      if (links.dpid1==dpid):
        for j in xrange(len((self.of_switch_nodes[links.dpid2].entry_list))):
          if (general_functions.addr_belongs_to_subnet(self.of_switch_nodes[links.dpid2].entry_list[j].ip_addr,
                                                             self.of_switch_nodes[links.dpid2].entry_list[j].ip_mask,
                                                             ip_addr)):
            return [links.dpid2, links.port2]
    return [0, 0]


  
  def addr_matches_several_subnets(self, addr, mask): # not used in current version
    
    """
    if (type(addr)!=list):
      ip_addr=general_functions.addr_to_list(addr)
    if (type(mask)!=list):
      ip_mask=general_functions.mask_to_list(mask)
    """
    counter=0
    subnet_list=[]
    for i in self.of_switch_nodes.keys():
      for j in xrange(len(self.of_switch_nodes[i].entry_list)):
        if (general_functions.addr_belongs_to_subnet(addr, mask, self.of_switch_nodes[i].entry_list[j].ip_addr)):
          if not (self.of_switch_nodes[i].entry_list[j].ip_addr in subnet_list):
            counter+=1
            subnet_list.append(self.of_switch_nodes[i].entry_list[j].ip_addr)
    if (counter>1):
      return True
    else:
      return False


  def install_drop_rule(self, dpid, connection):
    msg = of.ofp_flow_mod()
    msg.command=of.OFPFC_ADD
    msg.flags=of.OFPFF_SEND_FLOW_REM
    msg.dl_type=0x800
    connection.send(msg)

  def install_in_flows(self, dpid, connection):
    port_list=[]
    for i in xrange(len(self.of_switch_nodes[dpid].entry_list)):  
      for links in core.openflow_discovery.adjacency.keys():
        if (links.dpid2==dpid):
          if (links.port2 not in port_list):
            #print "inport=", links.port1
            
            msg = of.ofp_flow_mod()
            port_list.append(links.port2)
            msg.command=of.OFPFC_ADD
            msg.flags=of.OFPFF_SEND_FLOW_REM
            msg.priority=self.of_switch_nodes[dpid].permanent_flow_priority
            self.of_switch_nodes[dpid].permanent_flow_priority+=1
            msg.match.dl_type = 0x800
            msg.match.in_port=links.port2
            #msg.actions.append(of.ofp_action_dl_addr.set_src("ff:ff:ff:ff:ff:ff"))
            #msg.actions.append(of.ofp_action_dl_addr.set_dst("ff:ff:ff:ff:ff:ff"))
            msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
            connection.send(msg)
            
            print "Last Flow Installed", msg.match.in_port


  def install_rule_flow(self, connection, dpid, inport, rule):
    msg = of.ofp_flow_mod()
    msg.command=of.OFPFC_ADD
    msg.flags=of.OFPFF_SEND_FLOW_REM
    """
    if (dpid==563110422331449):
      msg.match.in_port=10
    else:
      msg.match.in_port=2
    """
    #self.find_input_port(dpid, rule.src_addr)# Not sure if it will always work properly
    msg.priority=self.of_switch_nodes[dpid].constant_flow_priority
    self.of_switch_nodes[dpid].constant_flow_priority-=1
    msg.match.dl_type = 0x800
    msg.match.nw_proto=rule.protocol
    msg.match.nw_src = general_functions.addr_to_string(rule.src_addr, rule.src_mask)
    msg.match.nw_dst = general_functions.addr_to_string(rule.dst_addr, rule.dst_mask)

    if (rule.protocol!=1) and (rule.protocol!=0):
      msg.match.tp_src = rule.src_port
      msg.match.tp_dst = rule.dst_port
        
    if (rule.action=="permit"):
      #msg.actions.append(of.ofp_action_dl_addr.set_src("ff:ff:ff:ff:ff:ff"))
      #msg.actions.append(of.ofp_action_dl_addr.set_dst("ff:ff:ff:ff:ff:ff"))
      msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
      
    #print "Rules Flow install", msg.priority
    connection.send(msg)

    

  def install_single_flow(self, connection, dpid, inport, buffer_id, packet):
    
    msg = of.ofp_flow_mod()
    msg.command=of.OFPFC_ADD
    msg.flags=of.OFPFF_SEND_FLOW_REM
    if (packet.next.protocol==1):
      msg.priority=self.of_switch_nodes[dpid].permanent_flow_priority
      self.of_switch_nodes[dpid].permanent_flow_priority+=1
      msg.idle_timeout = FLOW_IDLE_TIMEOUT
      msg.hard_timeout = FLOW_HARD_TIMEOUT 
      msg.match.dl_type = 0x800
      msg.match.in_port=inport
      #msg.buffer_id=buffer_id
      msg.match.nw_proto=packet.next.protocol
      msg.match.nw_src=packet.next.srcip
      msg.match.nw_dst=packet.next.dstip
      if (packet.next.protocol!=1):
        msg.match.tp_src=packet.next.next.srcport
        msg.match.tp_dst=packet.next.next.dstport
        if (packet.next.protocol==6):
          msg.match.tos=packet.next.tos # it can change maybe
      dst_ip_addr=packet.next.dstip
    
      outport=self.find_output_port(dpid, packet.next.dstip.toStr())
      if (outport==-1):
        outport=1
        print "Cannot find port"
      elif (outport==inport):
        log.warning("%i %i not sending packet for %s back out of the input port" % (
        dpid, inport, str(dst_ip_addr)))
        return False
      mac_addr=self.find_mac_addr(dpid, outport)
      msg.actions.append(of.ofp_action_dl_addr.set_src(mac_addr))
      msg.actions.append(of.ofp_action_dl_addr.set_dst("ff:ff:ff:ff:ff:ff"))
      msg.actions.append(of.ofp_action_output(port = outport))
      if (packet.next.protocol==1):
        connection.send(msg)
        print "Single Flow Installed", msg.priority
    else:
      msg.match.dl_src=of.EthAddr("ff:ff:12:34:ff:ff")
      msg.match.dl_dst=of.EthAddr("ff:ff:12:34:ff:56")
      #msg.idle_timeout = 1
      #msg.hard_timeout = 1
      msg.priority=self.of_switch_nodes[dpid].permanent_flow_priority
      self.of_switch_nodes[dpid].permanent_flow_priority+=1
      connection.send(msg)
    return True
  
                            
  def install_flows(self, dpid, connection, rule_tree):
    #dpid = event.connection.dpid
    #inport = event.port
    #connection=event.connection
    inport=0
    print "Install all flows for subnet", dpid
    for a in xrange(len(rule_tree)):# perebor po proto
      for b in xrange(len(rule_tree[a])): # perebor po src_addr 
          for c in xrange(len(rule_tree[a][b])): # perebor po src_port
              for d in xrange(len(rule_tree[a][b][c])): # perebor po dst_addr
                  for e in xrange(len(rule_tree[a][b][c][d])): # perebor po dst_port
                      for f in xrange(len(rule_tree[a][b][c][d][e])): # perebor po number
                        rule=rule_tree[a][b][c][d][e][f]
                        #print rule.action, rule.src_addr, rule.src_mask, rule.dst_addr, rule.dst_mask
                        self.install_rule_flow(connection, dpid, inport, rule)

    if (not self.reflexive):
      print "install IN flows for subnet", dpid
      self.install_in_flows(dpid, connection)
    return
  
   
  def clear_table(self, connection):
    log.debug("Clearing all flows from %s." % (dpidToStr(connection.dpid),))
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    connection.send(msg)
    return


  def reply_to_arp(self, event, match):

    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    
    #print "reply to ARP request", match.dl_dst
    r = arp()
    r.opcode = arp.REPLY
    r.hwdst = match.dl_src
    if (self.addr_is_gw(dpid, match.nw_dst.toStr())):
      r.protosrc = match.nw_dst
    mac_addr=self.find_mac_addr(dpid, inport)
    #print "mac_addr=", mac_addr
    r.hwsrc = addresses.EthAddr(mac_addr)
    r.protodst = match.nw_src
    e = ethernet(type=packet.ARP_TYPE, src=r.hwsrc, dst=r.hwdst)
    e.set_payload(r)
    log.debug("%i %i answering ARP for %s" %( dpid, inport, str(r.protosrc)))
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.in_port = inport
    event.connection.send(msg)
    return


  def reply_to_ping(self, event):
    # Reply to pings
    packet=event.parsed
    # Make the ping reply
    icmp = pkt.icmp()
    icmp.type = pkt.TYPE_ECHO_REPLY
    icmp.payload = packet.find("icmp").payload

    # Make the IP packet around it
    ipp = pkt.ipv4()
    ipp.protocol = ipp.ICMP_PROTOCOL
    packet=event.parsed
    ipp.srcip = packet.find("ipv4").dstip
    ipp.dstip = packet.find("ipv4").srcip

    # Ethernet around that...
    e = pkt.ethernet()
    e.src = packet.dst
    e.dst = packet.src
    e.type = e.IP_TYPE

    # Hook them up...
    ipp.payload = icmp
    e.payload = ipp

    # Send it back to the input port
    msg = of.ofp_packet_out()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_IN_PORT))
    msg.data = e.pack()
    msg.in_port = event.port
    event.connection.send(msg)

    log.debug("%s pinged %s", ipp.dstip, ipp.srcip)


  def resend_packet(self, event):
    print "Resend"
    msg = of.ofp_packet_out()
    #msg.buffer_id = event.ofp.buffer_id
    msg.data=event.ofp.data
    msg.in_port = event.port
    packet=event.parsed

    #if (packet.next.protocol==1):
    outport=self.find_output_port(event.dpid, packet.next.dstip.toStr())
    if (outport==-1):
      if(event.dpid==563110422331449)and(packet.next.dstip.toStr()=="192.168.1.2"):
        outport=9
      else:
        outport=1
      #print event.dpid, packet.next.dstip.toStr()
      #print "outport==-1"
      #return
    mac_addr=self.find_mac_addr(event.dpid, outport)
    msg.actions.append(of.ofp_action_dl_addr.set_src(mac_addr))
    #msg.actions.append(of.ofp_action_dl_addr.set_src("ff:ff:ff:ff:ff:ff"))
    msg.actions.append(of.ofp_action_dl_addr.set_dst("ff:ff:ff:ff:ff:ff"))
    msg.actions.append(of.ofp_action_output(port = outport))
    #if (packet.next.protocol==1):
    event.connection.send(msg)
    return
    
  def analise_ipv4_packet(self, event):
    
    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    
    log.debug("%i %i IP %s => %s", dpid, inport, str(packet.next.srcip), str(packet.next.dstip))

    
    # Learn or update port/MAC info
    """
    if packet.next.srcip in self.arpTable[dpid]:
      if self.arpTable[dpid][packet.next.srcip] != (inport, packet.src):
        log.info("%i %i RE-learned %s", dpid,inport,str(packet.next.srcip))
    else:
      log.debug("%i %i learned %s", dpid,inport,str(packet.next.srcip))
    self.arpTable[dpid][packet.next.srcip] = Entry(inport, packet.src)
    """
      
    flag=self.addr_is_gw(dpid, packet.next.dstip.toStr())
    if (packet.find("icmp")):
      if (self.addr_is_gw(dpid, packet.next.dstip.toStr())):
        self.reply_to_ping(event)
        return

    if (self.reflexive):

      next_switch=self.find_next_switch(dpid, packet.next.dstip.toStr())      
      print "next flow=", next_switch[0], next_switch[1], packet.next.dstip.toStr()
      if (next_switch[0]!=0):
        dpid2=next_switch[0]
        port2=next_switch[1]
        self.install_single_flow(self.of_switch_nodes[dpid2].connection, dpid2,\
                                   port2, event.ofp.buffer_id, packet)
          
      else:
        pass
        #print "AHTUNG!"

    #print "Resend"
    self.resend_packet(event)
      
    if (self.reflexive):
      self.install_single_flow(event.connection, dpid, inport,\
                               event.ofp.buffer_id, packet)
        
    return



  def analise_arp_packet(self, event):

    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed
    print "addr=", packet.dst
    
    a = packet.next
    log.debug("%i %i ARP %s %s => %s", dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst))

    if a.prototype == arp.PROTO_TYPE_IP:
      if a.hwtype == arp.HW_TYPE_ETHERNET:

        if a.protosrc != 0:

          # Learn or update port/MAC info
          if a.protosrc in self.arpTable[dpid]:
            if self.arpTable[dpid][a.protosrc] != (inport, packet.src):
              log.info("%i %i RE-learned %s", dpid,inport,str(a.protosrc))
          else:
            log.debug("%i %i learned %s", dpid,inport,str(a.protosrc))
          self.arpTable[dpid][a.protosrc] = Entry(inport, packet.src)

          if a.opcode == arp.REQUEST:
            # Maybe we can answer
            match=of.ofp_match.from_packet(packet)

            index=self.addr_is_gw(dpid, match.nw_dst.toStr())
            if ( match.dl_type == packet.ARP_TYPE and
                match.nw_proto == arp.REQUEST and (index!=-1)):
              #print "Arp for GW"
              self.reply_to_arp(event, match)              
              return
              
              
            elif a.protodst in self.arpTable[dpid]:
              # We have an answer...
              if not self.arpTable[dpid][a.protodst].isExpired():
                # .. and it's relatively current, so we'll reply ourselves
                r = arp()
                r.hwtype = a.hwtype
                r.prototype = a.prototype
                r.hwlen = a.hwlen
                r.protolen = a.protolen
                r.opcode = arp.REPLY
                r.hwdst = a.hwsrc
                r.protodst = a.protosrc
                r.protosrc = a.protodst
                r.hwsrc = self.arpTable[dpid][a.protodst].mac
                e = ethernet(type=packet.type, src=r.hwsrc, dst=a.hwsrc)
                e.set_payload(r)
                log.debug("%i %i answering ARP for %s" % (dpid, inport,
                str(r.protosrc)))
                msg = of.ofp_packet_out()
                msg.data = e.pack()
                msg.actions.append(of.ofp_action_output(port =
                                                          of.OFPP_IN_PORT))
                msg.in_port = inport
                event.connection.send(msg)
                return

    # Didn't know how to answer or otherwise handle this ARP, so just flood it
    log.debug("%i %i flooding ARP %s %s => %s" % (dpid, inport,
       {arp.REQUEST:"request",arp.REPLY:"reply"}.get(a.opcode,
       'op:%i' % (a.opcode,)), str(a.protosrc), str(a.protodst)))

    msg = of.ofp_packet_out(in_port = inport, action = of.ofp_action_output(port = of.OFPP_FLOOD))
    if event.ofp.buffer_id is of.NO_BUFFER:
      # Try sending the (probably incomplete) raw data
      msg.data = event.data
    else:
      msg.buffer_id = event.ofp.buffer_id
    event.connection.send(msg.pack())


  def _handle_PacketIn (self, event):

    dpid = event.connection.dpid
    inport = event.port
    packet = event.parsed

    #print "MAC=", packet.src, packet.dst

    if not packet.parsed:
      log.warning("%i %i ignoring unparsed packet", dpid, inport)
      return

    print "Packet In"

    if dpid not in self.arpTable:
      # New switch -- create an empty table
      self.arpTable[dpid] = {}

    if packet.type == ethernet.LLDP_TYPE:
      # Ignore LLDP packets
      return

    if isinstance(packet.next, ipv4):
      self.analise_ipv4_packet(event)
    elif isinstance(packet.next, arp):
      self.analise_arp_packet(event)

    return

  def _handle_FlowRemoved(self, event):
    pass
    print "Flow Removed!"
    #print "dpid=", event.dpid
    #print "priority=", event.ofp.priority

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    print "My_DPID=", event.connection.dpid
    self.of_switch_nodes[event.dpid].connection=event.connection
    self.clear_table(event.connection)
    #self.install_drop_rule(event.dpid, event.connection)

    mac_list=[]
    for i in xrange(len(event.ofp.ports)):
      mac_list.append((event.ofp.ports[i].port_no, event.ofp.ports[i].hw_addr.toStr())) #tuple
    self.of_switch_nodes[event.dpid].macTable=copy.deepcopy(mac_list)
    
  def _handle_GoingUpEvent (self, event):
    self.listenTo(core.openflow)
    log.debug("Up...")

  def _handle_SwitchReadyEvent(self, event):
    print "Switch is Ready!!!"
    dpid=event.dpid
    connection=self.of_switch_nodes[dpid].connection
    #self.clear_table(connection)
    self.install_flows(dpid, connection, self.of_switch_nodes[dpid].rule_tree)
    self.of_switch_nodes[dpid].was_used=True
    

def launch ():

  #Topology
  reload (Topology)
  reload (general_functions)
  Topo=Topology.Topology()
  #Topo.check_connection()
  Topo.new_topology()
  Topo.designate_rules_to_OF_switches()
  reflexive=True
  discovery_object=discovery.Discovery(True, True)
  switch=l3_switch(Topo._of_switch_nodes, reflexive, discovery_object)
  core.register("switch", l3_switch)
  core.register("openflow_discovery", discovery_object)
  print "OK"
  

