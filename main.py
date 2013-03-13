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
This is an L2 learning switch written directly against the OpenFlow library.
It is derived from one written live for an SDN crash course.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib import addresses
import time
import Topology, general_functions
log = core.getLogger()

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 5


class LearningSwitch (EventMixin):
  """
  The learning switch "brain" associated with a single OpenFlow switch.

  When we see a packet, we'd like to output it on a port which will
  eventually lead to the destination.  To accomplish this, we build a
  table that maps addresses to ports.

  We populate the table by observing traffic.  When we see a packet
  from some source coming from some port, we know that source is out
  that port.

  When we want to forward traffic, we look up the desintation in our
  table.  If we don't know the port, we simply send the message out
  all ports except the one it came in on.  (In the presence of loops,
  this is bad!).

  In short, our algorithm looks like this:

  For each new flow:
  1) Use source address and port to update address/port table
  2) Is destination address a Bridge Filtered address, or is Ethertpe LLDP?
     * This step is ignored if transparent = True *
     Yes:
        2a) Drop packet to avoid forwarding link-local traffic (LLDP, 802.1x)
            DONE
  3) Is destination multicast?
     Yes:
        3a) Flood the packet
            DONE
  4) Port for destination address in our address/port table?
     No:
        4a) Flood the packet
            DONE
  5) Is output port the same as input port?
     Yes:
        5a) Drop packet and similar ones for a while
  6) Install flow table entry in the switch so that this
     flow goes out the appopriate port
     6a) Send buffered packet out appopriate port
  """
  def set_protocol(self, protocol):
    if (protocol=="tcp"): return 6
    elif (protocol=="udp"): return 17
    elif (protocol=="icmp"): return 1

  def addr_to_string(self, addr, mask):
    ip_addr=str(addr[0])+"."+str(addr[1])+"."+str(addr[2])+"."+str(addr[3])
    ip_addr+="/"
    print "our mask=", mask
    ip_addr+=str(mask)
    return ip_addr
  
  def addr_to_list(self, addr):
    temp=addr.split(".")
    list_addr=[]
    for n in xrange(0,4):
      list_addr.append(int(temp[n]))
    return list_addr

  def install_flows(self, rule_tree):
    #for each rule
    print "here we install all flows"
    priority=999 #max number of rules
    for a in xrange(len(rule_tree)):# perebor po proto
        for b in xrange(len(rule_tree[a])): # perebor po src_addr 
            for c in xrange(len(rule_tree[a][b])): # perebor po src_port
                for d in xrange(len(rule_tree[a][b][c])): # perebor po dst_addr
                    for e in xrange(len(rule_tree[a][b][c][d])): # perebor po dst_port
                        for f in xrange(len(rule_tree[a][b][c][d][e])): # perebor po number
                            rule=rule_tree[a][b][c][d][e][f]
                            msg = of.ofp_flow_mod()
                            msg.priority = priority
                            msg.match.dl_type = 0x800
                            msg.match.nw_proto=self.set_protocol(rule.protocol)
                            src_addr_string=self.addr_to_string(rule.src_addr, rule.src_mask)
                            print "See here", src_addr_string
                            msg.match.nw_src = addresses.IPAddr()
                            msg.match.tp_src = rule.src_port
                            msg.match.nw_dst = addresses.IPAddr(self.addr_to_string(rule.dst_addr, rule.dst_mask))
                            msg.match.tp_dst = rule.dst_port
                            if (rule.action=="deny"):
                              pass #probably if list of actions will be empty, action will be drop by default
                            else:
                              #find output port
                              msg.actions.append(of.ofp_action_output(port = 4))
                            self.connection.send(msg)
                            priority-=1

  def clear_table(self, connection):
    log.debug("Clearing all flows from %s." % (dpidToStr(connection.dpid),))
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    connection.send(msg)
    

    
  def __init__ (self, connection, transparent, host_nodes):
    # Switch we'll be adding L2 learning switch capabilities to
    self.connection = connection
    self.transparent = transparent
    self.host_nodes=host_nodes
    self.new=True # has this switch already filled with rules?

    # Our table
    self.macToPort = {}

    # We want to hear PacketIn messages, so we listen
    self.listenTo(connection)

    self.clear_table(connection)

    #self.install_flows()
  
    #log.debug("Initializing LearningSwitch, transparent=%s",
    #          str(self.transparent))

  def handle_IP_packet (self, packet):
    ip = packet.find('ipv4')
    if ip is None:
      # This packet isn't IP!
      return False
    print "Source IP:", ip.srcip
    return True

  def find_subnet(self, src_addr):
    """
    returns index >0 in list of host_nodes if appropriate subnet was found
            -1 if subnet was not found
    """
    print "We are in find"
    for i in xrange(len(self.host_nodes)):
      if (general_functions.addr_belongs_to_subnet(self.host_nodes[i]._ip_addr, self.host_nodes[i]._ip_mask, src_addr)):
        return i
    return -1

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch to implement above algorithm.
    """

    packet = event.parse()
    if self.handle_IP_packet(packet):
      src_ip=packet.find('ipv4').srcip
      print "type=", src_ip.toStr()
      if self.new:
        self.new=False
        src_addr=self.addr_to_list(src_ip.toStr())
        index=self.find_subnet(src_addr)
        if (index!=-1):
          self.install_flows(self.host_nodes[index]._new_rule_tree)
        else:
          print "new subnet"
        

    def flood ():
      """ Floods the packet """
      if event.ofp.buffer_id == -1:
        log.warning("Not flooding unbuffered packet on %s",
                    dpidToStr(event.dpid))
        return
      msg = of.ofp_packet_out()
      if time.time() - self.connection.connect_time > FLOOD_DELAY:
        # Only flood if we've been connected for a little while...
        #log.debug("%i: flood %s -> %s", event.dpid, packet.src, packet.dst)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        pass
        #log.info("Holding down flood for %s", dpidToStr(event.dpid))
      msg.buffer_id = event.ofp.buffer_id
      msg.in_port = event.port
      self.connection.send(msg)

    def drop (duration = None):
      """
      Drops this packet and optionally installs a flow to continue
      dropping similar ones for a while
      """
      if duration is not None:
        if not isinstance(duration, tuple):
          duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = event.ofp.buffer_id
        self.connection.send(msg)
      elif event.ofp.buffer_id != -1:
        msg = of.ofp_packet_out()
        msg.buffer_id = event.ofp.buffer_id
        msg.in_port = event.port
        self.connection.send(msg)

    self.macToPort[packet.src] = event.port # 1

    if not self.transparent:
      if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered(): # 2
        drop()
        return

    if packet.dst.isMulticast():
      flood() # 3a
    else:
      if packet.dst not in self.macToPort: # 4
        log.debug("Port for %s unknown -- flooding" % (packet.dst,))
        flood() # 4a
      else:
        port = self.macToPort[packet.dst]
        if port == event.port: # 5
          # 5a
          log.warning("Same port for packet from %s -> %s on %s.  Drop." %
                      (packet.src, packet.dst, port), dpidToStr(event.dpid))
          drop(10)
          return
        # 6
        log.debug("installing flow for %s.%i -> %s.%i" %
                  (packet.src, event.port, packet.dst, port))
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = 10
        msg.hard_timeout = 30
        msg.actions.append(of.ofp_action_output(port = port))
        msg.buffer_id = event.ofp.buffer_id # 6a
        self.connection.send(msg)

class l2_learning (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent, host_nodes):
    print "init"
    self.host_nodes=host_nodes
    self.listenTo(core.openflow)
    self.transparent = transparent

  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    LearningSwitch(event.connection, self.transparent, self.host_nodes)
    # create ofp_flow_mod message to delete all flows
    # (note that flow_mods match all flows by default)
    
    

def launch (transparent=False):
  """
  Starts an L2 learning switch.
  """
  #Topology shit
  host_nodes=[1,2,3,4]
  #reload(graph)
  reload (Topology)
  Topo=Topology.Topology()
  print "QWERTY"
  #Topo.test()
  print "??????????????????????????????????????????????"
  Topo.check_connection()
  Topo.new_topology()
  core.registerNew(l2_learning, str_to_bool(transparent), Topo._host_nodes)
