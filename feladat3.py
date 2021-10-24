from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr,EthAddr,parse_cidr
from pox.lib.addresses import IP_BROADCAST, IP_ANY
from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.proto.dhcpd import DHCPLease, DHCPD
from collections import defaultdict
from pox.openflow.discovery import Discovery
import time
log = core.getLogger("f.t_p")
adjacency = defaultdict(lambda:defaultdict(lambda:None))
switches_by_dpid = {}
switches_by_id = {}
path_map = defaultdict(lambda:defaultdict(lambda:(None,None)))
def dpid_to_mac (dpid):
  return EthAddr("%012x" % (dpid & 0xffFFffFFffFF,))
def _calc_paths ():
  def dump ():
    for i in sws:
      for j in sws:
        a = path_map[i][j][0]
        if a is None: a = "*"
        print a,
      print
  sws = switches_by_dpid.values()
  path_map.clear()
  for k in sws:
    for j,port in adjacency[k].iteritems():
      if port is None: continue
      path_map[k][j] = (1,None)
    path_map[k][k] = (0,None)
  for k in sws:
    for i in sws:
      for j in sws:
        if path_map[i][k][0] is not None:
          if path_map[k][j][0] is not None:
            ikj_dist = path_map[i][k][0]+path_map[k][j][0]
            if path_map[i][j][0] is None or ikj_dist < path_map[i][j][0]:
              path_map[i][j] = (ikj_dist, k)
def _get_raw_path (src, dst):
  if len(path_map) == 0: _calc_paths()
  if src is dst:
    return []
  if path_map[src][dst][0] is None:
    return None
  intermediate = path_map[src][dst][1]
  if intermediate is None:
    return []
  return _get_raw_path(src, intermediate) + [intermediate] + \
         _get_raw_path(intermediate, dst)
def _get_path (src, dst):
  if src == dst:
    path = [src]
  else:
    path = _get_raw_path(src, dst)
    if path is None: return None
    path = [src] + path + [dst]
  r = []
  for s1,s2 in zip(path[:-1],path[1:]):
    out_port = adjacency[s1][s2]
    r.append((s1,out_port))
    in_port = adjacency[s2][s1]
  return r
def ipinfo (ip):
  parts = [int(x) for x in str(ip).split('.')]
  ID = parts[1]
  port = parts[2]
  num = parts[3]
  return switches_by_id.get(ID),port,num
class TopoSwitch (DHCPD):
  _eventMixin_events = set([DHCPLease])
  _next_id = 100
  def __repr__ (self):
    try:
      return "[%s/%s]" % (dpid_to_str(self.connection.dpid),self._id)
    except:
      return "[Unknown]"
  def __init__ (self):
    self.log = log.getChild("Unknown")
    self.connection = None
    self.ports = None
    self.dpid = None
    self._listeners = None
    self._connected_at = None
    self._id = None
    self.subnet = None
    self.network = None
    self._install_flow = False
    self.mac = None
    self.ip_to_mac = {}
    self.addListenerByName("DHCPLease", self._on_lease)
    core.ARPHelper.addListeners(self)
  def _handle_ARPRequest (self, event):
    if ipinfo(event.ip)[0] is not self: return
    event.reply = self.mac
  def send_table (self):
    if self.connection is None:
      self.log.debug("Can't send table: disconnected")
      return
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    self.connection.send(clear)
    self.connection.send(of.ofp_barrier_request())
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_proto = pkt.ipv4.UDP_PROTOCOL
    msg.match.tp_src = pkt.dhcp.CLIENT_PORT
    msg.match.tp_dst = pkt.dhcp.SERVER_PORT
    msg.actions.append(of.ofp_action_output(port = of.OFPP_CONTROLLER))
    self.connection.send(msg)
    core.openflow_discovery.install_flow(self.connection)
    src = self
    for dst in switches_by_dpid.itervalues():
      if dst is src: continue
      p = _get_path(src, dst)
      if p is None: continue
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      msg.match.nw_dst = "%s/%s" % (dst.network, "255.255.0.0")
      msg.actions.append(of.ofp_action_output(port=p[0][1]))
      self.connection.send(msg)
    for ip,mac in self.ip_to_mac.iteritems():
      self._send_rewrite_rule(ip, mac)
    flood_ports = []
    for port in self.ports:
      p = port.port_no
      if p < 0 or p >= of.OFPP_MAX: continue
      if core.openflow_discovery.is_edge_port(self.dpid, p):
        flood_ports.append(p)
      msg = of.ofp_flow_mod()
      msg.priority -= 1
      msg.match = of.ofp_match()
      msg.match.dl_type = pkt.ethernet.IP_TYPE
      msg.match.nw_dst = "10.%s.%s.0/255.255.255.0" % (self._id,p)
      msg.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
      self.connection.send(msg)
    msg = of.ofp_flow_mod()
    msg.priority -= 1
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_dst = "255.255.255.255"
    for p in flood_ports:
      msg.actions.append(of.ofp_action_output(port=p))
    self.connection.send(msg)
  def _send_rewrite_rule (self, ip, mac):
    p = ipinfo(ip)[1]
    msg = of.ofp_flow_mod()
    msg.match = of.ofp_match()
    msg.match.dl_type = pkt.ethernet.IP_TYPE
    msg.match.nw_dst = ip
    msg.actions.append(of.ofp_action_dl_addr.set_src(self.mac))
    msg.actions.append(of.ofp_action_dl_addr.set_dst(mac))
    msg.actions.append(of.ofp_action_output(port=p))
    self.connection.send(msg)
  def disconnect (self):
    if self.connection is not None:
      log.debug("Disconnect %s" % (self.connection,))
      self.connection.removeListeners(self._listeners)
      self.connection = None
      self._listeners = None
  def connect (self, connection):
    if connection is None:
      self.log.warn("Can't connect to nothing")
      return
    if self.dpid is None:
      self.dpid = connection.dpid
    assert self.dpid == connection.dpid
    if self.ports is None:
      self.ports = connection.features.ports
    self.disconnect()
    self.connection = connection
    self._listeners = self.listenTo(connection)
    self._connected_at = time.time()
    label = dpid_to_str(connection.dpid)
    self.log = log.getChild(label)
    self.log.debug("Connect %s" % (connection,))
    if self._id is None:
      if self.dpid not in switches_by_id and self.dpid <= 254:
        self._id = self.dpid
      else:
        self._id = TopoSwitch._next_id
        TopoSwitch._next_id += 1
      switches_by_id[self._id] = self
    self.network = IPAddr("10.%s.0.0" % (self._id,))
    self.mac = dpid_to_mac(self.dpid)
    con = connection
    log.debug("Disabling flooding for %i ports", len(con.ports))
    for p in con.ports.itervalues():
      if p.port_no >= of.OFPP_MAX: continue
      pm = of.ofp_port_mod(port_no=p.port_no,
                          hw_addr=p.hw_addr,
                          config = of.OFPPC_NO_FLOOD,
                          mask = of.OFPPC_NO_FLOOD)
      con.send(pm)
    con.send(of.ofp_barrier_request())
    con.send(of.ofp_features_request())
    self.send_table()
    def fix_addr (addr, backup):
      if addr is None: return None
      if addr is (): return IPAddr(backup)
      return IPAddr(addr)
    self.ip_addr = IPAddr("10.%s.0.1" % (self._id,))
    self.router_addr = None
    self.dns_addr = None 
    self.subnet = IPAddr("255.0.0.0")
    self.pools = {}
    for p in connection.ports:
      if p < 0 or p >= of.OFPP_MAX: continue
      self.pools[p] = [IPAddr("10.%s.%s.%s" % (self._id,p,n))
                       for n in range(1,255)]
    self.lease_time = 60 * 60
    self.offers = {}
    self.leases = {}
  def _get_pool (self, event):
    pool = self.pools.get(event.port)
    if pool is None:
      log.warn("No IP pool for port %s", event.port)
    return pool
  def _handle_ConnectionDown (self, event):
    self.disconnect()
  def _mac_learn (self, mac, ip):
    if ip.inNetwork(self.network,"255.255.0.0"):
      if self.ip_to_mac.get(ip) != mac:
        self.ip_to_mac[ip] = mac
        self._send_rewrite_rule(ip, mac)
        return True
    return False
  def _on_lease (self, event):
    if self._mac_learn(event.host_mac, event.ip):
        self.log.debug("Learn %s -> %s by DHCP Lease",event.ip,event.host_mac)
  def _handle_PacketIn (self, event):
    packet = event.parsed
    arpp = packet.find('arp')
    if arpp is not None:
      if event.port != ipinfo(arpp.protosrc)[1]:
        self.log.warn("%s has incorrect IP %s", arpp.hwsrc, arpp.protosrc)
        return
      if self._mac_learn(packet.src, arpp.protosrc):
        self.log.debug("Learn %s -> %s by ARP",arpp.protosrc,packet.src)
    else:
      ipp = packet.find('ipv4')
      if ipp is not None:
        sw,p,_= ipinfo(ipp.dstip)
        if sw is self:
          log.debug("Need MAC for %s", ipp.dstip)
          core.ARPHelper.send_arp_request(event.connection,ipp.dstip,port=p)
    return super(TopoSwitch,self)._handle_PacketIn(event)
class topo_addressing (object):
  def __init__ (self):
    core.listen_to_dependencies(self, listen_args={'openflow':{'priority':0}})
  def _handle_ARPHelper_ARPRequest (self, event):
    pass
  def _handle_openflow_discovery_LinkEvent (self, event):
    def flip (link):
      return Discovery.Link(link[2],link[3], link[0],link[1])
    l = event.link
    sw1 = switches_by_dpid[l.dpid1]
    sw2 = switches_by_dpid[l.dpid2]
    clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    for sw in switches_by_dpid.itervalues():
      if sw.connection is None: continue
      sw.connection.send(clear)
    path_map.clear()
    if event.removed:
      if sw2 in adjacency[sw1]: del adjacency[sw1][sw2]
      if sw1 in adjacency[sw2]: del adjacency[sw2][sw1]
      for ll in core.openflow_discovery.adjacency:
        if ll.dpid1 == l.dpid1 and ll.dpid2 == l.dpid2:
          if flip(ll) in core.openflow_discovery.adjacency:
            adjacency[sw1][sw2] = ll.port1
            adjacency[sw2][sw1] = ll.port2
            break
    else:
      if adjacency[sw1][sw2] is None:
        if flip(l) in core.openflow_discovery.adjacency:
          adjacency[sw1][sw2] = l.port1
          adjacency[sw2][sw1] = l.port2
    for sw in switches_by_dpid.itervalues():
      sw.send_table()
  def _handle_openflow_ConnectionUp (self, event):
    sw = switches_by_dpid.get(event.dpid)
    if sw is None:
      sw = TopoSwitch()
      switches_by_dpid[event.dpid] = sw
      sw.connect(event.connection)
    else:
      sw.connect(event.connection)
def launch (debug = False):
  core.registerNew(topo_addressing)
  from proto.arp_helper import launch
  launch(eat_packets=False)
  if not debug:
    core.getLogger("proto.arp_helper").setLevel(99)
