from scapy.fields import ByteField, ShortField, XShortField, IntField, XIntField, LongField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.utils import checksum

import struct

from timers import Timer
from graph import Graph, Dijkstra

IP_PROTO_PWOPSF     = 89

PWOSPF_VERSION      = 2
PWOSPF_TYPE_HELLO   = 1
PWOSPF_TYPE_LSU     = 4
ALLSPFRouters       = "224.0.0.5"

TYPE_PWOSPF_HELLO   = 0x000b
TYPE_PWOSPF_LSU     = 0x000a

class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [ ByteField("version", PWOSPF_VERSION),
                    ByteField("type", None),
                    ShortField("length", None),
                    IntField("router_id", None),
                    IntField("area_id", None),
                    XShortField("chksum", None),
                    ShortField("authtype", 0),
                    LongField("auth", 0)]

    def post_build(self, p, pay):
        if self.length is None:
            l = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", l) + p[4:]
        if self.chksum is None:
            c = checksum(p[:16])
            p = p[:12] + struct.pack("!H", c) + p[14:]
        return p + pay
    
class HELLO(Packet):
    name = "HELLO"
    fields_desc = [ XIntField("netmask", None),
                    ShortField("helloint", None),
                    ShortField("padding", 0)]

bind_layers(IP, PWOSPF, proto=IP_PROTO_PWOPSF)
bind_layers(PWOSPF, HELLO, type=PWOSPF_TYPE_HELLO)

class PWOSPFRouter:
    def __init__(self, area_id, router_id, lsuint=30, interfaces=None):
        self.area_id = area_id
        self.router_id = router_id
        self.lsuint = lsuint
        self.interfaces = [] if interfaces is None else interfaces

        self.topodb = Graph()
        self.dijkstra = Dijkstra(self.topodb)


    def add_interface(self, *args, **kwargs):
        interface = PWOSPFInterface(self, *args, **kwargs)
        self.interfaces.append(interface)

    def find_hello_intf(self, port, netmask, helloint):
        for intf in self.interfaces:
            if intf.port == port and intf.netmask == netmask and intf.helloint == helloint:
                return intf
        return None
    
    def get_neighbor_ports(self):
        ports = []
        for intf in self.interfaces:
            if intf.has_neighbor():
                ports.append(intf.port)
        return ports
    
    def print_interfaces(self):
        print(f"Router {self.router_id} in area {self.area_id} has the following interfaces:")
        for intf in self.interfaces:
            print(f"\tInterface {intf.ip} on port {intf.port}")

class PWOSPFInterface:
    def __init__(self, router, ip, netmask, hello_bcast, helloint=10, port=None, mac=None):
        self.ip = ip
        self.netmask = netmask
        self.helloint = helloint
        self.neighbors = []

        self.area_id = router.area_id
        self.router_id = router.router_id
        self.port = port
        self.mac = mac

        self.hello_bcast_timer = Timer(hello_bcast, {'intf': self}, self.helloint).start()

    def has_neighbor(self):
        return len(self.neighbors) > 0

    def add_neighbor(self, rid, ip, hello_dead):
        neighbor = PWOSPFNeighbor(self, rid, ip, hello_dead, self.helloint*3)
        self.neighbors.append(neighbor)

    def find_neighbor(self, rid, src_ip):
        for neighbor in self.neighbors:
            if neighbor.router_id == rid and neighbor.ip == src_ip:
                neighbor.hello_dead_timer.reset()
                return True # Neighbor found
        return False # Neighbor not found
    
    def remove_neighbor(self, neighbor):
        self.neighbors.remove(neighbor)
        print('Neighbor {} ({}) removed from router {}\'s interface {}'.format(neighbor.router_id, neighbor.ip, self.router_id, self.ip))

class PWOSPFNeighbor:
    def __init__(self, intf, router_id, ip, hello_dead, hello_dead_int):
        self.router_id = router_id
        self.ip = ip

        self.hello_dead_timer = Timer(hello_dead, {'intf': intf, 'neighbor': self}, hello_dead_int).start()