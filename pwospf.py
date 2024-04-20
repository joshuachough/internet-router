from scapy.fields import ByteField, ShortField, IntField, LongField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP

from timers import Timer

IP_PROTO_PWOPSF     = 89
ALLSPFRouters       = "224.0.0.5"
TYPE_PWOSPF_HELLO   = 0x000b
TYPE_PWOSPF_LSU     = 0x000a

class PWOSPF(Packet):
    name = "PWOSPF"
    fields_desc = [ ByteField("version", 2),
                    ByteField("type", None),
                    ShortField("length", 0),
                    IntField("router_id", None),
                    IntField("area_id", None),
                    ShortField("checksum", None),
                    ShortField("authtype", 0),
                    LongField("auth", 0)]
    
class HELLO(Packet):
    name = "HELLO"
    fields_desc = [ IntField("netmask", None),
                    ShortField("helloint", None)]

bind_layers(IP, PWOSPF, proto=IP_PROTO_PWOPSF)
bind_layers(PWOSPF, HELLO, type=TYPE_PWOSPF_HELLO)

class PWOSPFRouter:
    def __init__(self, area_id, router_id, lsuint=30, interfaces=[]):
        self.area_id = area_id
        self.router_id = router_id
        self.lsuint = lsuint
        self.interfaces = interfaces

    def add_interface(self, *args, **kwargs):
        interface = PWOSPFInterface(self, *args, **kwargs)
        self.interfaces.append(interface)

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

        self.hello_bcast_timer = Timer(hello_bcast, {'interface': self}, self.helloint).start()

class PWOSPFNeighbor:
    def __init__(self, router_id, ip):
        self.router_id = router_id
        self.ip = ip