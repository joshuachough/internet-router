from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time

ARP_OP_REQ = 0x0001
ARP_OP_REPLY = 0x0002

TYPE_ARP = 0x0806
TYPE_CPU_METADATA = 0x080a
TYPE_IPV4 = 0x0800
TYPE_IPV6 = 0x86dd
TYPE_UNKNOWN = 0x000a
TYPE_LOCAL_IP = 0x000b
TYPE_ROUTER_MISS = 0x000c
TYPE_ARP_MISS = 0x000d
TYPE_PWOSPF = 0x000e

NUM_COUNTERS = 3
ARP_COUNTER = 0
IP_COUNTER = 1
CTRL_COUNTER = 2

class RouterController(Thread):
    def __init__(self, sw, start_wait=0.3):
        super(RouterController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}
        self.stop_event = Event()
        self.arp_pending_buffer = [] # buffer for packets waiting on ARP resolution

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return
        self.port_for_mac[mac] = port

    def addIpAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return
        srcAddr = self.sw.intfs[self.port_for_mac[mac]].MAC()
        self.sw.insertTableEntry(table_name='MyIngress.arp',
                match_fields={'meta.nextHop': [ip]},
                action_name='MyIngress.ipv4_forward',
                action_params={'dstAddr': mac, 'srcAddr': srcAddr})
        self.mac_for_ip[ip] = mac

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        # Send any packets that were waiting on this ARP resolution
        if pkt[ARP].hwdst == self.sw.intfs[pkt[CPUMetadata].srcPort].MAC():
            for p in self.arp_pending_buffer.copy():
                if p[CPUMetadata].nextHop == pkt[ARP].psrc:
                    self.send(p)
                    self.arp_pending_buffer.remove(p)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.createArpReply(pkt)

    def createArpRequest(self, pkt):
        destIp, srcIp, srcPort = pkt[CPUMetadata].nextHop, pkt[IP].src, pkt[CPUMetadata].srcPort
        for i in range(2, len(self.sw.intfs)):
            if i == srcPort: continue
            srcAddr = self.sw.intfs[i].MAC()
            pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=srcAddr, type=TYPE_CPU_METADATA) / CPUMetadata(origEtherType=TYPE_ARP, srcPort=1, forward=1, egressPort=i) / ARP(
                op=ARP_OP_REQ,
                hwsrc=srcAddr,
                psrc=srcIp,
                hwdst='00:00:00:00:00:00',
                pdst=destIp)
            self.send(pkt)

    def createArpReply(self, pkt):
        routerPortMac = self.sw.intfs[pkt[CPUMetadata].srcPort].MAC()
        reply = pkt.copy()
        reply[ARP].op = ARP_OP_REPLY
        reply[ARP].hwdst = pkt[ARP].hwsrc
        reply[ARP].pdst = pkt[ARP].psrc
        reply[ARP].hwsrc = routerPortMac
        reply[ARP].psrc = pkt[ARP].pdst
        reply[CPUMetadata].origEtherType = TYPE_ARP
        reply[CPUMetadata].srcPort = 1
        reply[CPUMetadata].forward = 1
        reply[CPUMetadata].egressPort = pkt[CPUMetadata].srcPort
        reply[Ether].dst = pkt[Ether].src
        reply[Ether].src = routerPortMac
        self.send(reply)

    def handlePkt(self, pkt):
        # Ignore IPv6 packets:
        if Ether in pkt and pkt[Ether].type == TYPE_IPV6: return

        # pkt.show2()

        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if pkt[CPUMetadata].type == TYPE_ARP and ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        elif IP in pkt:
            if pkt[CPUMetadata].type == TYPE_ARP_MISS:
                if pkt[CPUMetadata].nextHop != '0.0.0.0':
                    self.arp_pending_buffer.append(pkt)
                    self.createArpRequest(pkt)
                else:
                    print('#Error: Missing next hop')
            elif pkt[CPUMetadata].type == TYPE_ROUTER_MISS:
                print('#Warning: Packet missed routing table')
            elif pkt[CPUMetadata].type == TYPE_LOCAL_IP:
                # TODO: Handle packets for local IP
                print('Packet for local IP')
            elif pkt[CPUMetadata].type == TYPE_PWOSPF:
                # TODO: Handle packets for PWOSPF
                print('Packet for PWOSPF')

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(RouterController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(RouterController, self).join(*args, **kwargs)
