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
        self.sw.insertTableEntry(table_name='MyIngress.arp',
                match_fields={'meta.nextHop': [ip]},
                action_name='MyIngress.ipv4_forward',
                action_params={'dstAddr': mac})
        self.mac_for_ip[ip] = mac

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        # Send any packets that were waiting on this ARP resolution
        if pkt[ARP].hwdst == self.sw.intfs[1].MAC():
            for p in self.arp_pending_buffer.copy():
                if p[CPUMetadata].nextHop == pkt[ARP].psrc:
                    self.send(p)
                    self.arp_pending_buffer.remove(p)
        pkt[CPUMetadata].forward = 1
        pkt[CPUMetadata].egressPort = self.port_for_mac[pkt[ARP].hwdst]
        self.send(pkt)

    def handleArpRequest(self, pkt):
        # Only cache routing information for packets that will be forwarded
        if pkt[CPUMetadata].srcPort != 1:
            self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
            self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        for i in range(2, len(self.sw.intfs)):
            if i == pkt[CPUMetadata].srcPort: continue
            copy = pkt.copy()
            copy[CPUMetadata].forward = 1
            copy[CPUMetadata].egressPort = i
            self.send(copy)

    def createArpRequest(self, destIp):
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff', type=TYPE_ARP) / ARP(
                op=ARP_OP_REQ,
                hwsrc=self.sw.intfs[1].MAC(),
                psrc=self.sw.intfs[1].IP(),
                hwdst='00:00:00:00:00:00',
                pdst=destIp)
        pkt[CPUMetadata].origEtherType = TYPE_ARP
        pkt[CPUMetadata].srcPort = 1
        self.handleArpRequest(pkt)

    def handlePkt(self, pkt):
        # Ignore IPv6 packets:
        if Ether in pkt and pkt[Ether].type == TYPE_IPV6: return

        # pkt.show2()

        assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if pkt[CPUMetadata].origEtherType == TYPE_ARP and ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        elif pkt[CPUMetadata].origEtherType == TYPE_IPV4 and IP in pkt:
            if pkt[CPUMetadata].nextHop != 0:
                self.arp_pending_buffer.append(pkt)
                self.createArpRequest(pkt[CPUMetadata].nextHop)

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
