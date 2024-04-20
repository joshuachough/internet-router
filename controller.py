from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, ICMP, UDP

from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf import PWOSPF, HELLO, PWOSPFRouter
from tables import ArpTableEntry
from timers import Timer
import time

ARP_OP_REQ          = 0x0001
ARP_OP_REPLY        = 0x0002

IP_PROTO_ICMP       = 1
IP_PROTO_PWOPSF     = 89

ICMP_T_ECHO_REQ     = 8
ICMP_T_ECHO_REPLY   = 0
ICMP_T_UNREACHABLE  = 3
ICMP_C_NET_UNREACH  = 0
ICMP_C_HOST_UNREACH = 1

PWOSPF_HELLO_LEN    = 32
PWOSPF_AREA         = 1
PWOSPF_HELLOINT     = 10

TYPE_ARP            = 0x0806
TYPE_CPU_METADATA   = 0x080a
TYPE_IPV4           = 0x0800
TYPE_IPV6           = 0x86dd
TYPE_UNKNOWN        = 0x000e
TYPE_ROUTER_MISS    = 0x000d
TYPE_ARP_MISS       = 0x000c
TYPE_PWOSPF_HELLO   = 0x000b
TYPE_PWOSPF_LSU     = 0x000a
TYPE_DIRECT         = 0x0009
TYPE_ARP_HIT        = 0x0008

NUM_COUNTERS        = 3
ARP_COUNTER         = 0
IP_COUNTER          = 1
CTRL_COUNTER        = 2

ARP_PENDING_TIMEOUT = 5
ARP_TE_TIMEOUT      = 10

ALLSPFRouters       = "224.0.0.5"

class RouterController(Thread):
    def __init__(self, router, router_id, start_wait=0.3):
        super(RouterController, self).__init__()
        self.router = router
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = router.intfs[1].name
        self.port_for_mac = {}
        self.mac_for_ip = {}
        self.stop_event = Event()
        self.arp_pending_buffer = [] # buffer for packets waiting on ARP resolution
        self.arp_timers = [] # timers for ARP entries
        self.routerPorts = [4]

        self.pwospf = PWOSPFRouter(PWOSPF_AREA, router_id)
        for port, intf in self.router.intfs.items():
            if port == 0 or port == 1: continue
            # Change prefix (24) into netmask (0xffffff00)
            netmask = 0xffffffff ^ (1 << 32 - int(intf.prefixLen)) - 1
            self.pwospf.add_interface(intf.IP(), netmask, self.broadcastHELLO, PWOSPF_HELLOINT, port=port, mac=intf.MAC())

    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac: return
        self.port_for_mac[mac] = port

    def addIpAddr(self, ip, mac):
        # Don't re-add the ip-mac mapping if we already have it:
        if ip in self.mac_for_ip: return
        self.addArpEntry(ip, mac)
        self.mac_for_ip[ip] = mac

    def addArpEntry(self, ip, mac):
        srcAddr = self.router.intfs[self.port_for_mac[mac]].MAC()
        table_entry = ArpTableEntry(ip, srcAddr, mac)
        self.router.insertTableEntry(**table_entry)
        self.arp_timers.append(Timer(self.removeArpEntry, {'table_entry': table_entry}, ARP_TE_TIMEOUT).start())

    def removeArpEntry(self, timer):
        table_entry = timer.payload['table_entry']
        self.router.removeTableEntry(**table_entry)
        self.arp_timers.remove(timer)
        nextHop = table_entry['match_fields']['meta.nextHop'][0]
        self.mac_for_ip.pop(nextHop)
        print('\nARP entry for {} removed'.format(nextHop))

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        # Send any packets that were waiting on this ARP resolution
        if pkt[ARP].hwdst == self.router.intfs[pkt[CPUMetadata].srcPort].MAC():
            for pending in self.arp_pending_buffer.copy():
                p = pending.payload['pkt']
                if p[CPUMetadata].nextHop == pkt[ARP].psrc:
                    self.send(p)
                    pending.cancel()
                    self.arp_pending_buffer.remove(pending)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addIpAddr(pkt[ARP].psrc, pkt[ARP].hwsrc)
        self.createArpReply(pkt)

    def createArpRequest(self, pkt):
        destIp, srcIp, srcPort = pkt[CPUMetadata].nextHop, pkt[IP].src, pkt[CPUMetadata].srcPort
        for i in range(2, len(self.router.intfs)):
            if i == srcPort or i in self.routerPorts: continue
            srcAddr = self.router.intfs[i].MAC()
            pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=srcAddr, type=TYPE_CPU_METADATA) / CPUMetadata(origEtherType=TYPE_ARP, srcPort=1, forward=1, egressPort=i) / ARP(
                op=ARP_OP_REQ,
                hwsrc=srcAddr,
                psrc=srcIp,
                hwdst='00:00:00:00:00:00',
                pdst=destIp)
            self.send(pkt)

    def createArpReply(self, pkt):
        routerPortMac = self.router.intfs[pkt[CPUMetadata].srcPort].MAC()
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

    def createICMPReply(self, pkt):
        del pkt[ICMP].chksum # Recalculate checksum
        pkt[IP].dst, pkt[IP].src = pkt[IP].src, pkt[IP].dst
        pkt[CPUMetadata].egressPort = pkt[CPUMetadata].srcPort
        pkt[CPUMetadata].srcPort = 1
        pkt[CPUMetadata].forward = 1
        pkt[Ether].dst, pkt[Ether].src = pkt[Ether].src, pkt[Ether].dst
        self.send(pkt)

    def createICMPEchoReply(self, pkt):
        # Generate ICMP echo reply
        reply = pkt.copy()
        reply[ICMP].type = ICMP_T_ECHO_REPLY
        self.createICMPReply(reply)

    def createICMPUnreachable(self, pkt, code):
        # Generate ICMP unreachable
        reply = pkt.copy()
        del reply[IP].payload # Delete the payload to avoid sending the original packet
        # Add the ICMP header
        reply[IP].proto = IP_PROTO_ICMP
        reply = reply / ICMP(type=ICMP_T_UNREACHABLE, code=code)
        self.createICMPReply(reply)

    def removeArpPendingPkt(self, pending):
        self.arp_pending_buffer.remove(pending)
        pkt = pending.payload['pkt']
        self.createICMPUnreachable(pkt, ICMP_C_HOST_UNREACH)

    def broadcastHELLO(self, timer):
        intf = timer.payload['interface']
        pkt = Ether(
            dst='ff:ff:ff:ff:ff:ff',
            src=intf.mac,
            type=TYPE_CPU_METADATA
            ) / CPUMetadata(
                origEtherType=TYPE_IPV4,
                srcPort=1,
                forward=1,
                egressPort=intf.port
                ) / IP(
                    dst=ALLSPFRouters,
                    src=intf.ip,
                    proto=IP_PROTO_PWOPSF
                    ) / PWOSPF( # how is the checksum calculated? 
                        type=TYPE_PWOSPF_HELLO,
                        length=PWOSPF_HELLO_LEN,
                        router_id=intf.router_id,
                        area_id=intf.area_id
                        ) / HELLO(
                            netmask=intf.netmask,
                            helloint=intf.helloint)
        self.send(pkt)
        timer.reset()

    def handlePkt(self, pkt):
        # Ignore IPv6 packets:
        if Ether in pkt and pkt[Ether].type == TYPE_IPV6: return
        # Ignore IGMP packets:
        if IP in pkt and pkt[IP].proto == 2: return
        # Ignore MDNS packets:
        if UDP in pkt and pkt[UDP].dport == 5353: return
        # Ignore IPv6mcast (33:33:xx:xx:xx:xx):
        if Ether in pkt and pkt[Ether].dst[:6] == '33:33:': return
        # Ignore IPv4mcast (01:00:xx:xx:xx:xx):
        if Ether in pkt and pkt[Ether].dst[:6] == '01:00:': return

        # pkt.show2()

        assert CPUMetadata in pkt, "Should only receive packets from router with special header"

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
                    self.arp_pending_buffer.append(Timer(self.removeArpPendingPkt, {'pkt': pkt}, ARP_PENDING_TIMEOUT).start())
                    self.createArpRequest(pkt)
                else:
                    print('#Error: Missing next hop')
            elif pkt[CPUMetadata].type == TYPE_ARP_HIT and pkt[CPUMetadata].arpHitNotified == 0:
                for timer in self.arp_timers:
                    table_entry = timer.payload['table_entry']
                    nextHop = table_entry['match_fields']['meta.nextHop'][0]
                    if nextHop == pkt[CPUMetadata].nextHop:
                        timer.reset()
                pkt[CPUMetadata].arpHitNotified = 1
                self.send(pkt)
            elif pkt[CPUMetadata].type == TYPE_ROUTER_MISS:
                self.createICMPUnreachable(pkt, ICMP_C_NET_UNREACH)
            elif pkt[CPUMetadata].type == TYPE_PWOSPF_HELLO:
                # TODO: Handle packets for PWOSPF HELLO
                print('Packet for PWOSPF HELLO from {} arrived at port {} ({})'.format(pkt[Ether].src, pkt[CPUMetadata].srcPort, pkt[Ether].dst))
            elif pkt[CPUMetadata].type == TYPE_DIRECT:
                if pkt[IP].proto == IP_PROTO_ICMP and ICMP in pkt:
                    if pkt[ICMP].type == ICMP_T_ECHO_REQ:
                        self.createICMPEchoReply(pkt)
                elif pkt[IP].proto == IP_PROTO_PWOPSF:
                    # TODO: Handle packets for PWOSPF LSU
                    print('Packet for PWOSPF LSU')

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
