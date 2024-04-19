import sys
sys.path.append("/home/joshua/p4app/docker/scripts")

from p4app import P4Mininet
from mininet.cli import CLI

from controller import RouterController
from my_topo import MyTopology, topology
from tables import RoutingTableEntry, LocalTableEntry

TYPE_PWOSPF_HELLO   = 0x000b
TYPE_PWOSPF_LSU     = 0x000a
TYPE_DIRECT         = 0x0009

NUM_COUNTERS        = 3
ARP_COUNTER         = 0
IP_COUNTER          = 1
CTRL_COUNTER        = 2

topo = MyTopology()
net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
net.start()

sw = net.get("s1")

# Set interface MAC and IP addresses
for i, h in enumerate(topology["switches"][0]["hosts"], start=1):
    sw.intfs[i].config(mac=h["sw_mac"], ip=h["sw_ip"])

# Add next-hop rules
for i in range(2, len(topology["switches"][0]["hosts"])+1):
    host = topology["switches"][0]["hosts"][i-1]
    sw.insertTableEntry(**RoutingTableEntry(keyIP=host['ip'], dstIP=host['ip'], port=i, priority=i))

# Fake route
sw.insertTableEntry(**RoutingTableEntry(keyIP="10.0.0.4", dstIP="10.0.0.4", port=4, priority=4))

# Add local IP rules
sw.insertTableEntry(**LocalTableEntry(dstIP="224.0.0.5", t=TYPE_PWOSPF_HELLO))
sw.insertTableEntry(**LocalTableEntry(dstIP="10.0.0.1", t=TYPE_DIRECT))

# Start the router controller
cpu = RouterController(sw)
cpu.start()

# CLI(net)

h2, h3 = net.get("h2"), net.get("h3")

# Print topology information
print('\n----- Printing topology information -----')
c1 = net.get("c1")

for i in range(len(sw.intfs)):
    print(sw.intfs[i].name, sw.intfs[i].MAC(), sw.intfs[i].IP())
print(c1.name, c1.MAC(), c1.IP())
print(h2.name, h2.MAC(), h2.IP())
print(h3.name, h3.MAC(), h3.IP())
print('')

# TODO: organize for testing presentation

# print(h2.cmd("arping -c1 10.0.0.3"))

print(h3.cmd("ping -c1 10.0.2.1"))

# print(h3.cmd("ping -c1 10.0.0.1"))

# print(h3.cmd("ping -c1 10.0.0.4"))

# print(h3.cmd("ping -c1 10.0.0.5"))

sw.printTableEntries()

# # Print packet counters
# print('\n----- Printing packetCounters -----')
# packet_count, byte_count = sw.readCounter('packetCounters', ARP_COUNTER)
# print("ARP_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))
# packet_count, byte_count = sw.readCounter('packetCounters', IP_COUNTER)
# packet_count, byte_count = sw.readCounter('packetCounters', IP_COUNTER)
# print("IP_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))
# packet_count, byte_count = sw.readCounter('packetCounters', CTRL_COUNTER)
# packet_count, byte_count = sw.readCounter('packetCounters', CTRL_COUNTER)
# print("CTRL_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))