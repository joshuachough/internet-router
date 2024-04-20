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

ALLSPFRouters = "224.0.0.5"
RouterControllerIP = "10.0.0.1"

topo = MyTopology()
net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
net.start()

# Get the routers, controllers, and hosts from the topology
routers = []
controllers = []
hosts = []
for i, router in enumerate(topology["routers"]):
    routers.append(net.get(router["name"]))
    hosts.append([])
    for host in router["hosts"]:
        if host['name'][0] == 'c':
            controllers.append(net.get(host['name']))
        else:
            hosts[i].append(net.get(host['name']))

# Set interface MAC and IP addresses
for i in range(len(routers)):
    for j, h in enumerate(topology["routers"][i]["hosts"], start=1):
        routers[i].intfs[j].config(mac=h["rmac"], ip=h["rip"])
link = topology["links"][0]
routers[0].intfs[link["port1"]].config(mac=link["r1mac"], ip=link["r1ip"])
routers[1].intfs[link["port2"]].config(mac=link["r2mac"], ip=link["r2ip"])

# # Fake route
# routers[0].insertTableEntry(**RoutingTableEntry(keyIP="10.0.0.4", dstIP="10.0.0.4", port=4, priority=4))

# Add local IP rules
for router in routers:
    router.insertTableEntry(**LocalTableEntry(dstIP=ALLSPFRouters, t=TYPE_PWOSPF_HELLO))
    router.insertTableEntry(**LocalTableEntry(dstIP=RouterControllerIP, t=TYPE_DIRECT))

# Start the router controllers
cpus = [RouterController(routers[i], i+1, topology["routers"][i]["hosts"]) for i in range(len(routers))]
for cpu in cpus:
    cpu.start()

# CLI(net)

# Print topology information
print('\n----- Printing topology information -----')
for i, router in enumerate(routers):
    print(router.intfs)
    for intf in router.intfs.values():
        print(intf.name, intf.MAC(), intf.IP(), intf.prefixLen)
        
    print(controllers[i].name, controllers[i].MAC(), controllers[i].IP())
    for host in hosts[i]:
        print(host.name, host.MAC(), host.IP())
print('')

# TODO: organize for testing presentation

# print(hosts[0][0].cmd("arping -c1 10.0.0.3"))

# print(hosts[0][1].cmd("ping -c1 10.0.2.1"))

# print(hosts[0][1].cmd("ping -c1 10.0.0.1"))

# print(hosts[0][1].cmd("ping -c1 10.0.0.4"))

# print(hosts[0][1].cmd("ping -c1 10.0.0.5"))

for router in routers:
    router.printTableEntries()

# # Print packet counters
# print('\n----- Printing r1 packetCounters -----')
# packet_count, byte_count = r1.readCounter('packetCounters', ARP_COUNTER)
# print("ARP_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))
# packet_count, byte_count = r1.readCounter('packetCounters', IP_COUNTER)
# print("IP_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))
# packet_count, byte_count = r1.readCounter('packetCounters', CTRL_COUNTER)
# print("CTRL_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))
# print('\n----- Printing r2 packetCounters -----')
# packet_count, byte_count = r2.readCounter('packetCounters', ARP_COUNTER)
# print("ARP_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))
# packet_count, byte_count = r2.readCounter('packetCounters', IP_COUNTER)
# print("IP_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))
# packet_count, byte_count = r2.readCounter('packetCounters', CTRL_COUNTER)
# print("CTRL_COUNTER: {} packets, {} bytes".format(packet_count, byte_count))