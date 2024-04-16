import sys
sys.path.append("/home/joshua/p4app/docker/scripts")

from p4app import P4Mininet

from controller import RouterController
from my_topo import SingleSwitchTopo

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = SingleSwitchTopo(N)
net = P4Mininet(program="router.p4", topo=topo, auto_arp=False)
net.start()

sw = net.get("s1")

# Add forwarding rules
for i in range(2, N + 1):
    sw.insertTableEntry(
        table_name="MyIngress.routing",
        match_fields={"hdr.ipv4.dstAddr": ["10.0.0.%d" % i, 0xffffffff]},
        action_name="MyIngress.next_hop",
        action_params={"dstAddr": "10.0.0.%d" % i, "port": i},
        priority=i
    )

# Start the router controller
cpu = RouterController(sw)
cpu.start()

h2, h3 = net.get("h2"), net.get("h3")

print(h2.cmd("arping -c1 10.0.0.3"))

print(h3.cmd("ping -c1 10.0.0.2"))

# These table entries were added by the CPU:
sw.printTableEntries()
