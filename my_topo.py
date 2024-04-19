from mininet.topo import Topo

topology = {
    "switches": [
        {
            "name": "s1",
            "hosts": [
                {
                    "name": "c1",
                    "ip": "10.0.0.1",
                    "mac": "00:00:00:00:00:01",
                    "sw_mac": "00:00:00:00:00:11",
                    "sw_ip": "10.0.0.0/24"
                },
                {
                    "name": "h2",
                    "ip": "10.0.2.1",
                    "mac": "00:00:00:00:00:02",
                    "sw_mac": "00:00:00:00:00:22",
                    "sw_ip": "10.0.2.0/24"
                },
                {
                    "name": "h3",
                    "ip": "10.0.3.1",
                    "mac": "00:00:00:00:00:03",
                    "sw_mac": "00:00:00:00:00:33",
                    "sw_ip": "10.0.3.0/24"
                }
            ]
        }
    ],
}

class MyTopology(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        for sw in topology["switches"]:

            self.addSwitch(sw['name'])

            for i, h in enumerate(sw["hosts"], start=1):
                self.addHost(h["name"], ip=h["ip"], mac=h["mac"])
                self.addLink(h["name"], sw['name'], port2=i)