from mininet.topo import Topo

topology = {
    "routers": [
        {
            "name": "r1",
            "hosts": [
                {
                    "name": "c1",
                    "ip": "10.0.0.1",
                    "mac": "00:00:00:00:00:01",
                    "rmac": "00:00:00:00:00:11",
                    "rip": "10.0.0.0/24"
                },
                {
                    "name": "h2",
                    "ip": "10.0.2.1",
                    "mac": "00:00:00:00:00:02",
                    "rmac": "00:00:00:00:00:22",
                    "rip": "10.0.2.0/24"
                },
                {
                    "name": "h3",
                    "ip": "10.0.3.1",
                    "mac": "00:00:00:00:00:03",
                    "rmac": "00:00:00:00:00:33",
                    "rip": "10.0.3.0/24"
                }
            ]
        },
        {
            "name": "r2",
            "hosts": [
                {
                    "name": "c2",
                    "ip": "10.0.4.1",
                    "mac": "00:00:00:00:00:04",
                    "rmac": "00:00:00:00:00:44",
                    "rip": "10.0.4.0/24"
                },
                {
                    "name": "h5",
                    "ip": "10.0.5.1",
                    "mac": "00:00:00:00:00:05",
                    "rmac": "00:00:00:00:00:55",
                    "rip": "10.0.5.0/24"
                }
            ]
        }
    ],
    "links": [
        {
            "name": "r1-r2",
            "port1": 4,
            "port2": 3,
            "r1mac": "00:00:00:00:00:aa",
            "r2mac": "00:00:00:00:00:bb",
            "r1ip": "10.0.a.0/24",
            "r2ip": "10.0.a.1/24"
        }
    ]
}

class MyTopology(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        for r in topology["routers"]:

            self.addSwitch(r['name'])

            for i, h in enumerate(r["hosts"], start=1):
                self.addHost(h["name"], ip=h["ip"], mac=h["mac"])
                self.addLink(h["name"], r['name'], port2=i)

        for link in topology["links"]:
            
            r1, r2 = link["name"].split("-")
            self.addLink(r1, r2, port1=link["port1"], port2=link["port2"])