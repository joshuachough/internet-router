class TableEntry(dict):
    def __init__(self, table_name, match_fields, action_name, action_params, priority):
        super(TableEntry, self).__init__()
        self['table_name'] = table_name
        self['match_fields'] = match_fields
        self['action_name'] = action_name
        self['action_params'] = action_params
        self['priority'] = priority

    def __getattr__(self, attr):
        return self[attr]
    
    def __setattr__(self, attr, value):
        self[attr] = value

class ArpTableEntry(TableEntry):
    def __init__(self, nextHopIP, srcMAC, dstMAC):
        super(ArpTableEntry, self).__init__(
            table_name="MyIngress.arp",
            match_fields={"meta.nextHop": [nextHopIP]},
            action_name="MyIngress.ipv4_forward",
            action_params={"dstAddr": dstMAC, "srcAddr": srcMAC},
            priority=None
        )
    
class RoutingTableEntry(TableEntry):
    def __init__(self, keyIP, dstIP, port, priority, mask=0xffffffff):
        super(RoutingTableEntry, self).__init__(
            table_name="MyIngress.routing",
            match_fields={"hdr.ipv4.dstAddr": [keyIP, mask]},
            action_name="MyIngress.next_hop",
            action_params={"dstAddr": dstIP, "port": port},
            priority=priority
        )

class LocalTableEntry(TableEntry):
    def __init__(self, dstIP, t):
        super(LocalTableEntry, self).__init__(
            table_name="MyIngress.local",
            match_fields={"hdr.ipv4.dstAddr": [dstIP]},
            action_name="MyIngress.send_to_cpu",
            action_params={"type": t},
            priority=None
        )

class Table:
    def __init__(self, name, size=1024, entries=[]):
        self.name = name
        self.entries = entries
        self.size = size
    
    def __str__(self):
        return f"Table {self.name}:\n" + '\n'.join([str(entry) for entry in self.entries])

    def add_entry(self, entry):
        self.entries.append(entry)

    def remove_entry(self, entry):
        self.entries.remove(entry)

    def get_entry(self, **kwargs):
        for entry in self.entries:
            for key, value in kwargs.items():
                if entry[key] != value:
                    break
            else:
                return entry
        return None

    def get_entries(self, **kwargs):
        entries = []
        for entry in self.entries:
            for key, value in kwargs.items():
                if entry[key] != value:
                    break
            else:
                entries.append(entry)
        return entries
    
    def reset(self):
        self.entries = []
    
class RoutingTable(Table):
    def __init__(self, size=1024, entries=[]):
        super(RoutingTable, self).__init__("MyIngress.routing", size, entries)