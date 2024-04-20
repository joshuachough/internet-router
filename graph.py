import heapq

class Edge:
    def __init__(self, to, weight, data, ip_address):
        self.to = to
        self.weight = weight
        self.data = data
        self.ip_address = ip_address

class Graph:
    def __init__(self):
        self.adjacency_list = {}
        self.ip_to_node = {}

    def add_node(self, node, ip_address):
        self.adjacency_list[node] = []
        self.ip_to_node[ip_address] = node

    def add_edge(self, from_node, to_node, weight, data, ip_address):
        edge = Edge(to_node, weight, data, ip_address)
        self.adjacency_list[from_node].append(edge)

    def remove_edge(self, from_node, to_node):
        for edge in self.adjacency_list[from_node]:
            if edge.to == to_node:
                self.adjacency_list[from_node].remove(edge)
                break

    def print_graph(self):
        for node in self.adjacency_list:
            edges = []
            for edge in self.adjacency_list[node]:
                edges.append(f"{edge.to}({edge.weight})")
            print(f"{node}: {' '.join(edges)}")

class Dijkstra:
    def __init__(self, graph):
        self.graph = graph

    def calculate_shortest_path(self, start_node, end_ip):
        end_node = self.graph.ip_to_node[end_ip]
        shortest_distances = {node: float('infinity') for node in self.graph.adjacency_list}
        previous_nodes = {node: None for node in self.graph.adjacency_list}
        shortest_distances[start_node] = 0
        heap = [(0, start_node)]
        while heap:
            current_distance, current_node = heapq.heappop(heap)
            if current_distance > shortest_distances[current_node]:
                continue
            for edge in self.graph.adjacency_list[current_node]:
                distance = current_distance + edge.weight
                if distance < shortest_distances[edge.to]:
                    shortest_distances[edge.to] = distance
                    previous_nodes[edge.to] = current_node
                    heapq.heappush(heap, (distance, edge.to))
        path = []
        current_node = end_node
        while current_node is not None:
            path.append(current_node)
            current_node = previous_nodes[current_node]
        path.reverse()
        return shortest_distances[end_node], path
    
    def get_edges_from_path(self, path):
        edges = []
        for i in range(len(path) - 1):
            start_node = path[i]
            end_node = path[i + 1]
            for edge in self.graph.adjacency_list[start_node]:
                if edge.to == end_node:
                    edges.append(edge)
                    break
        return edges

    def get_shortest_edge_path(self, start_node, end_ip):
        _, path = self.calculate_shortest_path(start_node, end_ip)
        edges = self.get_edges_from_path(path)
        return edges
    
    def print_edges(self, edges):
        for i, edge in enumerate(edges):
            print(f"Edge {i + 1}:")
            print(f"    To: {edge.to}")
            print(f"    Weight: {edge.weight}")
            print(f"    Data: {edge.data}")
            print(f"    IP Address: {edge.ip_address}")

    def calculate_all_shortest_paths(self):
        all_shortest_paths = {}
        for start_node in self.graph.adjacency_list:
            all_shortest_paths[start_node] = {}
            for end_ip in self.graph.ip_to_node:
                distance, path = self.calculate_shortest_path(start_node, end_ip)
                all_shortest_paths[start_node][end_ip] = {'distance': distance, 'path': path}
        return all_shortest_paths

    def print_all_shortest_paths(self, paths=None):
        if paths is None:
            paths = self.calculate_all_shortest_paths()
        for start_node in paths:
            for end_ip in paths[start_node]:
                distance = paths[start_node][end_ip]['distance']
                path = ' -> '.join(paths[start_node][end_ip]['path'])
                print(f"Shortest path from {start_node} to {end_ip}: {path} (distance: {distance})")

    def calculate_next_hop(self, start_node):
        all_shortest_paths = self.calculate_all_shortest_paths()
        print(f"Next hop for {start_node}:")
        self.print_all_shortest_paths(all_shortest_paths)
        next_hop = {}
        for end_node in all_shortest_paths[start_node]:
            distance = all_shortest_paths[start_node][end_node]['distance']
            if distance != float('infinity') and distance > 0:
                path = all_shortest_paths[start_node][end_node]['path']
                edges = self.get_edges_from_path(path)
                self.print_edges(edges)
                next_hop[end_node] = {
                    'ip': edges[0].ip_address,
                    'netmask': edges[0].data['netmask'],
                    'port': edges[0].data['port'],
                    'mac': edges[0].data['mac'],
                    'router_id': edges[0].to if '.' not in edges[0].to else None
                }
        return next_hop