/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IPV4         = 0x0800;
const bit<16> TYPE_UNKNOWN      = 0x000e;
const bit<16> TYPE_ROUTER_MISS  = 0x000d;
const bit<16> TYPE_ARP_MISS     = 0x000c;
const bit<16> TYPE_PWOSPF_HELLO = 0x000b;
const bit<16> TYPE_PWOSPF_LSU   = 0x000a;
const bit<16> TYPE_DIRECT       = 0x0009;

const bit<8> TYPE_ICMP          = 0x01;

const bit<32> NUM_COUNTERS      = 3;
const bit<32> ARP_COUNTER       = 0;
const bit<32> IP_COUNTER        = 1;
const bit<32> CTRL_COUNTER      = 2;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<8> forward;
    bit<16> egressPort;
    ip4Addr_t nextHop;
    bit<16> type;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> checksum;
    bit<32> rest;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
    icmp_t            icmp;
}

struct metadata {
    bit<1> routed;
    ip4Addr_t nextHop;
    bit<1> countArp;
    bit<1> countIp;
    bit<1> countCtrl;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid(), {
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr
        }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    counter(NUM_COUNTERS, CounterType.packets_and_bytes) packetCounters;

    action initMeta() {
        meta.routed = 0;
        meta.nextHop = 0;
        meta.countArp = 0;
        meta.countIp = 0;
        meta.countCtrl = 0;
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
        meta.routed = 1;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu(bit<16> type) {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
        hdr.cpu_metadata.type = type;
        meta.countCtrl = 1;
    }

    // Set the next hop ip address (and port) and apply the ARP table to get the MAC address
    action next_hop(ip4Addr_t dstAddr, port_t port) {
        set_egr(port);
        meta.nextHop = dstAddr;
    }

    // Forward the packet to the next hop using the MAC address
    action ipv4_forward(macAddr_t dstAddr, macAddr_t srcAddr) {
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.countIp = 1;
    }

    // On routing table miss, send the packet to the CPU
    action routing_miss() {
        send_to_cpu(TYPE_ROUTER_MISS);
    }

    // On arp table miss, send the packet to the CPU
    action arp_miss() {
        send_to_cpu(TYPE_ARP_MISS);
        hdr.cpu_metadata.nextHop = meta.nextHop;
    }
    
    table routing {
        key = {
            hdr.ipv4.dstAddr: ternary;
        }
        actions = {
            next_hop;
            routing_miss;
        }
        size = 1024;
        default_action = routing_miss();
    }

    table arp {
        key = {
            meta.nextHop: exact;
        }
        actions = {
            ipv4_forward;
            arp_miss;
        }
        size = 1024;
        default_action = arp_miss();
    }

    table local {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            send_to_cpu;
            NoAction;
        }
        size = 1024; 
        default_action = NoAction;
    }

    apply {
        initMeta();

        if (standard_metadata.ingress_port == CPU_PORT) {
            if (hdr.cpu_metadata.isValid() && hdr.cpu_metadata.forward == 1)
                set_egr((bit<9>)hdr.cpu_metadata.egressPort);
            cpu_meta_decap();
        }
        if (meta.routed == 0) {
            if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
                meta.countArp = 1;
                send_to_cpu(TYPE_ARP);
            }
            else if (hdr.ipv4.isValid()) {
                if (hdr.ipv4.ttl == 0)
                    drop();

                if (local.apply().miss) {
                    if (routing.apply().hit) {
                        arp.apply();
                    }
                }
            }
            else {
                send_to_cpu(TYPE_UNKNOWN);
            }
        }

        // Handle counters
        if (meta.countArp == 1) {
            packetCounters.count(ARP_COUNTER);
        }
        else if (meta.countIp == 1) {
            packetCounters.count(IP_COUNTER);
        }
        else if (meta.countCtrl == 1) {
            packetCounters.count(CTRL_COUNTER);
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid(), {
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.diffserv,
            hdr.ipv4.totalLen,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.fragOffset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.srcAddr,
            hdr.ipv4.dstAddr
        }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
