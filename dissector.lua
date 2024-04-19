-- LUA Dissector for the CPU_Metadata protocol for Wireshark
cpu_metadata = Proto("CPU_Metadata",  "CPU_Metadata Protocol")

from_CPU          = ProtoField.uint8("cpumeta.from_CPU"         , "fromCPU"       , base.HEX)
orig_ethertype    = ProtoField.uint16("cpumeta.orig_ethertype"  , "origEtherType" , base.HEX)
src_port          = ProtoField.uint16("cpumeta.src_port"        , "srcPort"       , base.HEX)
forward           = ProtoField.uint8("cpumeta.forward"          , "forward"       , base.HEX)
egress_port       = ProtoField.uint16("cpumeta.egress_port"     , "egressPort"    , base.HEX)
next_hop          = ProtoField.ipv4("cpumeta.next_hop"          , "nextHop"       , base.HEX)
type              = ProtoField.uint16("cpumeta.type"            , "type"          , base.HEX)

cpu_metadata.fields = { from_CPU, orig_ethertype, src_port, forward, egress_port, next_hop, type, arp_hit_notified }

function cpu_metadata.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = cpu_metadata.name

  local subtree = tree:add(cpu_metadata, buffer(), "CPU_Metadata Protocol Data")

  subtree:add(from_CPU,         buffer(0, 1))

  local orig_ethertype_number = buffer(1, 2):uint()
  local orig_ethertype_name = get_ethertype_name(orig_ethertype_number)
  subtree:add(orig_ethertype,   buffer(1, 2)):append_text(" (" .. orig_ethertype_name .. ")")

  subtree:add(src_port,         buffer(3, 2))
  subtree:add(forward,          buffer(5, 1))
  subtree:add(egress_port,      buffer(6, 2))
  subtree:add(next_hop,         buffer(8, 4))

  local type_number = buffer(12, 2):uint()
  local type_name = get_type_name(type_number)
  subtree:add(type,             buffer(12, 2)):append_text(" (" .. type_name .. ")")
end

function get_ethertype_name(opcode)
  local name = "Unknown"

      if opcode == 0x0806 then name = "TYPE_ARP"
  elseif opcode == 0x0800 then name = "TYPE_IPV4" end

  return name
end

function get_type_name(opcode)
  local name = "Unknown"

      if opcode == 0x0806 then name = "TYPE_ARP"
  elseif opcode == 0x000a then name = "TYPE_UNKNOWN"
  elseif opcode == 0x000b then name = "TYPE_ROUTER_MISS"
  elseif opcode == 0x000c then name = "TYPE_ARP_MISS"
  elseif opcode == 0x000d then name = "TYPE_PWOSPF_HELLO"
  elseif opcode == 0x000e then name = "TYPE_PWOSPF_LSU" end

  return name
end

local ethertype_table = DissectorTable.get("ethertype")
ethertype_table:add(0x080a, cpu_metadata)