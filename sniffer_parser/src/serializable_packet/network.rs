//! Network level Packets Representation

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::Packet;
use pnet::util::MacAddr;
use serde::Serialize;

/// ARP Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableArpPacket {
    pub hardware_type: String,
    pub protocol_type: u16,
    pub hw_addr_len: u8,
    pub proto_addr_len: u8,
    pub operation: String,
    pub sender_hw_addr: MacAddr,
    pub sender_proto_addr: Ipv4Addr,
    pub target_hw_addr: MacAddr,
    pub target_proto_addr: Ipv4Addr,
    pub length: usize,
}

impl<'a> From<&ArpPacket<'a>> for SerializableArpPacket {
    fn from(packet: &ArpPacket<'a>) -> Self {
        SerializableArpPacket {
            hardware_type: format!("{:?}", packet.get_hardware_type()),
            protocol_type: packet.get_protocol_type().0,
            hw_addr_len: packet.get_hw_addr_len(),
            proto_addr_len: packet.get_proto_addr_len(),
            operation: match packet.get_operation() {
                ArpOperations::Reply => format!("ARP Reply ({})", packet.get_operation().0),
                ArpOperations::Request => format!("ARP Request ({})", packet.get_operation().0),
                _ => format!("ARP Unknown ({})", packet.get_operation().0),
            },
            sender_hw_addr: packet.get_sender_hw_addr(),
            sender_proto_addr: packet.get_sender_proto_addr(),
            target_hw_addr: packet.get_target_hw_addr(),
            target_proto_addr: packet.get_target_proto_addr(),
            length: packet.payload().len(),
        }
    }
}

impl fmt::Display for SerializableArpPacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ARP Packet: \n\
            \tHardware Type: {}\n\
            \tProtocol Type: {}\n\
            \tHW Addr Length: {}\n\
            \tProto Addr Length: {}\n\
            \tOperation: {}\n\
            \tSender HW Addr: {}\n\
            \tSender Proto Addr: {}\n\
            \tTarget HW Addr: {}\n\
            \tTarget Proto Addr: {}\n\
            \tLength: {}",
            self.hardware_type,
            self.protocol_type,
            self.hw_addr_len,
            self.proto_addr_len,
            self.operation,
            self.sender_hw_addr,
            self.sender_proto_addr,
            self.target_hw_addr,
            self.target_proto_addr,
            self.length
        )
    }
}

/// IPv6 Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableIpv6Packet {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: String,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub length: usize,
}

impl<'a> From<&Ipv6Packet<'a>> for SerializableIpv6Packet {
    fn from(packet: &Ipv6Packet<'a>) -> Self {
        SerializableIpv6Packet {
            version: packet.get_version(),
            traffic_class: packet.get_traffic_class(),
            flow_label: packet.get_flow_label(),
            payload_length: packet.get_payload_length(),
            next_header: format!(
                "{} ({})",
                packet.get_next_header(),
                packet.get_next_header().0
            ),
            hop_limit: packet.get_hop_limit(),
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.payload().len(),
        }
    }
}

impl fmt::Display for SerializableIpv6Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv6 Packet: \n\
            \tVersion: {}\n\
            \tTraffic Class: {}\n\
            \tFlow Label: {}\n\
            \tPayload Length: {}\n\
            \tNext Header: {}\n\
            \tHop Limit: {}\n\
            \tSource: {}\n\
            \tDestination: {}\n\
            \tLength: {}",
            self.version,
            self.traffic_class,
            self.flow_label,
            self.payload_length,
            self.next_header,
            self.hop_limit,
            self.source,
            self.destination,
            self.length
        )
    }
}

/// IPv4 Packet Representation
#[derive(Serialize, Debug, Clone)]
pub struct SerializableIpv4Packet {
    pub version: u8,
    pub header_length: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub next_level_protocol: String,
    pub checksum: u16,
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub length: usize,
}

impl<'a> From<&Ipv4Packet<'a>> for SerializableIpv4Packet {
    fn from(packet: &Ipv4Packet<'a>) -> Self {
        SerializableIpv4Packet {
            version: packet.get_version(),
            header_length: packet.get_header_length(),
            dscp: packet.get_dscp(),
            ecn: packet.get_ecn(),
            total_length: packet.get_total_length(),
            identification: packet.get_identification(),
            flags: packet.get_flags(),
            fragment_offset: packet.get_fragment_offset(),
            ttl: packet.get_ttl(),
            next_level_protocol: format!(
                "{} ({})",
                packet.get_next_level_protocol(),
                packet.get_next_level_protocol().0
            ),
            checksum: packet.get_checksum(),
            source: packet.get_source(),
            destination: packet.get_destination(),
            length: packet.payload().len(),
        }
    }
}

impl fmt::Display for SerializableIpv4Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 Packet: \n\
            \tVersion: {}\n\
            \tHeader Length: {}\n\
            \tDSCP: {}\n\
            \tECN: {}\n\
            \tTotal Length: {}\n\
            \tIdentification: {}\n\
            \tFlags: {}\n\
            \tFragment Offset: {}\n\
            \tTTL: {}\n\
            \tNext Level Protocol: {}\n\
            \tChecksum: {}\n\
            \tSource: {}\n\
            \tDestination: {}\n\
            \tLength: {}",
            self.version,
            self.header_length,
            self.dscp,
            self.ecn,
            self.total_length,
            self.identification,
            self.flags,
            self.fragment_offset,
            self.ttl,
            self.next_level_protocol,
            self.checksum,
            self.source,
            self.destination,
            self.length
        )
    }
}