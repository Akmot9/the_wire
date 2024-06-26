//! Application layer Packet parsing

use std::{cell::RefCell, collections::HashMap, net::IpAddr};

use crate::serializable_packet::ParsedPacket;

use self::{
    dns::handle_dns_packet, 
    http::handle_http_packet, 
    tls::handle_tls_packet,
    modbus::handle_modbus_packet
};

pub mod dns;
pub mod http;
pub mod tls;
pub mod modbus;

thread_local!(
    pub(crate) static ACTIVE_HTTP_PARSERS: RefCell<
        HashMap<((IpAddr, u16), (IpAddr, u16)), Vec<u8>>,
    > = RefCell::new(HashMap::new());
    pub(crate) static ACTIVE_TLS_PARSERS: RefCell<
        HashMap<((IpAddr, u16), (IpAddr, u16)), Vec<u8>>,
    > = RefCell::new(HashMap::new());
);

/// IANA Well Known TCP/UDP Ports
#[allow(non_snake_case)]
mod WellKnownPorts {
    pub const HTTP_PORT: u16 = 80;
    pub const TLS_PORT: u16 = 443;
    pub const DNS_PORT: u16 = 53;
    pub const MODBUS_PORT: u16 = 502;
}


// HTTP ----------------------------------------------------------------------------------------------------------------

/// HTTP Types of Content Encoding
#[allow(non_snake_case)]
mod ContentEncoding {
    pub const GZIP: &str = "gzip";
    pub const ZLIB: &str = "zlib";
    pub const DEFLATE: &str = "deflate";
}

/// HTTP String representation for Header names
#[allow(non_snake_case)]
mod HeaderNamesValues {
    pub const CONTENT_ENCODING: &str = "Content-Encoding";
    pub const TRANSFER_ENCODING: &str = "Transfer-Encoding";
    pub const CONTENT_TYPE: &str = "Content-Type";
    pub const CONTENT_LENGTH: &str = "Content-Length";
    pub const CHUNKED: &str = "chunked";
}

/// HTTP Types of packets
pub enum HttpPacketType {
    Request,
    Response,
}

/// Build an application-layer packet from a transport-layer one, save it in a Parsed Packet
pub fn handle_application_protocol(
    source_ip: IpAddr,
    source_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
    is_fin: bool,
    packet: &[u8],
    parsed_packet: &mut ParsedPacket,
) {
    match (source_port, dest_port) {
        (WellKnownPorts::HTTP_PORT, _) | (_, WellKnownPorts::HTTP_PORT) => {
            let http_type = match dest_port {
                WellKnownPorts::HTTP_PORT => HttpPacketType::Request,
                _ => HttpPacketType::Response,
            };

            handle_http_packet(
                source_ip,
                source_port,
                dest_ip,
                dest_port,
                http_type,
                is_fin,
                packet,
                parsed_packet,
            )
        }
        (WellKnownPorts::TLS_PORT, _) | (_, WellKnownPorts::TLS_PORT) => handle_tls_packet(
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            packet,
            parsed_packet,
        ),
        (WellKnownPorts::DNS_PORT, _) | (_, WellKnownPorts::DNS_PORT) 
        => handle_dns_packet(
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            packet,
            parsed_packet,
        ),
        (WellKnownPorts::MODBUS_PORT, _) | (_, WellKnownPorts::MODBUS_PORT) => 
        handle_modbus_packet(
            source_ip,
            source_port,
            dest_ip,
            dest_port,
            packet,
            parsed_packet,
        ),
        _ => (),
    }
}
