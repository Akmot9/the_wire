// Copyright (c) 2014, 2015 Robert Clipsham <robert@octarineparrot.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// This example shows a basic packet logger using libpnet
extern crate pnet;
extern crate sniffer_parser;

use sniffer_parser::serializable_packet::util::{
    contains_arp, contains_dns, contains_ethernet, contains_http, contains_icmp, contains_icmp6,
    contains_ipv4, contains_ipv6, contains_malformed, contains_tcp, contains_tls, contains_udp,
    contains_unknokn, get_dest_ip, get_dest_mac, get_dest_port, get_source_ip, get_source_mac,
    get_source_port,
};
use sniffer_parser::{parse_ethernet_frame, HeaderLength};

use pnet::datalink::{self, NetworkInterface};


use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};


use pnet::util::MacAddr;

use std::env;
use std::io::{self, Write};

use std::process;

fn main() {
    use pnet::datalink::Channel::Ethernet;

    let iface_name = match env::args().nth(1) {
        Some(n) => n,
        None => {
            writeln!(io::stderr(), "USAGE: packetdump <NETWORK INTERFACE>").unwrap();
            process::exit(1);
        }
    };
    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                let mut info =0;
                let new_packet = parse_ethernet_frame(&ethernet_packet, info);
                info += 1;
                println!("{:?} id : {info}", new_packet);
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}
