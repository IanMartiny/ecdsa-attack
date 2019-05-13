mod cache;
mod common;
mod flow_tracker;
mod stats_tracker;
mod tls_parser;
mod tls_structs;

#[macro_use]
extern crate enum_primitive;
extern crate pcap;
extern crate pnet;
extern crate postgres;
extern crate time;
extern crate clap;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use std::time::{Instant, Duration};
use std::error::Error;
use pcap::Capture;
use clap::{Arg, App};
use flow_tracker::FlowTracker;

fn main() {
    let cl_args = App::new("TLS Fingerprint Debugger")
        .about("Reads from either PCAP or interface for debugging TLS fingerprint \
            tool. Defaults \nto pcap if nothing is specified.")
        .version("1.0")
        .arg(Arg::with_name("pcap")
            .short("p")
            .long("pcap")
            .value_name("FILE")
            .help("Custom PCAP file to open")
            .takes_value(true))
        .arg(Arg::with_name("interface")
            .short("i")
            .long("interface")
            .value_name("INTERFACE")
            .help("Interface from which to read live packets")
            .takes_value(true))
        .get_matches();


    let pcap_filename = cl_args.value_of("pcap")
        .unwrap_or("data/tls-capture-ecdhe-rsa-pkcs1-sha256.pcap.pcapng");

    match cl_args.value_of("interface") {
        Some(interface_name) => {
            let interface_ref_closure = |iface: &NetworkInterface| iface.name == interface_name;

            // Find the network interface with the provided name
            let interfaces = datalink::interfaces();

            match interfaces.into_iter().find(interface_ref_closure) {
                Some (interface) => {
                    run_from_interface( &interface);
                },
                None => {
                    println!("Unknown interface '{}' reading from pcap.\n{}", 
                        interface_name, pcap_filename);
                    run_from_pcap(pcap_filename);
                },
            };
        },
        None => {
            println!("No interface specified reading from pcap.\n{}", pcap_filename);
            run_from_pcap(pcap_filename);
        },
    };
}


fn run_from_pcap(pcap_filename: &str){
    match Capture::from_file(pcap_filename) {
        Ok(mut cap)=> {
            let mut ft = FlowTracker::new();
            while let Ok(cap_pkt) = cap.next() {
                let pnet_pkt = pnet::packet::ethernet::EthernetPacket::new(cap_pkt.data);
                match pnet_pkt {
                    Some(eth_pkt) => {
                        match eth_pkt.get_ethertype() {
                            // EtherTypes::Vlan?
                            EtherTypes::Ipv4 => ft.handle_ipv4_packet(&eth_pkt),
                            EtherTypes::Ipv6 => ft.handle_ipv6_packet(&eth_pkt),
                            _ => println!("[Warning] Could not parse packet"),
                        }
                    }
                    None => {
                        println!("[Warning] Could not parse packet");
                    }
                }
            }
        },
        Err(e) => {
            println!("\nPCAP Parse error with file '{}'.", pcap_filename);
            println!("Error => {}", e.description());
        },
    }
}


fn run_from_interface(interface: &NetworkInterface){
    let mut ft = FlowTracker::new();

    // Create a new channel, dealing with layer 2 packets
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            println!("Unhandled channel type");
            return
        }
        Err(e) => {
            println!("An error occurred when creating the datalink channel: {}", e);
            return
        }
    };

    let cleanup_frequency = Duration::from_secs(1);
    let mut last_cleanup = Instant::now();

    loop {
        match rx.next() {
            Ok(packet) => {
                match EthernetPacket::new(packet) {
                    Some(eth_pkt) => {
                        match eth_pkt.get_ethertype() {
                            // EtherTypes::Vlan?
                            EtherTypes::Ipv4 => ft.handle_ipv4_packet(&eth_pkt),
                            EtherTypes::Ipv6 => ft.handle_ipv6_packet(&eth_pkt),
                            _ => continue,
                        }
                    }
                    None => {
                        println!("[Warning] Could not parse packet: {:?}", packet);
                        continue;
                    }
                }
                if last_cleanup.elapsed() >= cleanup_frequency {
                    ft.cleanup();
                    last_cleanup = Instant::now();
                    ft.debug_print();
                }
            }
            Err(e) => {
                println!("[ERROR] An error occurred while reading: {}", e);
            }
        }
    }
}