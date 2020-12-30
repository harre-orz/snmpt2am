extern crate pnet;
extern crate snmp_parser;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use snmp_parser::{parse_snmp_generic_message, SnmpGenericMessage};
use snmp_parser::snmp::{NetworkAddress, SnmpMessage, SnmpPdu, ObjectSyntax};
use std::str;

#[derive(Debug)]
struct SnmpOid(String);

#[derive(Debug)]
enum SnmpVar {
    Number(u64),
    String(String),
    Object(SnmpOid),
    BitString(String),
    Empty,
    UnknownSimple(String),
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(String),
    NsapAddress(String),
    Counter64(u64),
    UInteger32(u32),
    UnknownApplication(String),
}

impl SnmpVar {
    fn new(obj: &ObjectSyntax) -> Self {
        match obj {
            ObjectSyntax::Number(i) => Self::Number(i.as_u64().unwrap_or(0)),
            ObjectSyntax::String(b) => Self::String(str::from_utf8(b).unwrap_or("").to_string()),
            ObjectSyntax::Object(o) => Self::Object(SnmpOid(o.to_id_string())),
            ObjectSyntax::BitString(_, b) => Self::BitString({
                let mut s = String::new();
                b.data.iter().for_each(|hex| {
                    s += (format!("{:02x}", hex)).as_str();
                });
                s
            }),
            ObjectSyntax::Empty => Self::Empty,
            ObjectSyntax::UnknownSimple(_) => Self::UnknownSimple("UnknownSimple".to_string()),
            ObjectSyntax::IpAddress(i) => Self::IpAddress(match i { NetworkAddress::IPv4(i) => *i }),
            ObjectSyntax::Counter32(n) => Self::Counter32(*n),
            ObjectSyntax::Gauge32(n) => Self::Gauge32(*n),
            ObjectSyntax::TimeTicks(n) => Self::TimeTicks(*n),
            ObjectSyntax::Opaque(_) => Self::Opaque("Opaque".to_string()),
            ObjectSyntax::NsapAddress(_) => Self::NsapAddress("NscapAAddress".to_string()),
            ObjectSyntax::Counter64(n) => Self::Counter64(*n),
            ObjectSyntax::UInteger32(n) => Self::UInteger32(*n),
            ObjectSyntax::UnknownApplication(_, _) => Self::UnknownApplication("UnknownApplication".to_string()),
        }
    }
}

#[derive(Debug)]
struct Snmp {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    version: u32,
    uptime: u32,
    trap_oid: SnmpOid,
    varbinds: Vec<(SnmpOid, SnmpVar)>,
}

type SnmpQueue = Arc<(Mutex<VecDeque<Snmp>>, Condvar)>;

fn do_snmp(que: &SnmpQueue, msg: SnmpMessage, remote_addr: SocketAddr, local_addr: SocketAddr) {
    let snmp = match msg.pdu {
        SnmpPdu::Generic(pdu) => {
            let mut snmp = Snmp {
                remote_addr: remote_addr,
                local_addr: local_addr,
                version: 0,
                uptime: 0,
                trap_oid: SnmpOid(String::new()),
                varbinds: Vec::new(),
            };
            for var in pdu.vars_iter() {
                let key = var.oid.to_id_string();
                match key.as_str() {
                    /* SNMPv2-MIB::sysUpTime.0 */ ".1.3.6.1.2.1.1.3.0" =>
                        if let ObjectSyntax::TimeTicks(t) = var.val {
                            snmp.uptime = t;
                        },
                    /* SNMPv2-MIB::snmpTrapOID.0 */ ".1.3.6.1.6.3.1.1.4.1.0" =>
                        if let ObjectSyntax::Object(ref oid) = var.val {
                            snmp.trap_oid = SnmpOid(oid.to_id_string());
                        },
                    _ => snmp.varbinds.push((SnmpOid(var.oid.to_id_string()), SnmpVar::new(&var.val)))
                }
            }
            snmp
        },
        SnmpPdu::Bulk(_) => return,
        SnmpPdu::TrapV1(pdu) => {
            let mut snmp = Snmp {
                remote_addr: remote_addr,
                local_addr: local_addr,
                version: 1,
                uptime: pdu.timestamp,
                trap_oid: SnmpOid(pdu.enterprise.to_id_string()),
                varbinds: Vec::new(),
            };
            pdu.vars_iter().for_each(|var| {
                snmp.varbinds.push((SnmpOid(var.oid.to_id_string()), SnmpVar::new(&var.val)))
            });
            snmp
        },
    };

    //println!("{:?}", snmp);
    let (mutex, cvar) = &**que;
    let mut que = mutex.lock().unwrap();
    que.push_back(snmp);
    cvar.notify_one();
}

fn parse_packet(que: &SnmpQueue, packet: &[u8]) {
    if let Some(eth_packet) = EthernetPacket::new(packet) {
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ip4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                    if ip4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        if let Some(udp_packet) = UdpPacket::new(ip4_packet.payload()) {
                            let port = udp_packet.get_destination();
                            if  port == 162 {
                                if let Ok((_, snmp)) = parse_snmp_generic_message(udp_packet.payload()) {
                                    match snmp {
                                        SnmpGenericMessage::V1(msg) => {
                                            let src = SocketAddrV4::new(ip4_packet.get_source(), udp_packet.get_source());
                                            let dst = SocketAddrV4::new(ip4_packet.get_destination(), port);
                                            do_snmp(que, msg, SocketAddr::V4(src), SocketAddr::V4(dst));
                                        },
                                        SnmpGenericMessage::V2(msg) => {
                                            let src = SocketAddrV4::new(ip4_packet.get_source(), udp_packet.get_source());
                                            let dst = SocketAddrV4::new(ip4_packet.get_destination(), port);
                                            do_snmp(que, msg, SocketAddr::V4(src), SocketAddr::V4(dst));
                                        },
                                        SnmpGenericMessage::V3(_) => {
                                            // not support
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            },
            EtherTypes::Ipv6 => {
                if let Some(ip6_packet) = Ipv6Packet::new(eth_packet.payload()) {
                    if ip6_packet.get_next_header() == IpNextHeaderProtocols::Udp {
                        if let Some(udp_packet) = UdpPacket::new(ip6_packet.payload()) {
                            let port = udp_packet.get_destination();
                            if port == 162 {
                                if let Ok((_, snmp)) = parse_snmp_generic_message(packet) {
                                    match snmp {
                                        SnmpGenericMessage::V1(msg) => {
                                            let src = SocketAddrV6::new(ip6_packet.get_source(), udp_packet.get_source(), 0, 0);
                                            let dst = SocketAddrV6::new(ip6_packet.get_destination(), port, 0, 0);
                                            do_snmp(que, msg, SocketAddr::V6(src), SocketAddr::V6(dst));
                                        },
                                        SnmpGenericMessage::V2(msg) => {
                                            let src = SocketAddrV6::new(ip6_packet.get_source(), udp_packet.get_source(), 0, 0);
                                            let dst = SocketAddrV6::new(ip6_packet.get_destination(), port, 0, 0);
                                            do_snmp(que, msg, SocketAddr::V6(src), SocketAddr::V6(dst));
                                        },
                                        SnmpGenericMessage::V3(_) => {
                                            // not support
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                // ignore
            },
        }
    }
}

fn thread(que: SnmpQueue) {
    std::thread::spawn(move|| {
        let (mutex, cvar) = &*que;
        loop {
            let snmp = {
                let mut que = mutex.lock().unwrap();
                loop {
                    if let Some(snmp) = que.pop_front() {
                        break snmp
                    }
                    que = cvar.wait(que).unwrap();
                }
            };
            println!("{:?}", snmp);
        }
    });
}

fn main() {
    let iface = datalink::interfaces()
        .into_iter()
        .filter(|iface| iface.name == "lo")
        .next()
        .unwrap();
    let mut rx = match datalink::channel(&iface, Default::default()) {
        Ok(Ethernet(_tx, rx)) => rx,
        _ => panic!("open error"),
    };

    let que: SnmpQueue = Arc::default();
    thread(que.clone());

    loop {
        match rx.next() {
            Ok(packet) => {
                parse_packet(&que, packet);
            },
            Err(e) => {
                panic!("receive error: {}", e);
            },
        }
    }
}
