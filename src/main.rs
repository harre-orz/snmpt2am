extern crate snmp_parser;
extern crate chrono;
extern crate pnet;
extern crate libc;
extern crate serde_yaml;

use std::net::{IpAddr, Ipv4Addr};
use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;
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
use chrono::{Utc, DateTime};
use ureq::json;

const SNMPTRAP_PORT: u16 = 162;

fn getnameinfo(ip: &IpAddr) -> String {
    use std::ptr;
    use std::mem;
    use std::ffi::CStr;

    let mut hbuf : [libc::c_char; 1025] = [0; 1025];
    let ec = match ip {
        IpAddr::V4(addr) => {
            let sin = libc::sockaddr_in {
                //sin_len: 0,
                sin_family: libc::AF_INET as u16,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: unsafe { mem::transmute(addr.octets()) },
                },
                sin_zero: [0; 8],
            };
            unsafe {
                libc::getnameinfo(
                    &sin as *const libc::sockaddr_in as *const libc::sockaddr,
                    mem::size_of_val(&sin) as libc::socklen_t,
                    hbuf.as_mut_ptr(),
                    hbuf.len() as libc::socklen_t,
                    ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD)
            }
        }
        IpAddr::V6(addr) => {
            let sin6 = libc::sockaddr_in6 {
                //sin6_len: 0,
                sin6_family: libc::AF_INET6 as u16,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: addr.octets(),
                },
                sin6_scope_id: 0,
            };
            unsafe {
                libc::getnameinfo(
                    &sin6 as *const libc::sockaddr_in6 as *const libc::sockaddr,
                    mem::size_of_val(&sin6) as libc::socklen_t,
                    hbuf.as_mut_ptr(),
                    hbuf.len() as libc::socklen_t,
                    ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD)
            }
        }
    };
    if ec == 0 {
        unsafe { CStr::from_ptr(hbuf.as_ptr()).to_str().unwrap().to_string() }
    } else {
        format!("{}", ip)
    }
}

fn timeticks2str(mut t: u32) -> String {
    let ms = t % 100;
    t /= 100;
    let s = t % 60;
    t /= 60;
    let m = t % 60;
    t /= 60;
    let h = t % 24;
    t /= 24;
    if t > 0 {
        format!("{} day, {}:{:02}:{:02}.{:02}", t, h, m ,s, ms)
    } else {
        format!("{}:{:02}:{:02}.{:02}", h, m ,s, ms)
    }
}

fn snmptranslate(oid: &str) -> String {
    if let Ok(output) = std::process::Command::new("/usr/sbin/snmptranslate").arg(oid).output() {
        std::str::from_utf8(&output.stdout).unwrap_or(oid).trim_end().to_string()
    } else {
        oid.to_string()
    }
}

fn replace_promlabel(s: String) -> String {
    s.replace(".", "_").replace("-", "_").replace(":", "_")
}

#[derive(Debug)]
enum SnmpVar {
    Integer(i64),
    UInteger(u64),
    TimeTicks(u32),
    String(String),
    Oid(String),
    IpAddress(Ipv4Addr),
    Unknown,
}

impl SnmpVar {
    fn new(obj: &ObjectSyntax) -> Self {
        match obj {
            ObjectSyntax::Number(i) => Self::Integer(i.as_u32().unwrap_or(0) as i32 as i64),
            ObjectSyntax::String(b) => Self::String(std::str::from_utf8(b).unwrap_or("").to_string()),
            ObjectSyntax::BitString(_, b) => Self::String(b.data.iter().map(|i| format!("{:02x}", i)).collect::<Vec<_>>().join(":")),
            ObjectSyntax::Object(o) => Self::Oid(o.to_id_string()),
            ObjectSyntax::IpAddress(i) => Self::IpAddress(match i { NetworkAddress::IPv4(i) => *i }),
            ObjectSyntax::Counter32(n) => Self::UInteger(*n as u64),
            ObjectSyntax::Gauge32(n) => Self::UInteger(*n as u64),
            ObjectSyntax::TimeTicks(n) => Self::TimeTicks(*n),
            ObjectSyntax::Counter64(n) => Self::UInteger(*n),
            ObjectSyntax::UInteger32(n) => Self::UInteger(*n as u64),

            // not support
            ObjectSyntax::Empty => Self::Unknown,
            ObjectSyntax::UnknownSimple(_) => Self::Unknown,
            ObjectSyntax::Opaque(_) => Self::Unknown,
            ObjectSyntax::NsapAddress(_) => Self::Unknown,
            ObjectSyntax::UnknownApplication(_, _) => Self::Unknown,
        }
    }
}

#[derive(Debug)]
struct Snmp {
    captured_time: DateTime<Utc>,
    received_from: IpAddr,
    trap_oid: String,
    sys_uptime: u32,
    var_binds: Vec<(String, SnmpVar)>,
    retries: i32,
}

type SnmpQueue = Arc<(Mutex<VecDeque<Snmp>>, Condvar)>;

fn thread(que: SnmpQueue, cfg :serde_yaml::Value) {
    std::thread::spawn(move|| {
        let (mutex, cvar) = &*que;
        loop {
            let mut snmp = {
                let mut que = mutex.lock().unwrap();
                loop {
                    if let Some(snmp) = que.pop_front() {
                        break snmp
                    }
                    que = cvar.wait(que).unwrap();
                }
            };

            let mut labels = json!({
                "alertname": "",
                "instance": getnameinfo(&snmp.received_from),
            });
            for (key, val) in &snmp.var_binds {
                let oid = replace_promlabel(snmptranslate(key));
                match val {
                    SnmpVar::Integer(i) => labels[oid] = json!(format!("{}",i)),
                    SnmpVar::UInteger(i) => labels[oid] = json!(format!("{}",i)),
                    SnmpVar::TimeTicks(i) => labels[oid] = json!(timeticks2str(*i)),
                    SnmpVar::String(s) => labels[oid] = json!(s),
                    SnmpVar::Oid(s) => labels[oid] = json!(snmptranslate(s)),
                    SnmpVar::IpAddress(i) => labels[oid] = json!(format!("{}", i)),
                    SnmpVar::Unknown => labels[oid] = json!("unknown"),
                }
            }

            // SNMPv2-MIB::snmpTrapOID.0
            let oid = replace_promlabel(snmptranslate(".1.3.6.1.6.3.1.1.4.1.0"));
            labels[oid] = json!(snmptranslate(&snmp.trap_oid));

            // SNMPv2-MIB::sysUpTime.0
            let oid = replace_promlabel(snmptranslate(".1.3.6.1.2.1.1.3.0"));
            labels[oid] = json!(timeticks2str(snmp.sys_uptime));

            // test
            let mut annotations = json!({});
            for rule in cfg["groups"]["rules"].as_sequence().unwrap() {
                let expr = rule["expr"].as_str().unwrap_or("");
                if  expr == snmptranslate(&snmp.trap_oid) || expr == "" {
                    labels["alertname"] = json!(rule["alert"].as_str().unwrap_or("").to_string());
                    if let Some(x) = rule["labels"].as_mapping() {
                        for (k, v) in x {
                            let k = k.as_str().unwrap_or("").to_string();
                            let v = v.as_str().unwrap_or("").to_string();
                            labels[k] = json!(v);
                        }
                    }
                    if let Some(x) = rule["annotations"].as_mapping() {
                        for (k, v) in x {
                            let k = k.as_str().unwrap_or("").to_string();
                            let v = v.as_str().unwrap_or("").to_string();
                            annotations[k] = json!(v);
                        }
                    }
                }
            }

            println!("labels = {:?}, annotations = {:?}", labels, annotations);

            for am in cfg["alerting"]["alertmanager"].as_sequence().unwrap_or(&vec![]) {
                let url = format!("{}/api/v1/alerts", am.as_str().unwrap_or(""));
                let resp = ureq::post(&url)
                    .send_json(json!([{
                        "labels": labels,
                        "annotations": annotations,
                        "startsAt": format!("{:?}", snmp.captured_time),
                    }]));
                if resp.ok() {
                    println!("success: {}", resp.into_string().unwrap());
                    return
                } else {
                    println!("error {}: {}", resp.status(), resp.into_string().unwrap());
                }
            }

            // retry
            if snmp.retries < 10 {
                snmp.retries += 1;
                std::thread::sleep(Duration::from_secs(10));
                let (mutex, _) = &*que;
                let mut que = mutex.lock().unwrap();
                que.push_back(snmp);
            }
        }
    });
}

fn do_snmp(que: &SnmpQueue, msg: SnmpMessage, received_from: IpAddr) {
    let snmp = match msg.pdu {
        SnmpPdu::Generic(pdu) => {
            let mut snmp = Snmp {
                captured_time: Utc::now(),
                received_from: received_from,
                trap_oid: String::new(),
                sys_uptime: 0,
                var_binds: Vec::new(),
                retries: 0,
            };
            for var in pdu.vars_iter() {
                let key = var.oid.to_id_string();
                match key.as_str() {
                    /* SNMPv2-MIB::sysUpTime.0 */ ".1.3.6.1.2.1.1.3.0" =>
                        if let ObjectSyntax::TimeTicks(t) = var.val {
                            snmp.sys_uptime = t;
                        },
                    /* SNMPv2-MIB::snmpTrapOID.0 */ ".1.3.6.1.6.3.1.1.4.1.0" =>
                        if let ObjectSyntax::Object(ref oid) = var.val {
                            snmp.trap_oid = oid.to_id_string();
                        },
                    _ => snmp.var_binds.push((var.oid.to_id_string(), SnmpVar::new(&var.val)))
                }
            }
            snmp
        },
        SnmpPdu::Bulk(_) => return,
        SnmpPdu::TrapV1(pdu) => {
            let mut snmp = Snmp {
                captured_time: Utc::now(),
                received_from: received_from,
                trap_oid: pdu.enterprise.to_id_string(),
                sys_uptime: pdu.timestamp,
                var_binds: Vec::new(),
                retries: 0,
            };
            pdu.vars_iter().for_each(|var| {
                snmp.var_binds.push((var.oid.to_id_string(), SnmpVar::new(&var.val)))
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

fn parse_raw_packet(que: &SnmpQueue, packet: &[u8]) {
    if let Some(eth_packet) = EthernetPacket::new(packet) {
        match eth_packet.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ip4_packet) = Ipv4Packet::new(eth_packet.payload()) {
                    if ip4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        if let Some(udp_packet) = UdpPacket::new(ip4_packet.payload()) {
                            let port = udp_packet.get_destination();
                            if  port == SNMPTRAP_PORT {
                                if let Ok((_, snmp)) = parse_snmp_generic_message(udp_packet.payload()) {
                                    match snmp {
                                        SnmpGenericMessage::V1(msg) => {
                                            do_snmp(que, msg, IpAddr::V4(ip4_packet.get_source()))
                                        },
                                        SnmpGenericMessage::V2(msg) => {
                                            do_snmp(que, msg, IpAddr::V4(ip4_packet.get_source()))
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
                            if port == SNMPTRAP_PORT {
                                if let Ok((_, snmp)) = parse_snmp_generic_message(packet) {
                                    match snmp {
                                        SnmpGenericMessage::V1(msg) => {
                                            do_snmp(que, msg, IpAddr::V6(ip6_packet.get_source()))
                                        },
                                        SnmpGenericMessage::V2(msg) => {
                                            do_snmp(que, msg, IpAddr::V6(ip6_packet.get_source()))
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

fn main() {
    // TODO: load config
    let f = std::fs::File::open("snmptrap.yml").unwrap();
    let config = serde_yaml::from_reader(f).unwrap();

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
    thread(que.clone(), config);

    loop {
        match rx.next() {
            Ok(packet) => {
                parse_raw_packet(&que, packet);
            },
            Err(e) => {
                panic!("receive error: {}", e);
            },
        }
    }
}
