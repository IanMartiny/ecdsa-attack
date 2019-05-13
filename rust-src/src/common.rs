extern crate time;
extern crate crypto;

use pnet::packet::tcp::TcpPacket;

use self::crypto::digest::Digest;

use tls_structs::CipherSuite;

use postgres::{Connection, TlsMode, Error};

use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::time::Instant;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ParseError {
    ShortBuffer,
    NotAHandshake,
    UnknownRecordTLSVersion,
    ShortOuterRecord,
    NotAClientHello,
    InnerOuterRecordLenContradict,
    UnknownChTLSVersion,
    SessionIDLenExceedBuf,
    CiphersuiteLenMisparse,
    CompressionLenExceedBuf,
    ExtensionsLenExceedBuf,
    ShortExtensionHeader,
    ExtensionLenExceedBuf,

    NotAServerHello,

    KeyShareExtShort,
    KeyShareExtLong,
    KeyShareExtLenMisparse,
    PskKeyExchangeModesExtShort,
    PskKeyExchangeModesExtLenMisparse,
    SupportedVersionsExtShort,
    SupportedVersionsExtLenMisparse,

    NotACertificate,
    NotFullCertificate,

    NoServerKeyExchange,
    UnImplementedCurveType,

    NotACiphersuite,
}

#[derive(Copy, Clone, Debug)]
pub struct Flow {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub overflow: usize,
    pub cipher_suite: CipherSuite,
}

impl PartialEq for Flow {
    fn eq(&self, other: &Flow) -> bool {
        self.src_ip == other.src_ip && self.dst_ip == other.dst_ip && self.src_port == other.src_port && self.dst_port == other.dst_port
    }
}

impl Eq for Flow {}

impl Hash for Flow {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.src_ip.hash(state);
        self.dst_ip.hash(state);
        self.src_port.hash(state);
        self.dst_port.hash(state);
    }
}

pub struct TimedFlow
{
    pub event_time: Instant,
    pub flow: Flow,
}

impl Flow {
    pub fn new(src_ip: &IpAddr, dst_ip: &IpAddr, tcp_pkt: &TcpPacket, of: usize, cs: CipherSuite) -> Flow {
        Flow {
            src_ip: *src_ip,
            dst_ip: *dst_ip,
            src_port: tcp_pkt.get_source(),
            dst_port: tcp_pkt.get_destination(),
            overflow: of,
            cipher_suite: cs,
        }
    }
    pub fn reversed_clone(&self) -> Flow {
        Flow{src_ip: self.dst_ip,
            src_port: self.dst_port,
            dst_ip: self.src_ip,
            dst_port: self.src_port,
            ..*self
        }
    }
}


#[derive(PartialEq, Eq, Hash)]
pub struct ConnectionIPv6 {
    pub id: i64,
    pub sid: i64,
    pub time_sec: i64,
    pub sni: Vec<u8>,
    pub serv_ip: Vec<u8>,
    pub anon_cli_ip: u32,
}

#[derive(PartialEq, Eq, Hash)]
pub struct ConnectionIPv4 {
    pub id: i64,
    pub sid: i64,
    pub time_sec: i64,
    pub anon_cli_ip: i16,
    pub serv_ip: u32,
    pub sni: Vec<u8>,
}


// TODO: better done as a trait on Digest
pub fn hash_u32<D: Digest>(h: &mut D, n: u32) {
    h.input(&[((n >> 24) & 0xff) as u8,
        ((n >> 16) & 0xff) as u8,
        ((n >> 8) & 0xff) as u8,
        (n & 0xff) as u8]);
}

pub fn u8_to_u16_be(first_byte: u8, second_byte: u8) -> u16 {
    (first_byte as u16) << 8 | (second_byte as u16)
}

pub fn u8_to_u32_be(first_byte: u8, second_byte: u8, third_byte: u8, forth_byte: u8) -> u32 {
    (first_byte as u32) << 24 | (second_byte as u32) << 16 | (third_byte as u32) << 8 |
        (forth_byte as u32)
}

pub fn u8array_to_u32_be(oct: [u8; 4]) -> u32 {
    (oct[0] as u32) << 24 | (oct[1] as u32) << 16 | (oct[2] as u32) << 8 | (oct[3] as u32)
}


// Doesn't check that a.len() % 2 == 1.
pub fn vec_u8_to_vec_u16_be(a: &Vec<u8>) -> Vec<u16> {
    let mut result = Vec::with_capacity(a.len() / 2);
    for i in 0..result.capacity() {
        result.push(u8_to_u16_be(a[2 * i], a[2 * i + 1]));
    }
    result
}


pub fn check_dsn(dsn: &str) -> Result<(), Error> {
    let db_conn = Connection::connect(dsn, TlsMode::None)?;
    db_conn.execute("SELECT 1", &[])?;
    Ok(())
}