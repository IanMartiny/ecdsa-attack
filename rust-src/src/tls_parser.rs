extern crate num;
extern crate openssl;

use self::num::FromPrimitive;
use self::openssl::x509::X509;

use common::{Flow, ParseError, u8_to_u16_be, u8_to_u32_be};
use tls_structs::{CipherSuite, HasSignature, ServerCertificateParseResult, ServerHelloFingerprint, ServerHelloParseResult, 
    ServerKeyExchange, ServerKeyExchangeParseResult, ServerParseResult, ServerReturn, TlsHandshakeType, TlsRecordType, 
    TlsVersion};



// Coverts array of [u8] into Vec<u8>, and performs ungrease.
// Ungrease stores all greasy extensions/ciphers/etc under single id to produce single fingerprint
// https://tools.ietf.org/html/draft-davidben-tls-grease-01
pub fn ungrease_u8(arr: &[u8]) -> Vec<u8> {
    let mut res: Vec<u8> = arr.iter().cloned().collect();
    for i in 0..(arr.len() / 2) {
        if res[2 * i] == res[2 * i + 1] && (res[2 * i] & 0x0f == 0x0a) {
            res[2 * i] = 0x0a;
            res[2 * i + 1] = 0x0a;
        }
    }
    res
}

// parses groups and lengths of key_share (but not keys themselves) and ungreases the groups
// passed vector must already be stripped from overall size
pub fn parse_key_share(arr: &[u8]) -> Result<Vec<u8>, ParseError> {
    if arr.len() > std::u16::MAX as usize {
        return Err(ParseError::KeyShareExtLong);
    }
    let mut i: usize = 0;
    let mut res = Vec::new();
    while i < arr.len() {
        if i  > arr.len() - 4 {
            return Err(ParseError::KeyShareExtShort);
        }
        let mut group_size = ungrease_u8(&arr[i .. i+2]);
        let size = u8_to_u16_be(arr[i+2], arr[i+3]) as usize;
        group_size.push(arr[i+2]);
        group_size.push(arr[i+3]);
        res.append(&mut group_size);

        i = match i.checked_add(4 + size) {
            Some(i) => i,
            None => return Err(ParseError::KeyShareExtShort),
        };
    }
    Ok(res)
}

pub fn find_server_hello(a: &[u8], fl: &mut Flow) -> ServerHelloParseResult {
    let of = fl.overflow;
    let record_type = a[of];
    if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
        return Err(ParseError::NotAHandshake);
    }

    let record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+1], a[of+2])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownRecordTLSVersion),
    };

    let record_length = u8_to_u16_be(a[of+3], a[of+4]);
    if usize::from_u16(record_length).unwrap() > a.len() - 5 {
        return Err(ParseError::ShortOuterRecord);
    }

    // TODO: make this more general, not just parsing hellos anymore
    if TlsHandshakeType::from_u8(a[of+5]) != Some(TlsHandshakeType::ServerHello) {
        return Err(ParseError::NotAServerHello);
    }

    let ch_length = u8_to_u32_be(0, a[of+6], a[of+7], a[of+8]);
    if ch_length != record_length as u32 - 4 {
        return Err(ParseError::InnerOuterRecordLenContradict);
    }

    let sh_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+9], a[of+10])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownChTLSVersion),
    };

    // 32 bytes of client random

    let mut offset: usize = of+11;
    let server_random = ungrease_u8(&a[offset..offset+32]);
    offset += 32;

    let session_id_len = a[offset] as usize;
    offset += session_id_len + 1;
    if offset + 2 > a.len() {
        return Err(ParseError::SessionIDLenExceedBuf);
    }

    if offset + 5 > a.len() {
        return Err(ParseError::ShortBuffer);
    }

    let cipher_suite = match CipherSuite::from_u16(u8_to_u16_be(a[offset], a[offset + 1])) {
        Some(cs) => cs,
        None => return Err(ParseError::NotACiphersuite),
    };

    fl.cipher_suite = cipher_suite;
    offset += 2;

    let compression_method = a[offset];
    offset += 1;


    let mut sh = ServerHelloFingerprint {
        record_tls_version: record_tls_version,
        sh_tls_version: sh_tls_version,
        server_random: server_random,
        cipher_suite: cipher_suite,
        compression_method: compression_method,
        extensions: Vec::new(),
        elliptic_curves: Vec::new(),
        ec_point_fmt: Vec::new(),
        alpn: Vec::new(),
    };

    let extensions_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
    offset += 2;
    if offset + extensions_len > a.len() {
        return Err(ParseError::ExtensionsLenExceedBuf);
    }

    let sh_end = offset + extensions_len;
    while offset < sh_end {
        if offset > sh_end - 4 {
            return Err(ParseError::ShortExtensionHeader);
        }

        let ext_len = u8_to_u16_be(a[offset + 2], a[offset + 3]) as usize;
        if offset + ext_len > sh_end {
            return Err(ParseError::ExtensionLenExceedBuf);
        }
        sh.process_extension(&a[offset..offset + 2], &a[offset + 4..offset + 4 + ext_len]);

        offset = match (offset + 4).checked_add(ext_len) {
            Some(i) => i,
            None => return Err(ParseError::ExtensionLenExceedBuf),
        };
    }

    fl.overflow = of+offset;

    Ok(sh)
}

pub fn find_certificate(a: &[u8], fl: &mut Flow) -> ServerCertificateParseResult {
    let of = fl.overflow;
    if a.len() < of {
        return Err(ParseError::ShortBuffer);
    }

    let record_type = a[of];
    if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
        return Err(ParseError::NotAHandshake);
    }

    let _record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+1], a[of+2])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownRecordTLSVersion),
    };

    let record_length = u8_to_u16_be(a[of+3], a[of+4]);
    if usize::from_u16(record_length).unwrap() > a[of..].len() - 5 {
        // have an overflow of certs between packets
        fl.overflow = record_length as usize - a[of+5..].len();
    }

    if TlsHandshakeType::from_u8(a[of+5]) != Some(TlsHandshakeType::Certificate) {
        return Err(ParseError::NotACertificate);
    }

    let ch_length = u8_to_u32_be(0, a[of+6], a[of+7], a[of+8]);
    if ch_length != record_length as u32 - 4 {
        return Err(ParseError::InnerOuterRecordLenContradict);
    }
    let cert_len = u8_to_u32_be(0, a[of+12], a[of+13], a[of+14]) as usize;

    if a[of+15..].len() < cert_len {
        return Err(ParseError::NotFullCertificate);
    }

    // we have a full certificate here

    match X509::from_der(&a[of+15..of+15+cert_len]) {
        Ok(cert) => Ok(cert),
        Err(_) => Err(ParseError::NotACertificate),
    }
}

pub fn find_server_key_exchange(a: &[u8], fl: &mut Flow) -> ServerKeyExchangeParseResult {
    let mut of = fl.overflow;
    if a.len() < of {
        return Err(ParseError::ShortBuffer);
    }

    let record_type = a[of];
    if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
        return Err(ParseError::NotAHandshake);
    }

    let _record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[of+1], a[of+2])) {
        Some(tls_version) => tls_version,
        None => return Err(ParseError::UnknownRecordTLSVersion),
    };

    let record_length = u8_to_u16_be(a[of+3], a[of+4]);

    if TlsHandshakeType::from_u8(a[of+5]) != Some(TlsHandshakeType::ServerKeyExchange) {
        return Err(ParseError::NoServerKeyExchange);
    }

    let ch_length = u8_to_u32_be(0, a[of+6], a[of+7], a[of+8]);
    if ch_length != record_length as u32 - 4 {
        return Err(ParseError::InnerOuterRecordLenContradict);
    }

    // what is collected here will depend on the type of algorithm selected, for now will only work for
    // ECDHE named curve
    
    //beginning of data
    of = of+9;

    // for ECDHE there is one byte for the type of curve to follow, for now only implement named_curve (0x03)

    let mut params: Vec<u8> = Vec::new();
    params.push(a[of]);
    match a[of] {
        0x03 => {params.extend(a[of+1..of+3].iter());}
        _ => {
            println!("unknown type of curve");
            return Err(ParseError::UnImplementedCurveType);
        }
    }

    // now append the public key, which will include the key length
    params.push(a[of+3]); // public key length
    if a[of+4..].len() < a[of+3] as usize {
        println!("Packet doesn't have full server key exchange");
        return Err(ParseError::ShortBuffer);
    }
    // this will have all of server key exchange so we have no more overflow on this flow
    fl.overflow = 0;
    params.extend(a[of+4..of+4+a[of+3] as usize].iter());// all of public key
    // (ec)dh(e)_rsa has a signature, we know whether it was selected from server hello
    of += 4 + a[of+3] as usize;

    let mut sig: Option<Vec<u8>>;
    match HasSignature::from_u16(fl.cipher_suite as u16) {
        Some(hs) => {
            let mut tmp_sig: Vec<u8> = Vec::new();
            tmp_sig.extend(a[of..of+2].iter());
            let sig_len = u8_to_u16_be(a[of+2], a[of+3]) as usize;
            tmp_sig.extend(a[of+2..of+2+sig_len+2].iter()); // extra two bytes is to include the length of signature
            sig = Some(tmp_sig);
        }
        None => {
            sig = None;
        }
    }

    let ske = ServerKeyExchange {
        server_params: params,
        signature: sig,
    };

    Ok(ske)

}

pub fn from_try(a: &[u8], fl: &mut Flow) -> ServerParseResult {
    // not as important for general check.

    let mut sr = ServerReturn {
        server_hello: None,
        cert: None,
        server_key_exchange: None,
    };

    // first check for a ServerHello:
    match find_server_hello(a, fl) {
        Ok(sh) => {
            sr.server_hello = enum_primitive::Option::Some(sh);
        }
        Err(_) => {} // didn't find server hello
    }
    
    // now check for other records!

    match find_certificate(a, fl) {
        Ok(cert) => {
            sr.cert = enum_primitive::Option::Some(cert);
        }
        Err(_) => {} // didn't find a certificate
    }

    match find_server_key_exchange(a, fl) {
        Ok(ske) => {
            sr.server_key_exchange = enum_primitive::Option::Some(ske);
        }
        Err(_) => {} // didn't find a server key exchange 
    }
    Ok(sr)
}


#[cfg(test)]
mod tests {
    use tls_parser::{ClientHelloFingerprint, TlsVersion};

    fn from_hex(hex: &str) -> Vec<u8>
    {
        let mut out = Vec::new();
        for i in (0..hex.len() / 2).map(|x| x * 2) {
            out.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
        }
        out
    }


    #[test]
    fn test_empty_fingerprint() {
        let ch = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS10,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: Vec::new(),
            compression_methods: Vec::new(),
            extensions: Vec::new(),
            named_groups: Vec::new(),
            ec_point_fmt: Vec::new(),
            sig_algs: Vec::new(),
            alpn: Vec::new(),
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };
        assert_eq!(ch.get_fingerprint(), 6116981759083077708);
    }


    #[test]
    fn test_chrome_fingerprint() {
        let ch = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS10,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: vec![0x0a, 0x0a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
                                0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0x13,
                                0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f,
                                0x00, 0x35, 0x00, 0x0a],
            compression_methods: vec![0],
            extensions: vec![0x0a, 0x0a, 0xff, 0x01, 0x00, 0x00, 0x00, 0x17,
                             0x00, 0x23, 0x00, 0x0d, 0x00, 0x05, 0x00, 0x12,
                             0x00, 0x10, 0x75, 0x50, 0x00, 0x0b, 0x00, 0x0a,
                             0x0a, 0x0a],
            named_groups: vec![0x00, 0x08, 0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17,
                               0x00, 0x18],
            ec_point_fmt: vec![0x01, 0x00],
            sig_algs: vec![0x00, 0x00, 0x00, 0x12, 0x00, 0x04, 0x00, 0x03,
                           0x00, 0x08, 0x00, 0x04, 0x00, 0x04, 0x00, 0x01,
                           0x00, 0x05, 0x00, 0x03, 0x00, 0x08, 0x00, 0x05,
                           0x00, 0x05, 0x00, 0x01, 0x00, 0x08, 0x00, 0x06,
                           0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x01],
            alpn: vec![0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00, 0x68,
                       0x00, 0x32, 0x00, 0x08, 0x00, 0x68, 0x00, 0x74,
                       0x00, 0x74, 0x00, 0x70, 0x00, 0x2f, 0x00, 0x31,
                       0x00, 0x2e, 0x00, 0x31],
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };
        assert_eq!(ch.get_fingerprint(), 2850294275305369904);
    }

    #[test]
    fn test_parse_ie() {
        let correct = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS12,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: vec![0x00, 0x3c, 0x00, 0x2f, 0x00, 0x3d, 0x00, 0x35,
                                0x00, 0x05, 0x00, 0x0a, 0xc0, 0x27, 0xc0, 0x13,
                                0xc0, 0x14, 0xc0, 0x2b, 0xc0, 0x23, 0xc0, 0x2c,
                                0xc0, 0x24, 0xc0, 0x09, 0xc0, 0x0a, 0x00, 0x40,
                                0x00, 0x32, 0x00, 0x6a, 0x00, 0x38, 0x00, 0x13,
                                0x00, 0x04],
            compression_methods: vec![0],
            extensions: vec![0x00, 0x00, 0x00, 0x05, 0x00, 0x0a, 0x00, 0x0b,
                             0x00, 0x0d, 0x00, 0x17, 0xff, 0x01],
            named_groups: vec![0x00, 0x04, 0x00, 0x17, 0x00, 0x18],
            ec_point_fmt: vec![0x01, 0x00],
            sig_algs: vec![0x00, 0x0e, 0x04, 0x01, 0x05, 0x01, 0x02, 0x01,
                           0x04, 0x03, 0x05, 0x03, 0x02, 0x03, 0x02, 0x02],
            alpn: vec![],
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };

        let buf = from_hex("16030300b8010000b4030359dd0e129dddd32e1645a018f43d7685f27972f4f518f5092d5105377b1448c200002a003c002f003d00350005000ac027c013c014c02bc023c02cc024c009c00a00400032006a00380013000401000061000000270025000022696531315f3077696e646f7773372e66696e6765727072696e742e637266732e696f000500050100000000000a0006000400170018000b00020100000d0010000e040105010201040305030203020200170000ff01000100");

        let res = ClientHelloFingerprint::from_try(&buf);

        assert_eq!(res, Ok(correct));
    }

    #[test]
    fn test_parse_chrome() {
        let correct = ClientHelloFingerprint {
            record_tls_version: TlsVersion::TLS10,
            ch_tls_version: TlsVersion::TLS12,
            cipher_suites: vec![0x0a, 0x0a, 0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c,
                                0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14,
                                0xcc, 0x13, 0xc0, 0x13, 0xc0, 0x14, 0x00, 0x9c,
                                0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a],
            compression_methods: vec![0],
            extensions: vec![0x0a, 0x0a, 0xff, 0x01, 0x00, 0x00, 0x00, 0x17,
                             0x00, 0x23, 0x00, 0x0d, 0x00, 0x05, 0x00, 0x12,
                             0x00, 0x10, 0x75, 0x50, 0x00, 0x0b, 0x00, 0x0a,
                             0x0a, 0x0a],
            named_groups: vec![0x00, 0x08, 0x0a, 0x0a, 0x00, 0x1d, 0x00, 0x17,
                               0x00, 0x18],
            ec_point_fmt: vec![0x01, 0x00],
            sig_algs: vec![0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01,
                           0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06,
                           0x06, 0x01, 0x02, 0x01],
            alpn: vec![0x00, 0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74,
                       0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31],
            sni: Vec::new(),
            ticket_size: None,
            key_share: Vec::new(),
            psk_key_exchange_modes: Vec::new(),
            supported_versions: Vec::new(),
            cert_compression_algs: Vec::new(),
            record_size_limit: Vec::new(),
        };

        let buf = from_hex("16030100e2010000de03036060d2755be23452624da20b1243313e638a444f15ee3968c6a20d05b63eaeab0000206a6ac02bc02fc02cc030cca9cca8cc14cc13c013c014009c009d002f0035000a01000095dada0000ff010001000000002c002a0000276368726f6d6535365f306f73787369657272612e66696e6765727072696e742e637266732e696f0017000000230000000d00140012040308040401050308050501080606010201000500050100000000001200000010000e000c02683208687474702f312e3175500000000b00020100000a000a00086a6a001d001700187a7a000100");

        let res = ClientHelloFingerprint::from_try(&buf);
        assert_eq!(res, Ok(correct));
    }
}
