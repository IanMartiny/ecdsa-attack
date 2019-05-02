extern crate byteorder;
extern crate crypto;
extern crate hex_slice;
extern crate num;
extern crate openssl;

use self::byteorder::{ByteOrder, BigEndian};
use self::crypto::digest::Digest;
use self::crypto::sha1::Sha1;
use self::hex_slice::AsHex;
use self::openssl::x509::X509;

use common::{hash_u32, ParseError, u8_to_u16_be, u8_to_u32_be, vec_u8_to_vec_u16_be};
use tls_parser;

use self::num::FromPrimitive;

use std::fmt;

enum_from_primitive! {
#[repr(u8)]
#[derive(PartialEq)]
pub enum TlsRecordType {
	ChangeCipherSpec = 20,
	Alert            = 21,
	Handshake        = 22,
	ApplicationData  = 23,
	Heartbeat        = 24,
}
}

enum_from_primitive! {
#[repr(u8)]
#[derive(PartialEq)]
pub enum TlsHandshakeType {
    HelloRequest       = 0,
	ClientHello        = 1,
	ServerHello        = 2,
	NewSessionTicket   = 4,
	Certificate        = 11,
	ServerKeyExchange  = 12,
	CertificateRequest = 13,
	ServerHelloDone    = 14,
	CertificateVerify  = 15,
	ClientKeyExchange  = 16,
	Finished           = 20,
	CertificateStatus  = 22,
	NextProtocol       = 67, // Not IANA assigned
}
}


enum_from_primitive! {
#[repr(u16)]
#[derive(Debug, PartialEq)]
pub enum TlsExtension {
	ServerName                       = 0,
	StatusRequest                    = 5,
	SupportedCurves                  = 10,
	SupportedPoints                  = 11,
	SignatureAlgorithms              = 13,
	ALPN                             = 16,
	SCT                              = 18, // https://tools.ietf.org/html/rfc6962#section-6
	Padding                          = 21,
	ExtendedMasterSecret             = 23, // https://tools.ietf.org/html/rfc7627
	SessionTicket                    = 35,
	NextProtoNeg                     = 13172, // not IANA assigned
	RenegotiationInfo                = 0xff01,
	ChannelID                        = 30032, // not IANA assigned

    KeyShare                         = 0x0033,
    PskKeyExchangeModes              = 0x002D,
    SupportedVersions                = 0x002B,
    CertificateCompressionAlgorithms = 0x001B,
    TokenBinding                     = 0x0018,
    EarlyData                        = 0x002A,
    PreSharedKey                     = 0x0029,
    RecordSizeLimit                  = 0x001C,
}
}

enum_from_primitive! {
#[repr(i16)]
#[derive(Debug, Hash, PartialEq, Clone, Copy)]
pub enum TlsVersion {
    // TODO
    NONE  = 0x0000,
	SSL30 = 0x0300,
	TLS10 = 0x0301,
	TLS11 = 0x0302,
	TLS12 = 0x0303,
}
}

impl Default for TlsVersion{
    fn default() -> TlsVersion {
        TlsVersion::NONE
    }
}

enum_from_primitive! {
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum CipherSuite {
    TlsNullWithNullNull                     = 0x0000,
    TlsRsaWithNullMd5                       = 0x0001,
    TlsRsaWithNullSha                       = 0x0002,
    TlsRsaExportWithRc440Md5              	= 0x0003,
    TlsRsaWithRc4128Md5                    	= 0x0004,
    TlsRsaWithRc4128Sha                    	= 0x0005,
    TlsRsaExportWithRc2Cbc40Md5          	= 0x0006,
    TlsRsaWithIdeaCbcSha                   	= 0x0007,
    TlsRsaExportWithDes40CbcSha           	= 0x0008,
    TlsRsaWithDesCbcSha                    	= 0x0009,
    TlsRsaWith3DesEdeCbcSha               	= 0x000A,
    TlsDhDssExportWithDes40CbcSha        	= 0x000B,
    TlsDhDssWithDesCbcSha                 	= 0x000C,
    TlsDhDssWith3DesEdeCbcSha            	= 0x000D,
    TlsDhRsaExportWithDes40CbcSha        	= 0x000E,
    TlsDhRsaWithDesCbcSha                 	= 0x000F,
    TlsDhRsaWith3DesEdeCbcSha            	= 0x0010,
    TlsDheDssExportWithDes40CbcSha       	= 0x0011,
    TlsDheDssWithDesCbcSha                	= 0x0012,
    TlsDheDssWith3DesEdeCbcSha           	= 0x0013,
    TlsDheRsaExportWithDes40CbcSha       	= 0x0014,
    TlsDheRsaWithDesCbcSha                	= 0x0015,
    TlsDheRsaWith3DesEdeCbcSha           	= 0x0016,
    TlsDhAnonExportWithRc440Md5          	= 0x0017,
    TlsDhAnonWithRc4128Md5                	= 0x0018,
    TlsDhAnonExportWithDes40CbcSha       	= 0x0019,
    TlsDhAnonWithDesCbcSha                	= 0x001A,
    TlsDhAnonWith3DesEdeCbcSha           	= 0x001B,
    TlsKrb5WithDesCbcSha                   	= 0x001E,
    TlsKrb5With3DesEdeCbcSha              	= 0x001F,
    TlsKrb5WithRc4128Sha                   	= 0x0020,
    TlsKrb5WithIdeaCbcSha                  	= 0x0021,
    TlsKrb5WithDesCbcMd5                   	= 0x0022,
    TlsKrb5With3DesEdeCbcMd5              	= 0x0023,
    TlsKrb5WithRc4128Md5                   	= 0x0024,
    TlsKrb5WithIdeaCbcMd5                  	= 0x0025,
    TlsKrb5ExportWithDesCbc40Sha         	= 0x0026,
    TlsKrb5ExportWithRc2Cbc40Sha         	= 0x0027,
    TlsKrb5ExportWithRc440Sha             	= 0x0028,
    TlsKrb5ExportWithDesCbc40Md5         	= 0x0029,
    TlsKrb5ExportWithRc2Cbc40Md5         	= 0x002A,
    TlsKrb5ExportWithRc440Md5             	= 0x002B,
    TlsPskWithNullSha                       = 0x002C,
    TlsDhePskWithNullSha                   	= 0x002D,
    TlsRsaPskWithNullSha                   	= 0x002E,
    TlsRsaWithAes128CbcSha                	= 0x002F,
    TlsDhDssWithAes128CbcSha             	= 0x0030,
    TlsDhRsaWithAes128CbcSha             	= 0x0031,
    TlsDheDssWithAes128CbcSha            	= 0x0032,
    TlsDheRsaWithAes128CbcSha            	= 0x0033,
    TlsDhAnonWithAes128CbcSha            	= 0x0034,
    TlsRsaWithAes256CbcSha                	= 0x0035,
    TlsDhDssWithAes256CbcSha             	= 0x0036,
    TlsDhRsaWithAes256CbcSha             	= 0x0037,
    TlsDheDssWithAes256CbcSha            	= 0x0038,
    TlsDheRsaWithAes256CbcSha            	= 0x0039,
    TlsDhAnonWithAes256CbcSha            	= 0x003A,
    TlsRsaWithNullSha256                    = 0x003B,
    TlsRsaWithAes128CbcSha256             	= 0x003C,
    TlsRsaWithAes256CbcSha256             	= 0x003D,
    TlsDhDssWithAes128CbcSha256          	= 0x003E,
    TlsDhRsaWithAes128CbcSha256          	= 0x003F,
    TlsDheDssWithAes128CbcSha256         	= 0x0040,
    TlsRsaWithCamellia128CbcSha           	= 0x0041,
    TlsDhDssWithCamellia128CbcSha        	= 0x0042,
    TlsDhRsaWithCamellia128CbcSha        	= 0x0043,
    TlsDheDssWithCamellia128CbcSha       	= 0x0044,
    TlsDheRsaWithCamellia128CbcSha       	= 0x0045,
    TlsDhAnonWithCamellia128CbcSha       	= 0x0046,
    TlsDheRsaWithAes128CbcSha256         	= 0x0067,
    TlsDhDssWithAes256CbcSha256          	= 0x0068,
    TlsDhRsaWithAes256CbcSha256          	= 0x0069,
    TlsDheDssWithAes256CbcSha256         	= 0x006A,
    TlsDheRsaWithAes256CbcSha256         	= 0x006B,
    TlsDhAnonWithAes128CbcSha256         	= 0x006C,
    TlsDhAnonWithAes256CbcSha256         	= 0x006D,
    TlsRsaWithCamellia256CbcSha           	= 0x0084,
    TlsDhDssWithCamellia256CbcSha        	= 0x0085,
    TlsDhRsaWithCamellia256CbcSha        	= 0x0086,
    TlsDheDssWithCamellia256CbcSha       	= 0x0087,
    TlsDheRsaWithCamellia256CbcSha       	= 0x0088,
    TlsDhAnonWithCamellia256CbcSha       	= 0x0089,
    TlsPskWithRc4128Sha                    	= 0x008A,
    TlsPskWith3DesEdeCbcSha               	= 0x008B,
    TlsPskWithAes128CbcSha                	= 0x008C,
    TlsPskWithAes256CbcSha                	= 0x008D,
    TlsDhePskWithRc4128Sha                	= 0x008E,
    TlsDhePskWith3DesEdeCbcSha           	= 0x008F,
    TlsDhePskWithAes128CbcSha            	= 0x0090,
    TlsDhePskWithAes256CbcSha            	= 0x0091,
    TlsRsaPskWithRc4128Sha                	= 0x0092,
    TlsRsaPskWith3DesEdeCbcSha           	= 0x0093,
    TlsRsaPskWithAes128CbcSha            	= 0x0094,
    TlsRsaPskWithAes256CbcSha            	= 0x0095,
    TlsRsaWithSeedCbcSha                   	= 0x0096,
    TlsDhDssWithSeedCbcSha                	= 0x0097,
    TlsDhRsaWithSeedCbcSha                	= 0x0098,
    TlsDheDssWithSeedCbcSha               	= 0x0099,
    TlsDheRsaWithSeedCbcSha               	= 0x009A,
    TlsDhAnonWithSeedCbcSha               	= 0x009B,
    TlsRsaWithAes128GcmSha256             	= 0x009C,
    TlsRsaWithAes256GcmSha384             	= 0x009D,
    TlsDheRsaWithAes128GcmSha256         	= 0x009E,
    TlsDheRsaWithAes256GcmSha384         	= 0x009F,
    TlsDhRsaWithAes128GcmSha256          	= 0x00A0,
    TlsDhRsaWithAes256GcmSha384          	= 0x00A1,
    TlsDheDssWithAes128GcmSha256         	= 0x00A2,
    TlsDheDssWithAes256GcmSha384         	= 0x00A3,
    TlsDhDssWithAes128GcmSha256          	= 0x00A4,
    TlsDhDssWithAes256GcmSha384          	= 0x00A5,
    TlsDhAnonWithAes128GcmSha256         	= 0x00A6,
    TlsDhAnonWithAes256GcmSha384         	= 0x00A7,
    TlsPskWithAes128GcmSha256             	= 0x00A8,
    TlsPskWithAes256GcmSha384             	= 0x00A9,
    TlsDhePskWithAes128GcmSha256         	= 0x00AA,
    TlsDhePskWithAes256GcmSha384         	= 0x00AB,
    TlsRsaPskWithAes128GcmSha256         	= 0x00AC,
    TlsRsaPskWithAes256GcmSha384         	= 0x00AD,
    TlsPskWithAes128CbcSha256             	= 0x00AE,
    TlsPskWithAes256CbcSha384             	= 0x00AF,
    TlsPskWithNullSha256                    = 0x00B0,
    TlsPskWithNullSha384                    = 0x00B1,
    TlsDhePskWithAes128CbcSha256         	= 0x00B2,
    TlsDhePskWithAes256CbcSha384         	= 0x00B3,
    TlsDhePskWithNullSha256                	= 0x00B4,
    TlsDhePskWithNullSha384                	= 0x00B5,
    TlsRsaPskWithAes128CbcSha256         	= 0x00B6,
    TlsRsaPskWithAes256CbcSha384         	= 0x00B7,
    TlsRsaPskWithNullSha256                	= 0x00B8,
    TlsRsaPskWithNullSha384                	= 0x00B9,
    TlsRsaWithCamellia128CbcSha256        	= 0x00BA,
    TlsDhDssWithCamellia128CbcSha256     	= 0x00BB,
    TlsDhRsaWithCamellia128CbcSha256     	= 0x00BC,
    TlsDheDssWithCamellia128CbcSha256    	= 0x00BD,
    TlsDheRsaWithCamellia128CbcSha256    	= 0x00BE,
    TlsDhAnonWithCamellia128CbcSha256    	= 0x00BF,
    TlsRsaWithCamellia256CbcSha256        	= 0x00C0,
    TlsDhDssWithCamellia256CbcSha256     	= 0x00C1,
    TlsDhRsaWithCamellia256CbcSha256     	= 0x00C2,
    TlsDheDssWithCamellia256CbcSha256    	= 0x00C3,
    TlsDheRsaWithCamellia256CbcSha256    	= 0x00C4,
    TlsDhAnonWithCamellia256CbcSha256    	= 0x00C5,
    TlsEmptyRenegotiationInfoScsv           = 0x00FF,
    TlsAes128GcmSha256                      = 0x1301,
    TlsAes256GcmSha384                      = 0x1302,
    TlsChacha20Poly1305Sha256               = 0x1303,
    TlsAes128CcmSha256                      = 0x1304,
    TlsAes128Ccm8Sha256                    	= 0x1305,
    TlsFallbackScsv                         = 0x5600,
    TlsEcdhEcdsaWithNullSha                	= 0xC001,
    TlsEcdhEcdsaWithRc4128Sha             	= 0xC002,
    TlsEcdhEcdsaWith3DesEdeCbcSha        	= 0xC003,
    TlsEcdhEcdsaWithAes128CbcSha         	= 0xC004,
    TlsEcdhEcdsaWithAes256CbcSha         	= 0xC005,
    TlsEcdheEcdsaWithNullSha               	= 0xC006,
    TlsEcdheEcdsaWithRc4128Sha            	= 0xC007,
    TlsEcdheEcdsaWith3DesEdeCbcSha       	= 0xC008,
    TlsEcdheEcdsaWithAes128CbcSha        	= 0xC009,
    TlsEcdheEcdsaWithAes256CbcSha        	= 0xC00A,
    TlsEcdhRsaWithNullSha                  	= 0xC00B,
    TlsEcdhRsaWithRc4128Sha               	= 0xC00C,
    TlsEcdhRsaWith3DesEdeCbcSha          	= 0xC00D,
    TlsEcdhRsaWithAes128CbcSha           	= 0xC00E,
    TlsEcdhRsaWithAes256CbcSha           	= 0xC00F,
    TlsEcdheRsaWithNullSha                 	= 0xC010,
    TlsEcdheRsaWithRc4128Sha              	= 0xC011,
    TlsEcdheRsaWith3DesEdeCbcSha         	= 0xC012,
    TlsEcdheRsaWithAes128CbcSha          	= 0xC013,
    TlsEcdheRsaWithAes256CbcSha          	= 0xC014,
    TlsEcdhAnonWithNullSha                 	= 0xC015,
    TlsEcdhAnonWithRc4128Sha              	= 0xC016,
    TlsEcdhAnonWith3DesEdeCbcSha         	= 0xC017,
    TlsEcdhAnonWithAes128CbcSha          	= 0xC018,
    TlsEcdhAnonWithAes256CbcSha          	= 0xC019,
    TlsSrpShaWith3DesEdeCbcSha           	= 0xC01A,
    TlsSrpShaRsaWith3DesEdeCbcSha       	= 0xC01B,
    TlsSrpShaDssWith3DesEdeCbcSha       	= 0xC01C,
    TlsSrpShaWithAes128CbcSha            	= 0xC01D,
    TlsSrpShaRsaWithAes128CbcSha        	= 0xC01E,
    TlsSrpShaDssWithAes128CbcSha        	= 0xC01F,
    TlsSrpShaWithAes256CbcSha            	= 0xC020,
    TlsSrpShaRsaWithAes256CbcSha        	= 0xC021,
    TlsSrpShaDssWithAes256CbcSha        	= 0xC022,
    TlsEcdheEcdsaWithAes128CbcSha256     	= 0xC023,
    TlsEcdheEcdsaWithAes256CbcSha384     	= 0xC024,
    TlsEcdhEcdsaWithAes128CbcSha256      	= 0xC025,
    TlsEcdhEcdsaWithAes256CbcSha384      	= 0xC026,
    TlsEcdheRsaWithAes128CbcSha256       	= 0xC027,
    TlsEcdheRsaWithAes256CbcSha384       	= 0xC028,
    TlsEcdhRsaWithAes128CbcSha256        	= 0xC029,
    TlsEcdhRsaWithAes256CbcSha384        	= 0xC02A,
    TlsEcdheEcdsaWithAes128GcmSha256     	= 0xC02B,
    TlsEcdheEcdsaWithAes256GcmSha384     	= 0xC02C,
    TlsEcdhEcdsaWithAes128GcmSha256      	= 0xC02D,
    TlsEcdhEcdsaWithAes256GcmSha384      	= 0xC02E,
    TlsEcdheRsaWithAes128GcmSha256       	= 0xC02F,
    TlsEcdheRsaWithAes256GcmSha384       	= 0xC030,
    TlsEcdhRsaWithAes128GcmSha256        	= 0xC031,
    TlsEcdhRsaWithAes256GcmSha384        	= 0xC032,
    TlsEcdhePskWithRc4128Sha              	= 0xC033,
    TlsEcdhePskWith3DesEdeCbcSha         	= 0xC034,
    TlsEcdhePskWithAes128CbcSha          	= 0xC035,
    TlsEcdhePskWithAes256CbcSha          	= 0xC036,
    TlsEcdhePskWithAes128CbcSha256       	= 0xC037,
    TlsEcdhePskWithAes256CbcSha384       	= 0xC038,
    TlsEcdhePskWithNullSha                 	= 0xC039,
    TlsEcdhePskWithNullSha256              	= 0xC03A,
    TlsEcdhePskWithNullSha384              	= 0xC03B,
    TlsRsaWithAria128CbcSha256            	= 0xC03C,
    TlsRsaWithAria256CbcSha384            	= 0xC03D,
    TlsDhDssWithAria128CbcSha256         	= 0xC03E,
    TlsDhDssWithAria256CbcSha384         	= 0xC03F,
    TlsDhRsaWithAria128CbcSha256         	= 0xC040,
    TlsDhRsaWithAria256CbcSha384         	= 0xC041,
    TlsDheDssWithAria128CbcSha256        	= 0xC042,
    TlsDheDssWithAria256CbcSha384        	= 0xC043,
    TlsDheRsaWithAria128CbcSha256        	= 0xC044,
    TlsDheRsaWithAria256CbcSha384        	= 0xC045,
    TlsDhAnonWithAria128CbcSha256        	= 0xC046,
    TlsDhAnonWithAria256CbcSha384        	= 0xC047,
    TlsEcdheEcdsaWithAria128CbcSha256    	= 0xC048,
    TlsEcdheEcdsaWithAria256CbcSha384    	= 0xC049,
    TlsEcdhEcdsaWithAria128CbcSha256     	= 0xC04A,
    TlsEcdhEcdsaWithAria256CbcSha384     	= 0xC04B,
    TlsEcdheRsaWithAria128CbcSha256      	= 0xC04C,
    TlsEcdheRsaWithAria256CbcSha384      	= 0xC04D,
    TlsEcdhRsaWithAria128CbcSha256       	= 0xC04E,
    TlsEcdhRsaWithAria256CbcSha384       	= 0xC04F,
    TlsRsaWithAria128GcmSha256            	= 0xC050,
    TlsRsaWithAria256GcmSha384            	= 0xC051,
    TlsDheRsaWithAria128GcmSha256        	= 0xC052,
    TlsDheRsaWithAria256GcmSha384        	= 0xC053,
    TlsDhRsaWithAria128GcmSha256         	= 0xC054,
    TlsDhRsaWithAria256GcmSha384         	= 0xC055,
    TlsDheDssWithAria128GcmSha256        	= 0xC056,
    TlsDheDssWithAria256GcmSha384        	= 0xC057,
    TlsDhDssWithAria128GcmSha256         	= 0xC058,
    TlsDhDssWithAria256GcmSha384         	= 0xC059,
    TlsDhAnonWithAria128GcmSha256        	= 0xC05A,
    TlsDhAnonWithAria256GcmSha384        	= 0xC05B,
    TlsEcdheEcdsaWithAria128GcmSha256    	= 0xC05C,
    TlsEcdheEcdsaWithAria256GcmSha384    	= 0xC05D,
    TlsEcdhEcdsaWithAria128GcmSha256     	= 0xC05E,
    TlsEcdhEcdsaWithAria256GcmSha384     	= 0xC05F,
    TlsEcdheRsaWithAria128GcmSha256      	= 0xC060,
    TlsEcdheRsaWithAria256GcmSha384      	= 0xC061,
    TlsEcdhRsaWithAria128GcmSha256       	= 0xC062,
    TlsEcdhRsaWithAria256GcmSha384       	= 0xC063,
    TlsPskWithAria128CbcSha256            	= 0xC064,
    TlsPskWithAria256CbcSha384            	= 0xC065,
    TlsDhePskWithAria128CbcSha256        	= 0xC066,
    TlsDhePskWithAria256CbcSha384        	= 0xC067,
    TlsRsaPskWithAria128CbcSha256        	= 0xC068,
    TlsRsaPskWithAria256CbcSha384        	= 0xC069,
    TlsPskWithAria128GcmSha256            	= 0xC06A,
    TlsPskWithAria256GcmSha384            	= 0xC06B,
    TlsDhePskWithAria128GcmSha256        	= 0xC06C,
    TlsDhePskWithAria256GcmSha384        	= 0xC06D,
    TlsRsaPskWithAria128GcmSha256        	= 0xC06E,
    TlsRsaPskWithAria256GcmSha384        	= 0xC06F,
    TlsEcdhePskWithAria128CbcSha256      	= 0xC070,
    TlsEcdhePskWithAria256CbcSha384      	= 0xC071,
    TlsEcdheEcdsaWithCamellia128CbcSha256	= 0xC072,
    TlsEcdheEcdsaWithCamellia256CbcSha384	= 0xC073,
    TlsEcdhEcdsaWithCamellia128CbcSha256 	= 0xC074,
    TlsEcdhEcdsaWithCamellia256CbcSha384 	= 0xC075,
    TlsEcdheRsaWithCamellia128CbcSha256  	= 0xC076,
    TlsEcdheRsaWithCamellia256CbcSha384  	= 0xC077,
    TlsEcdhRsaWithCamellia128CbcSha256   	= 0xC078,
    TlsEcdhRsaWithCamellia256CbcSha384   	= 0xC079,
    TlsRsaWithCamellia128GcmSha256        	= 0xC07A,
    TlsRsaWithCamellia256GcmSha384        	= 0xC07B,
    TlsDheRsaWithCamellia128GcmSha256    	= 0xC07C,
    TlsDheRsaWithCamellia256GcmSha384    	= 0xC07D,
    TlsDhRsaWithCamellia128GcmSha256     	= 0xC07E,
    TlsDhRsaWithCamellia256GcmSha384     	= 0xC07F,
    TlsDheDssWithCamellia128GcmSha256    	= 0xC080,
    TlsDheDssWithCamellia256GcmSha384    	= 0xC081,
    TlsDhDssWithCamellia128GcmSha256     	= 0xC082,
    TlsDhDssWithCamellia256GcmSha384     	= 0xC083,
    TlsDhAnonWithCamellia128GcmSha256    	= 0xC084,
    TlsDhAnonWithCamellia256GcmSha384    	= 0xC085,
    TlsEcdheEcdsaWithCamellia128GcmSha256	= 0xC086,
    TlsEcdheEcdsaWithCamellia256GcmSha384	= 0xC087,
    TlsEcdhEcdsaWithCamellia128GcmSha256 	= 0xC088,
    TlsEcdhEcdsaWithCamellia256GcmSha384 	= 0xC089,
    TlsEcdheRsaWithCamellia128GcmSha256  	= 0xC08A,
    TlsEcdheRsaWithCamellia256GcmSha384  	= 0xC08B,
    TlsEcdhRsaWithCamellia128GcmSha256   	= 0xC08C,
    TlsEcdhRsaWithCamellia256GcmSha384   	= 0xC08D,
    TlsPskWithCamellia128GcmSha256        	= 0xC08E,
    TlsPskWithCamellia256GcmSha384        	= 0xC08F,
    TlsDhePskWithCamellia128GcmSha256    	= 0xC090,
    TlsDhePskWithCamellia256GcmSha384    	= 0xC091,
    TlsRsaPskWithCamellia128GcmSha256    	= 0xC092,
    TlsRsaPskWithCamellia256GcmSha384    	= 0xC093,
    TlsPskWithCamellia128CbcSha256        	= 0xC094,
    TlsPskWithCamellia256CbcSha384        	= 0xC095,
    TlsDhePskWithCamellia128CbcSha256    	= 0xC096,
    TlsDhePskWithCamellia256CbcSha384    	= 0xC097,
    TlsRsaPskWithCamellia128CbcSha256    	= 0xC098,
    TlsRsaPskWithCamellia256CbcSha384    	= 0xC099,
    TlsEcdhePskWithCamellia128CbcSha256  	= 0xC09A,
    TlsEcdhePskWithCamellia256CbcSha384  	= 0xC09B,
    TlsRsaWithAes128Ccm                    	= 0xC09C,
    TlsRsaWithAes256Ccm                    	= 0xC09D,
    TlsDheRsaWithAes128Ccm                	= 0xC09E,
    TlsDheRsaWithAes256Ccm                	= 0xC09F,
    TlsRsaWithAes128Ccm8                  	= 0xC0A0,
    TlsRsaWithAes256Ccm8                  	= 0xC0A1,
    TlsDheRsaWithAes128Ccm8              	= 0xC0A2,
    TlsDheRsaWithAes256Ccm8              	= 0xC0A3,
    TlsPskWithAes128Ccm                    	= 0xC0A4,
    TlsPskWithAes256Ccm                    	= 0xC0A5,
    TlsDhePskWithAes128Ccm                	= 0xC0A6,
    TlsDhePskWithAes256Ccm                	= 0xC0A7,
    TlsPskWithAes128Ccm8                  	= 0xC0A8,
    TlsPskWithAes256Ccm8                  	= 0xC0A9,
    TlsPskDheWithAes128Ccm8              	= 0xC0AA,
    TlsPskDheWithAes256Ccm8              	= 0xC0AB,
    TlsEcdheEcdsaWithAes128Ccm            	= 0xC0AC,
    TlsEcdheEcdsaWithAes256Ccm            	= 0xC0AD,
    TlsEcdheEcdsaWithAes128Ccm8          	= 0xC0AE,
    TlsEcdheEcdsaWithAes256Ccm8          	= 0xC0AF,
    TlsEccpwdWithAes128GcmSha256          	= 0xC0B0,
    TlsEccpwdWithAes256GcmSha384          	= 0xC0B1,
    TlsEccpwdWithAes128CcmSha256          	= 0xC0B2,
    TlsEccpwdWithAes256CcmSha384          	= 0xC0B3,
    TlsSha256Sha256                         = 0xC0B4,
    TlsSha384Sha384                         = 0xC0B5,
    TlsGostr341112256WithKuznyechikCtrOmac	= 0xC100,
    TlsGostr341112256WithMagmaCtrOmac     	= 0xC101,
    TlsGostr341112256With28147CntImit     	= 0xC102,
    TlsEcdheRsaWithChacha20Poly1305Sha256 	= 0xCCA8,
    TlsEcdheEcdsaWithChacha20Poly1305Sha256	= 0xCCA9,
    TlsDheRsaWithChacha20Poly1305Sha256   	= 0xCCAA,
    TlsPskWithChacha20Poly1305Sha256       	= 0xCCAB,
    TlsEcdhePskWithChacha20Poly1305Sha256 	= 0xCCAC,
    TlsDhePskWithChacha20Poly1305Sha256   	= 0xCCAD,
    TlsRsaPskWithChacha20Poly1305Sha256   	= 0xCCAE,
    TlsEcdhePskWithAes128GcmSha256       	= 0xD001,
    TlsEcdhePskWithAes256GcmSha384       	= 0xD002,
    TlsEcdhePskWithAes128Ccm8Sha256     	= 0xD003,
    TlsEcdhePskWithAes128CcmSha256       	= 0xD005,
}
}

impl Default for CipherSuite {
    fn default() -> Self {CipherSuite::TlsNullWithNullNull}
}

impl fmt::UpperHex for CipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", *self as u16)
    }
}

enum_from_primitive! {
#[repr(u16)]
#[derive(Debug)]
pub enum HasSignature {
    TlsDhDssExportWithDes40CbcSha        	= 0x000B,
    TlsDhDssWithDesCbcSha                 	= 0x000C,
    TlsDhDssWith3DesEdeCbcSha            	= 0x000D,
    TlsDhRsaExportWithDes40CbcSha        	= 0x000E,
    TlsDhRsaWithDesCbcSha                 	= 0x000F,
    TlsDhRsaWith3DesEdeCbcSha            	= 0x0010,
    TlsDheDssExportWithDes40CbcSha       	= 0x0011,
    TlsDheDssWithDesCbcSha                	= 0x0012,
    TlsDheDssWith3DesEdeCbcSha           	= 0x0013,
    TlsDheRsaExportWithDes40CbcSha       	= 0x0014,
    TlsDheRsaWithDesCbcSha                	= 0x0015,
    TlsDheRsaWith3DesEdeCbcSha           	= 0x0016,
    TlsDhDssWithAes128CbcSha             	= 0x0030,
    TlsDhRsaWithAes128CbcSha             	= 0x0031,
    TlsDheDssWithAes128CbcSha            	= 0x0032,
    TlsDheRsaWithAes128CbcSha            	= 0x0033,
    TlsDhDssWithAes256CbcSha             	= 0x0036,
    TlsDhRsaWithAes256CbcSha             	= 0x0037,
    TlsDheDssWithAes256CbcSha            	= 0x0038,
    TlsDheRsaWithAes256CbcSha            	= 0x0039,
    TlsDhDssWithAes128CbcSha256          	= 0x003E,
    TlsDhRsaWithAes128CbcSha256          	= 0x003F,
    TlsDheDssWithAes128CbcSha256         	= 0x0040,
    TlsDhDssWithCamellia128CbcSha        	= 0x0042,
    TlsDhRsaWithCamellia128CbcSha        	= 0x0043,
    TlsDheDssWithCamellia128CbcSha       	= 0x0044,
    TlsDheRsaWithCamellia128CbcSha       	= 0x0045,
    TlsDheRsaWithAes128CbcSha256         	= 0x0067,
    TlsDhDssWithAes256CbcSha256          	= 0x0068,
    TlsDhRsaWithAes256CbcSha256          	= 0x0069,
    TlsDheDssWithAes256CbcSha256         	= 0x006A,
    TlsDheRsaWithAes256CbcSha256         	= 0x006B,
    TlsDhDssWithCamellia256CbcSha        	= 0x0085,
    TlsDhRsaWithCamellia256CbcSha        	= 0x0086,
    TlsDheDssWithCamellia256CbcSha       	= 0x0087,
    TlsDheRsaWithCamellia256CbcSha       	= 0x0088,
    TlsDhDssWithSeedCbcSha                	= 0x0097,
    TlsDhRsaWithSeedCbcSha                	= 0x0098,
    TlsDheDssWithSeedCbcSha               	= 0x0099,
    TlsDheRsaWithSeedCbcSha               	= 0x009A,
    TlsDheRsaWithAes128GcmSha256         	= 0x009E,
    TlsDheRsaWithAes256GcmSha384         	= 0x009F,
    TlsDhRsaWithAes128GcmSha256          	= 0x00A0,
    TlsDhRsaWithAes256GcmSha384          	= 0x00A1,
    TlsDheDssWithAes128GcmSha256         	= 0x00A2,
    TlsDheDssWithAes256GcmSha384         	= 0x00A3,
    TlsDhDssWithAes128GcmSha256          	= 0x00A4,
    TlsDhDssWithAes256GcmSha384          	= 0x00A5,
    TlsDhDssWithCamellia128CbcSha256     	= 0x00BB,
    TlsDhRsaWithCamellia128CbcSha256     	= 0x00BC,
    TlsDheDssWithCamellia128CbcSha256    	= 0x00BD,
    TlsDheRsaWithCamellia128CbcSha256    	= 0x00BE,
    TlsDhDssWithCamellia256CbcSha256     	= 0x00C1,
    TlsDhRsaWithCamellia256CbcSha256     	= 0x00C2,
    TlsDheDssWithCamellia256CbcSha256    	= 0x00C3,
    TlsDheRsaWithCamellia256CbcSha256    	= 0x00C4,
    TlsEcdhEcdsaWithNullSha                	= 0xC001,
    TlsEcdhEcdsaWithRc4128Sha             	= 0xC002,
    TlsEcdhEcdsaWith3DesEdeCbcSha        	= 0xC003,
    TlsEcdhEcdsaWithAes128CbcSha         	= 0xC004,
    TlsEcdhEcdsaWithAes256CbcSha         	= 0xC005,
    TlsEcdheEcdsaWithNullSha               	= 0xC006,
    TlsEcdheEcdsaWithRc4128Sha            	= 0xC007,
    TlsEcdheEcdsaWith3DesEdeCbcSha       	= 0xC008,
    TlsEcdheEcdsaWithAes128CbcSha        	= 0xC009,
    TlsEcdheEcdsaWithAes256CbcSha        	= 0xC00A,
    TlsEcdhRsaWithNullSha                  	= 0xC00B,
    TlsEcdhRsaWithRc4128Sha               	= 0xC00C,
    TlsEcdhRsaWith3DesEdeCbcSha          	= 0xC00D,
    TlsEcdhRsaWithAes128CbcSha           	= 0xC00E,
    TlsEcdhRsaWithAes256CbcSha           	= 0xC00F,
    TlsEcdheRsaWithNullSha                 	= 0xC010,
    TlsEcdheRsaWithRc4128Sha              	= 0xC011,
    TlsEcdheRsaWith3DesEdeCbcSha         	= 0xC012,
    TlsEcdheRsaWithAes128CbcSha          	= 0xC013,
    TlsEcdheRsaWithAes256CbcSha          	= 0xC014,
    TlsSrpShaRsaWith3DesEdeCbcSha       	= 0xC01B,
    TlsSrpShaDssWith3DesEdeCbcSha       	= 0xC01C,
    TlsSrpShaRsaWithAes128CbcSha        	= 0xC01E,
    TlsSrpShaDssWithAes128CbcSha        	= 0xC01F,
    TlsSrpShaRsaWithAes256CbcSha        	= 0xC021,
    TlsSrpShaDssWithAes256CbcSha        	= 0xC022,
    TlsEcdheEcdsaWithAes128CbcSha256     	= 0xC023,
    TlsEcdheEcdsaWithAes256CbcSha384     	= 0xC024,
    TlsEcdhEcdsaWithAes128CbcSha256      	= 0xC025,
    TlsEcdhEcdsaWithAes256CbcSha384      	= 0xC026,
    TlsEcdheRsaWithAes128CbcSha256       	= 0xC027,
    TlsEcdheRsaWithAes256CbcSha384       	= 0xC028,
    TlsEcdhRsaWithAes128CbcSha256        	= 0xC029,
    TlsEcdhRsaWithAes256CbcSha384        	= 0xC02A,
    TlsEcdheEcdsaWithAes128GcmSha256     	= 0xC02B,
    TlsEcdheEcdsaWithAes256GcmSha384     	= 0xC02C,
    TlsEcdhEcdsaWithAes128GcmSha256      	= 0xC02D,
    TlsEcdhEcdsaWithAes256GcmSha384      	= 0xC02E,
    TlsEcdheRsaWithAes128GcmSha256       	= 0xC02F,
    TlsEcdheRsaWithAes256GcmSha384       	= 0xC030,
    TlsEcdhRsaWithAes128GcmSha256        	= 0xC031,
    TlsEcdhRsaWithAes256GcmSha384        	= 0xC032,
    TlsDhDssWithAria128CbcSha256         	= 0xC03E,
    TlsDhDssWithAria256CbcSha384         	= 0xC03F,
    TlsDhRsaWithAria128CbcSha256         	= 0xC040,
    TlsDhRsaWithAria256CbcSha384         	= 0xC041,
    TlsDheDssWithAria128CbcSha256        	= 0xC042,
    TlsDheDssWithAria256CbcSha384        	= 0xC043,
    TlsDheRsaWithAria128CbcSha256        	= 0xC044,
    TlsDheRsaWithAria256CbcSha384        	= 0xC045,
    TlsEcdheEcdsaWithAria128CbcSha256    	= 0xC048,
    TlsEcdheEcdsaWithAria256CbcSha384    	= 0xC049,
    TlsEcdhEcdsaWithAria128CbcSha256     	= 0xC04A,
    TlsEcdhEcdsaWithAria256CbcSha384     	= 0xC04B,
    TlsEcdheRsaWithAria128CbcSha256      	= 0xC04C,
    TlsEcdheRsaWithAria256CbcSha384      	= 0xC04D,
    TlsEcdhRsaWithAria128CbcSha256       	= 0xC04E,
    TlsEcdhRsaWithAria256CbcSha384       	= 0xC04F,
    TlsDheRsaWithAria128GcmSha256        	= 0xC052,
    TlsDheRsaWithAria256GcmSha384        	= 0xC053,
    TlsDhRsaWithAria128GcmSha256         	= 0xC054,
    TlsDhRsaWithAria256GcmSha384         	= 0xC055,
    TlsDheDssWithAria128GcmSha256        	= 0xC056,
    TlsDheDssWithAria256GcmSha384        	= 0xC057,
    TlsDhDssWithAria128GcmSha256         	= 0xC058,
    TlsDhDssWithAria256GcmSha384         	= 0xC059,
    TlsEcdheEcdsaWithAria128GcmSha256    	= 0xC05C,
    TlsEcdheEcdsaWithAria256GcmSha384    	= 0xC05D,
    TlsEcdhEcdsaWithAria128GcmSha256     	= 0xC05E,
    TlsEcdhEcdsaWithAria256GcmSha384     	= 0xC05F,
    TlsEcdheRsaWithAria128GcmSha256      	= 0xC060,
    TlsEcdheRsaWithAria256GcmSha384      	= 0xC061,
    TlsEcdhRsaWithAria128GcmSha256       	= 0xC062,
    TlsEcdhRsaWithAria256GcmSha384       	= 0xC063,
    TlsEcdheEcdsaWithCamellia128CbcSha256	= 0xC072,
    TlsEcdheEcdsaWithCamellia256CbcSha384	= 0xC073,
    TlsEcdhEcdsaWithCamellia128CbcSha256 	= 0xC074,
    TlsEcdhEcdsaWithCamellia256CbcSha384 	= 0xC075,
    TlsEcdheRsaWithCamellia128CbcSha256  	= 0xC076,
    TlsEcdheRsaWithCamellia256CbcSha384  	= 0xC077,
    TlsEcdhRsaWithCamellia128CbcSha256   	= 0xC078,
    TlsEcdhRsaWithCamellia256CbcSha384   	= 0xC079,
    TlsDheRsaWithCamellia128GcmSha256    	= 0xC07C,
    TlsDheRsaWithCamellia256GcmSha384    	= 0xC07D,
    TlsDhRsaWithCamellia128GcmSha256     	= 0xC07E,
    TlsDhRsaWithCamellia256GcmSha384     	= 0xC07F,
    TlsDheDssWithCamellia128GcmSha256    	= 0xC080,
    TlsDheDssWithCamellia256GcmSha384    	= 0xC081,
    TlsDhDssWithCamellia128GcmSha256     	= 0xC082,
    TlsDhDssWithCamellia256GcmSha384     	= 0xC083,
    TlsEcdheEcdsaWithCamellia128GcmSha256	= 0xC086,
    TlsEcdheEcdsaWithCamellia256GcmSha384	= 0xC087,
    TlsEcdhEcdsaWithCamellia128GcmSha256 	= 0xC088,
    TlsEcdhEcdsaWithCamellia256GcmSha384 	= 0xC089,
    TlsEcdheRsaWithCamellia128GcmSha256  	= 0xC08A,
    TlsEcdheRsaWithCamellia256GcmSha384  	= 0xC08B,
    TlsEcdhRsaWithCamellia128GcmSha256   	= 0xC08C,
    TlsEcdhRsaWithCamellia256GcmSha384   	= 0xC08D,
    TlsDheRsaWithAes128Ccm                	= 0xC09E,
    TlsDheRsaWithAes256Ccm                	= 0xC09F,
    TlsDheRsaWithAes128Ccm8              	= 0xC0A2,
    TlsDheRsaWithAes256Ccm8              	= 0xC0A3,
    TlsEcdheEcdsaWithAes128Ccm            	= 0xC0AC,
    TlsEcdheEcdsaWithAes256Ccm            	= 0xC0AD,
    TlsEcdheEcdsaWithAes128Ccm8          	= 0xC0AE,
    TlsEcdheEcdsaWithAes256Ccm8          	= 0xC0AF,
    TlsEcdheRsaWithChacha20Poly1305Sha256 	= 0xCCA8,
    TlsEcdheEcdsaWithChacha20Poly1305Sha256	= 0xCCA9,
    TlsDheRsaWithChacha20Poly1305Sha256   	= 0xCCAA,
}
}

#[derive(Debug, PartialEq)]
pub struct ClientHelloFingerprint {
    pub record_tls_version: TlsVersion,
    pub ch_tls_version: TlsVersion,
    pub client_random: Vec<u8>,
    pub cipher_suites: Vec<u8>,
    pub compression_methods: Vec<u8>,

    pub extensions: Vec<u8>,
    pub named_groups: Vec<u8>,
    pub ec_point_fmt: Vec<u8>,
    pub sig_algs: Vec<u8>,
    pub alpn: Vec<u8>,

    // fields below are not part of final fingerprint
    pub sni: Vec<u8>,
    pub ticket_size: Option<i16>,

    pub key_share: Vec<u8>, // format [[u16, u16], [u16, u16], ...], where each element is [group, length]
    pub psk_key_exchange_modes: Vec<u8>,
    pub supported_versions: Vec<u8>,
    pub cert_compression_algs: Vec<u8>,
    pub record_size_limit : Vec<u8>,
}

pub type ClientHelloParseResult = Result<ClientHelloFingerprint, ParseError>;

impl ClientHelloFingerprint {
    pub fn from_try(a: &[u8]) -> ClientHelloParseResult {
        if a.len() < 42 {
            return Err(ParseError::ShortBuffer);
        }

        let record_type = a[0];
        if TlsRecordType::from_u8(record_type) != Some(TlsRecordType::Handshake) {
            return Err(ParseError::NotAHandshake);
        }

        let record_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[1], a[2])) {
            Some(tls_version) => tls_version,
            None => return Err(ParseError::UnknownRecordTLSVersion),
        };

        let record_length = u8_to_u16_be(a[3], a[4]);
        if usize::from_u16(record_length).unwrap() > a.len() - 5 {
            return Err(ParseError::ShortOuterRecord);
        }

        if TlsHandshakeType::from_u8(a[5]) != Some(TlsHandshakeType::ClientHello) {
            return Err(ParseError::NotAClientHello);
        }

        let ch_length = u8_to_u32_be(0, a[6], a[7], a[8]);
        if ch_length != record_length as u32 - 4 {
            return Err(ParseError::InnerOuterRecordLenContradict);
        }

        let ch_tls_version = match TlsVersion::from_u16(u8_to_u16_be(a[9], a[10])) {
            Some(tls_version) => tls_version,
            None => return Err(ParseError::UnknownChTLSVersion),
        };

        // 32 bytes of client random

        let mut offset: usize = 11;
        let c_random = tls_parser::ungrease_u8(&a[offset..offset+32]);
        offset += 32;

        let session_id_len = a[offset] as usize;
        offset += session_id_len + 1;
        if offset + 2 > a.len() {
            return Err(ParseError::SessionIDLenExceedBuf);
        }

        let cipher_suites_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + cipher_suites_len + 1 > a.len() || cipher_suites_len % 2 == 1 {
            return Err(ParseError::CiphersuiteLenMisparse);
        }

        let cipher_suites = tls_parser::ungrease_u8(&a[offset..offset + cipher_suites_len]);
        offset += cipher_suites_len;

        let compression_len = a[offset] as usize;
        offset += 1;
        if offset + compression_len + 2 > a.len() {
            return Err(ParseError::CompressionLenExceedBuf);
        }

        let compression_methods = a[offset..offset + compression_len].to_vec();
        offset += compression_len;

        let extensions_len = u8_to_u16_be(a[offset], a[offset + 1]) as usize;
        offset += 2;
        if offset + extensions_len > a.len() {
            return Err(ParseError::ExtensionsLenExceedBuf);
        }

        let mut ch = ClientHelloFingerprint {
            record_tls_version: record_tls_version,
            ch_tls_version: ch_tls_version,
            client_random: c_random,
            cipher_suites: cipher_suites,
            compression_methods: compression_methods,
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

        let ch_end = offset + extensions_len;
        while offset < ch_end {
            if offset > ch_end - 4 {
                return Err(ParseError::ShortExtensionHeader);
            }
            let ext_len = u8_to_u16_be(a[offset + 2], a[offset + 3]) as usize;
            if offset + ext_len > ch_end {
                return Err(ParseError::ExtensionLenExceedBuf);
            }
            ch.process_extension(&a[offset..offset + 2], &a[offset + 4..offset + 4 + ext_len])?;
            offset = match (offset + 4).checked_add(ext_len) {
                Some(i) => i,
                None => return Err(ParseError::ExtensionLenExceedBuf),
            };
        }
        Ok(ch)
    }

    fn process_extension(&mut self, ext_id_u8: &[u8], ext_data: &[u8]) -> Result<(), ParseError> {
        let ext_id = u8_to_u16_be(ext_id_u8[0], ext_id_u8[1]);
        match TlsExtension::from_u16(ext_id) {
            // we copy whole ext_data, including all the redundant lengths
            Some(TlsExtension::SupportedCurves) => {
                self.named_groups = tls_parser::ungrease_u8(ext_data);
            }
            Some(TlsExtension::SupportedPoints) => {
                self.ec_point_fmt = ext_data.to_vec();
            }
            Some(TlsExtension::SignatureAlgorithms) => {
                self.sig_algs = ext_data.to_vec();
            }
            Some(TlsExtension::ServerName) => {
                self.sni = ext_data.to_vec();
            }
            Some(TlsExtension::SessionTicket) => {
                if ext_data.len() <= i16::max_value() as usize {
                    self.ticket_size = Some(ext_data.len() as i16)
                }
            }
            Some(TlsExtension::ALPN) => {
                /* TODO Could be greasy
   ALPN identifiers beginning with
   the prefix "ignore/".  This corresponds to the seven-octet prefix:
   0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65, 0x2f.
                */
                self.alpn = ext_data.to_vec();
            }
            Some(TlsExtension::KeyShare) => {
                // key share goes [[group, size, key_itself], [group, size, key_itself], ...]
                // we want [[group, size], [group, size], ...]
                let key_share_data = ext_data.to_vec();
                if key_share_data.len() < 2 {
                    return Err(ParseError::KeyShareExtShort);
                }
                let key_share_inner_len = u8_to_u16_be(key_share_data[0], key_share_data[1]) as usize;
                let key_share_inner_data = match key_share_data.get(2 .. key_share_data.len()) {
                    Some(data) => data,
                    None => return Err(ParseError::KeyShareExtShort),
                };
                if key_share_inner_len != key_share_inner_data.len() {
                    return Err(ParseError::KeyShareExtLenMisparse);
                }
                self.key_share = tls_parser::parse_key_share(key_share_inner_data)?;
            }
            Some(TlsExtension::PskKeyExchangeModes) => {
                if ext_data.len() < 1 {
                    return Err(ParseError::PskKeyExchangeModesExtShort);
                }
                let psk_modes_inner_len = ext_data[0] as usize;
                if psk_modes_inner_len != ext_data.len() - 1 {
                    return Err(ParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.psk_key_exchange_modes = tls_parser::ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::SupportedVersions) => {
                if ext_data.len() < 1 {
                    return Err(ParseError::SupportedVersionsExtLenMisparse);
                }
                let versions_inner_len = ext_data[0] as usize;
                if versions_inner_len != ext_data.len() - 1 {
                    return Err(ParseError::PskKeyExchangeModesExtLenMisparse);
                }

                self.supported_versions = tls_parser::ungrease_u8(&ext_data[1 .. ]);
            }
            Some(TlsExtension::CertificateCompressionAlgorithms) => {
                self.cert_compression_algs = ext_data.to_vec();
            }
            Some(TlsExtension::RecordSizeLimit) => {
                self.record_size_limit = ext_data.to_vec();
            }
            _ => {}
        };

        self.extensions.append(&mut tls_parser::ungrease_u8(ext_id_u8));
        Ok(())
    }

    pub fn get_fingerprint(&self) -> u64 {
        //let mut s = DefaultHasher::new(); // This is SipHasher13, nobody uses this...
        //let mut s = SipHasher24::new_with_keys(0, 0);
        // Fuck Rust's deprecated "holier than thou" bullshit attitude
        // We'll use Sha1 instead...

        let mut hasher = Sha1::new();
        let versions = (self.record_tls_version as u32) << 16 | (self.ch_tls_version as u32);
        hash_u32(&mut hasher, versions);


        hash_u32(&mut hasher, self.cipher_suites.len() as u32);
        hasher.input(&self.cipher_suites);

        hash_u32(&mut hasher, self.compression_methods.len() as u32);
        hasher.input(&self.compression_methods);

        hash_u32(&mut hasher, self.extensions.len() as u32);
        hasher.input(&self.extensions);

        hash_u32(&mut hasher, self.named_groups.len() as u32);
        hasher.input(&self.named_groups);

        hash_u32(&mut hasher, self.ec_point_fmt.len() as u32);
        hasher.input(&self.ec_point_fmt);

        hash_u32(&mut hasher, self.sig_algs.len() as u32);
        hasher.input(&self.sig_algs);

        hash_u32(&mut hasher, self.alpn.len() as u32);
        hasher.input(&self.alpn);

        hash_u32(&mut hasher, self.key_share.len() as u32);
        hasher.input(&self.key_share);

        hash_u32(&mut hasher, self.psk_key_exchange_modes.len() as u32);
        hasher.input(&self.psk_key_exchange_modes);

        hash_u32(&mut hasher, self.supported_versions.len() as u32);
        hasher.input(&self.supported_versions);

        hash_u32(&mut hasher, self.cert_compression_algs.len() as u32);
        hasher.input(&self.cert_compression_algs);

        hash_u32(&mut hasher, self.record_size_limit.len() as u32);
        hasher.input(&self.record_size_limit);

        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }
}

impl fmt::Display for ClientHelloFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "record: {:?} ch: {:?} random: {:02x?} ciphers: {:X} compression: {:X} \
        extensions: {:X} curves: {:X} ec_fmt: {:X} sig_algs: {:X} alpn: {:X} sni: {}",
               self.record_tls_version, self.ch_tls_version, self.client_random.as_slice(),
               vec_u8_to_vec_u16_be(&self.cipher_suites).as_slice().as_hex(),
               &self.compression_methods.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.extensions).as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.named_groups).as_slice().as_hex(),
               self.ec_point_fmt.as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.sig_algs).as_slice().as_hex(),
               self.alpn.as_slice().as_hex(),
               String::from_utf8_lossy(self.sni.clone().as_slice()),
        )
    }
}

#[derive(Debug, PartialEq, Default)]
pub struct ServerHelloFingerprint {
    pub record_tls_version: TlsVersion,
    pub sh_tls_version: TlsVersion,
    pub server_random: Vec<u8>,
    pub cipher_suite: CipherSuite,
    pub compression_method: u8,

    pub extensions: Vec<u8>,
    pub elliptic_curves: Vec<u8>,
    pub ec_point_fmt: Vec<u8>,
    pub alpn: Vec<u8>,
}

impl ServerHelloFingerprint {
    // NOT UNGREASED
    pub fn process_extension(&mut self, ext_id_u8: &[u8], ext_data: &[u8]) {
        let ext_id = u8_to_u16_be(ext_id_u8[0], ext_id_u8[1]);
        match TlsExtension::from_u16(ext_id) {
            // we copy whole ext_data, including all the redundant lengths
            Some(TlsExtension::SupportedCurves) => {
                self.set_elliptic_curves( ext_data.to_vec());
            }
            Some(TlsExtension::SupportedPoints) => {
                self.set_ec_point_fmt(ext_data.to_vec());
            }
            Some(TlsExtension::ALPN) => {
                self.set_alpn(ext_data.to_vec());
            }
            _ => {}
        };

        self.append_extensions(&mut tls_parser::ungrease_u8(ext_id_u8));
    }

    pub fn get_fingerprint(&self) -> u64 {
        let mut hasher = Sha1::new();

        let versions = (self.get_record_tls_version().unwrap_or_else(|| TlsVersion::NONE) as u32) << 16 | (self.get_sh_tls_version().unwrap_or_else(|| TlsVersion::NONE) as u32);
        hash_u32(&mut hasher, versions);

        let suite_and_compr = (self.get_cipher_suite().unwrap_or_else(|| CipherSuite::TlsNullWithNullNull) as u32) << 16 | (self.get_compression_method().unwrap_or_else(|| 0) as u32);
        // 8 bytes are left empty, that's fine
        hash_u32(&mut hasher, suite_and_compr as u32);

        match self.get_extensions() {
            Some(ex) => {
                hash_u32(&mut hasher, ex.len() as u32);
                hasher.input(&ex);
            }
            None => {}
        }

        match self.get_elliptic_curves() {
            Some(ec) => {
                hash_u32(&mut hasher, ec.len() as u32);
                hasher.input(&ec);
            }
            None => {}
        }

        match self.get_ec_point_fmt() {
            Some(ecpf) => {
                hash_u32(&mut hasher, ecpf.len() as u32);
                hasher.input(&ecpf);
            }
            None => {}
        }

        match self.get_alpn() {
            Some(alpn) => {
                hash_u32(&mut hasher, alpn.len() as u32);
                hasher.input(&alpn);
            }
            None => {}
        }

        let mut result = [0; 20];
        hasher.result(&mut result);
        BigEndian::read_u64(&result[0..8])
    }
}

pub struct ServerKeyExchange {
    pub server_params: Vec<u8>,
    pub signature: Option<Vec<u8>>, // dh_Anon has no signature
}

pub trait ServerHelloAccessors {
    fn set_record_tls_version(&mut self, TlsVersion);
    fn get_record_tls_version(&self) -> Option<TlsVersion>;

    fn set_sh_tls_version(&mut self, TlsVersion);
    fn get_sh_tls_version(&self) -> Option<TlsVersion>;

    fn set_server_random(&mut self, Vec<u8>);
    fn get_server_random(&self) -> Option<&Vec<u8>>;

    fn set_cipher_suite(&mut self, CipherSuite);
    fn get_cipher_suite(&self) -> Option<CipherSuite>;

    fn set_compression_method(&mut self, u8);
    fn get_compression_method(&self) -> Option<u8>;

    fn set_extensions(&mut self, Vec<u8>);
    fn get_extensions(&self) -> Option<&Vec<u8>>;
    fn append_extensions(&mut self, &mut Vec<u8>);

    fn set_elliptic_curves(&mut self, Vec<u8>);
    fn get_elliptic_curves(&self) -> Option<&Vec<u8>>;

    fn set_ec_point_fmt(&mut self, Vec<u8>);
    fn get_ec_point_fmt(&self) -> Option<&Vec<u8>>;

    fn set_alpn(&mut self, Vec<u8>);
    fn get_alpn(&self) -> Option<&Vec<u8>>;
}

pub struct ServerReturn {
    pub server_hello: Option<ServerHelloFingerprint>,
    pub cert: Option<openssl::x509::X509>,
    pub server_key_exchange: Option<ServerKeyExchange>,
}

impl ServerHelloAccessors for ServerHelloFingerprint { 
    fn set_record_tls_version(&mut self, t: TlsVersion) {
        self.record_tls_version = t;
    }

    fn get_record_tls_version(&self) -> Option<TlsVersion> {
        Some(self.record_tls_version)
    }

    fn set_sh_tls_version(&mut self, t: TlsVersion) {
        self.sh_tls_version = t;
    }

    fn get_sh_tls_version(&self) -> Option<TlsVersion> {
        Some(self.sh_tls_version)
    }

    fn set_server_random(&mut self, v:Vec<u8>) {
        self.server_random = v;
    }

    fn get_server_random(&self) -> Option<&Vec<u8>> {
        Some(&self.server_random)
    }

    fn set_cipher_suite(&mut self, cs: CipherSuite) {
        self.cipher_suite = cs;
    }

    fn get_cipher_suite(&self) -> Option<CipherSuite> {
        Some(self.cipher_suite)
    }

    fn set_compression_method(&mut self, cm: u8) {
        self.compression_method = cm;
    }

    fn get_compression_method(&self) -> Option<u8> {
        Some(self.compression_method)
    }

    fn set_extensions(&mut self, ex: Vec<u8>) {
        self.extensions = ex;
    }

    fn get_extensions(&self) -> Option<&Vec<u8>> {
        Some(&self.extensions)
    }

    fn append_extensions(&mut self, v: &mut Vec<u8>) {
        self.extensions.append(v);
    }

    fn set_elliptic_curves(&mut self, ec: Vec<u8>) {
        self.elliptic_curves = ec;
    }

    fn get_elliptic_curves(&self) -> Option<&Vec<u8>> {
        Some(&self.elliptic_curves)
    }

    fn set_ec_point_fmt(&mut self, ecpf: Vec<u8>) {
        self.ec_point_fmt = ecpf;
    }

    fn get_ec_point_fmt(&self) -> Option<&Vec<u8>> {
        Some(&self.ec_point_fmt)
    }

    fn set_alpn(&mut self, alpn: Vec<u8>) {
        self.alpn = alpn;
    }

    fn get_alpn(&self) -> Option<&Vec<u8>> {
        Some(&self.alpn)
    }
}

impl ServerHelloAccessors for ServerReturn {
    fn set_record_tls_version(&mut self, t: TlsVersion) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.record_tls_version = t;
            }
            _ => {}
        }
    }

    fn get_record_tls_version(&self) -> Option<TlsVersion> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.record_tls_version)}
            None => {None}
        }
    }

    fn set_sh_tls_version(&mut self, t: TlsVersion) {
        match self.server_hello {
            Some(ref mut sh) => {sh.sh_tls_version = t;}
            _ => {}
        }
    }

    fn get_sh_tls_version(&self) -> Option<TlsVersion> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.sh_tls_version)}
            None => {None}
        }
    }

    fn set_server_random(&mut self, v:Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.server_random = v;
            }
            _ => {}
        }
    }

    fn get_server_random(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.server_random)}
            None => {None}
        }
    }

    fn set_cipher_suite(&mut self, cs: CipherSuite) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.cipher_suite = cs;
            }
            _ => {}
        }
    }

    fn get_cipher_suite(&self) -> Option<CipherSuite> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.cipher_suite)}
            None => {None}
        }
    }

    fn set_compression_method(&mut self, cm: u8) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.compression_method = cm;
            }
            _ => {}
        }
    }

    fn get_compression_method(&self) -> Option<u8> {
        match self.server_hello {
            Some(ref sh) => {Some(sh.compression_method)}
            None => {None}
        }
    }

    fn set_extensions(&mut self, ex: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.extensions = ex;
            }
            _ => {}
        }
    }

    fn get_extensions(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.extensions)}
            None => {None}
        }
    }

    fn append_extensions(&mut self, v: &mut Vec<u8>) {
        match self.server_hello{
            Some(ref mut sh) => {
                sh.extensions.append(v);
            }
            _ => {}
        }
    }

    fn set_elliptic_curves(&mut self, ec: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.elliptic_curves = ec;
            }
            _ => {}
        }
    }

    fn get_elliptic_curves(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.elliptic_curves)}
            None => {None}
        }
    }

    fn set_ec_point_fmt(&mut self, ecpf: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.ec_point_fmt = ecpf;
            }
            _ => {}
        }
    }

    fn get_ec_point_fmt(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.ec_point_fmt)}
            None => {None}
        }
    }

    fn set_alpn(&mut self, alpn: Vec<u8>) {
        match self.server_hello {
            Some(ref mut sh) => {
                sh.alpn = alpn;
            }
            _ => {}
        }
    }

    fn get_alpn(&self) -> Option<&Vec<u8>> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh.alpn)}
            None => {None}
        }
    }
}

pub type ServerParseResult = Result<ServerReturn, ParseError>;
pub type ServerHelloParseResult = Result<ServerHelloFingerprint, ParseError>;
pub type ServerCertificateParseResult = Result<X509, ParseError>;
pub type ServerKeyExchangeParseResult = Result<ServerKeyExchange, ParseError>;

impl ServerReturn {
    pub fn get_server_hello(&self) -> Option<&ServerHelloFingerprint> {
        match self.server_hello {
            Some(ref sh) => {Some(&sh)}
            None => {None}
        }
    }

    pub fn get_certificate(&self) -> Option<&openssl::x509::X509> {
        match self.cert {
            Some(ref cert) => {Some(&cert)}
            None => {None}
        }
    }

    pub fn get_server_key_exchange(&self) -> Option<&ServerKeyExchange> {
        match self.server_key_exchange {
            Some(ref ske) => {Some(&ske)}
            None => {None}
        }
    }



}

impl fmt::Display for ServerHelloFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "record: {:?} sh: {:?} random: {:02x?} cipher: {:X} compression: {:X} \
        extensions: {:X} curves: {:X} ec_fmt: {:X} alpn: {:X}",
               self.record_tls_version, self.sh_tls_version, self.server_random.as_slice(),
               &self.cipher_suite,
               &self.compression_method,
               vec_u8_to_vec_u16_be(&self.extensions).as_slice().as_hex(),
               vec_u8_to_vec_u16_be(&self.elliptic_curves).as_slice().as_hex(),
               self.ec_point_fmt.as_slice().as_hex(),
               self.alpn.as_slice().as_hex(),
        )
    }
}

impl fmt::Display for ServerReturn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.get_server_hello() {
            Some(ref sh) => {write!(f, "{}", sh)}
            None => {write!(f, "No server Hello")}
        }
    }
}

impl fmt::Display for ServerKeyExchange {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ret_string = String::new();
        ret_string.push_str("params: 0x");

        for i in 0..self.server_params.len() {
            if i == 10 {
                ret_string.push_str("...");
                break;
            }
            ret_string.push_str(&format!(" {:02x}", self.server_params[i]));
        }

        match self.signature {
            Some(ref sig) => {
                let mut sig_string = String::new();
                sig_string.push_str("signature: 0x");
                for i in 0..sig.len() {
                    if i == 10 {
                        sig_string.push_str("...");
                        break;
                    }
                    sig_string.push_str(&format!(" {:02x}", sig[i]));
                }

                write!(f, "{}, {}", ret_string, sig_string)
            }
            None => {write!(f, "{}, no signature", ret_string)}
        }
    }
}