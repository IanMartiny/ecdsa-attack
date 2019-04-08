package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile string
	handle   *pcap.Handle
	err      error
)

func main() {
	if len(os.Args) < 2 {
		panic("Need path to pcap file as first argument")
	}

	pcapFile = os.Args[1]
	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := getPackets(packetSource.Packets())

	clientRandom, serverRandom := findRandoms(packets)
	// fmt.Printf("clientRandom: ")
	// printSliceInHex(clientRandom)
	// fmt.Printf("serverRandom: ")
	// printSliceInHex(serverRandom)
	// now find the signature key from the certificate
	serverIP := getServerIP(packets)
	// fmt.Printf("serverIP: %s\n", serverIP)
	sigKey := getSigKey(packets, serverIP)
	rsaKey, ok := sigKey.(*rsa.PublicKey)
	if !ok {
		panic("couldn't parse sigKey as rsa key")
	}
	// fmt.Printf("signature key: ")
	// fmt.Printf("%v\n", rsaKey)
	pubKey, signature := getServerKeyAndSignature(packets, serverIP)
	// fmt.Printf("pubKey: ")
	// printSliceInHex(pubKey)
	// fmt.Printf("signature: ")
	// printSliceInHex(signature)
	data := append(clientRandom, serverRandom...)
	data = append(data, pubKey...)
	hashed := sha256.Sum256(data)

	err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		panic("invalid signature")
	}
	fmt.Printf("valid signature\n")
}

func getServerKeyAndSignature(packets []gopacket.Packet, serverIP string) ([]byte, []byte) {
	// step 1: find starting place of serverKeyExchange
	startInd, offset := findServerKeyExchangePacket(packets, serverIP)
	// fmt.Printf("packet with serverKeyExchange: %d, offset in packet: %d\n", startInd+1, offset)
	// fmt.Printf("packets[i].ApplicationLayer().Payload[offset:offset+10]: ")
	// printSliceInHex(packets[startInd].ApplicationLayer().Payload()[offset : offset+10])

	// step 2: get all of serverKeyExchange
	TCPServerKeyPayload := packets[startInd].ApplicationLayer().Payload()[offset+6:]
	serverKeyLen := sliceToUint(TCPServerKeyPayload[:3])
	// fmt.Printf("serverKeyLen: %d\n", serverKeyLen)
	TCPServerKeyPayload = TCPServerKeyPayload[3:] // 1 extra bytes cut off after the length has been read

	if serverKeyLen < uint(len(TCPServerKeyPayload)) {
		TCPServerKeyPayload = TCPServerKeyPayload[:serverKeyLen]
	} else if serverKeyLen > uint(len(TCPServerKeyPayload)) { // serverKey finishes in another packet
		lenNeeded := serverKeyLen - uint(len(TCPServerKeyPayload))
		// fmt.Printf("lenNeeded: %d\n", lenNeeded)
		for _, packet := range packets[startInd+1:] {
			// check whether packet is from server
			if t := packet.Layer(layers.LayerTypeIPv4); t != nil {
				ip, _ := t.(*layers.IPv4)
				if ip.SrcIP.String() != serverIP {
					continue
				}
			} else {
				continue
			}

			// only look at packets that contain an application layer
			if packet.ApplicationLayer() == nil {
				continue
			}
			payload := packet.ApplicationLayer().Payload()
			var appendLen int
			if lenNeeded > uint(len(payload)) {
				appendLen = len(payload)
			} else {
				appendLen = int(lenNeeded)
			}
			TCPServerKeyPayload = append(TCPServerKeyPayload, packet.ApplicationLayer().Payload()[:appendLen]...)
			lenNeeded -= uint(appendLen)

			if lenNeeded == 0 {
				break
			}
		}

	}

	// step 3: get necessary bytes
	// fmt.Printf("serverKeyPayload: ")
	// printSliceInHex(TCPServerKeyPayload[:10])
	keyLen := TCPServerKeyPayload[3]
	sigLen := sliceToUint(TCPServerKeyPayload[keyLen+6 : keyLen+8])
	// fmt.Printf("sigLen: %d\n", sigLen)

	return TCPServerKeyPayload[:4+keyLen], TCPServerKeyPayload[keyLen+8 : uint(keyLen)+8+sigLen]
}

func getServerIP(packets []gopacket.Packet) string {
	var s string
	for _, packet := range packets {
		if !isTLSPacket(packet) {
			continue
		}
		payload := packet.ApplicationLayer().Payload()
		if payload[5] != 0x02 {
			continue
		}
		ip, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)

		s = ip.SrcIP.String()
		break
	}

	return s
}

func sliceToUint(s []byte) uint {
	mult := len(s) - 1
	var res uint
	for _, b := range s {
		res |= uint(b) << uint(8*mult)
		mult--
	}

	return res
}

func getSigKey(packets []gopacket.Packet, serverIP string) interface{} {
	// step 1: find where certificate begins:
	startInd, offset := findCertificatePacket(packets, serverIP)
	// fmt.Printf("certificate starts in packet %d\n", startInd)

	// step 2: get all of the certificate payload
	TCPCertPayload := packets[startInd].ApplicationLayer().Payload()[offset+12:] // +12 to get to the lowest level (server) certificate
	certLen := sliceToUint(TCPCertPayload[:3])
	TCPCertPayload = TCPCertPayload[3:] // 3 extra bytes cut off after the length has been read

	// fmt.Printf("certLen: %d\n", certLen)

	if certLen < uint(len(TCPCertPayload)) {
		TCPCertPayload = TCPCertPayload[:certLen]
	} else if certLen > uint(len(TCPCertPayload)) { // certificate finishes in another packet
		lenNeeded := certLen - uint(len(TCPCertPayload))
		for _, packet := range packets[startInd+1:] {
			// check whether packet is from server
			if t := packet.Layer(layers.LayerTypeIPv4); t != nil {
				ip, _ := t.(*layers.IPv4)
				if ip.SrcIP.String() != serverIP {
					continue
				}
			} else {
				continue
			}

			// only look at packets that contain an application layer
			if packet.ApplicationLayer() == nil {
				continue
			}
			payload := packet.ApplicationLayer().Payload()
			var appendLen int
			if lenNeeded > uint(len(payload)) {
				appendLen = len(payload)
			} else {
				appendLen = int(lenNeeded)
			}
			TCPCertPayload = append(TCPCertPayload, packet.ApplicationLayer().Payload()[:appendLen]...)
			lenNeeded -= uint(appendLen)

			if lenNeeded == 0 {
				break
			}
		}

	}

	// Step 3: get the certificate into something useful
	cert, err := x509.ParseCertificate(TCPCertPayload)
	if err != nil {
		panic("Couldn't parse TCPCertPayload in to x509 certificate")
	}

	// return cert.RawSubjectPublicKeyInfo
	// return cert.PublicKey
	// fmt.Printf("type of key: %T\n", cert.PublicKey)
	// rsaKey, err := x509.ParsePKCS1PublicKey(cert.RawSubjectPublicKeyInfo)
	// if err != nil {
	// 	panic("couldn't decode raw subject public key info into rsa key")
	// }

	return cert.PublicKey
}

func findServerKeyExchangePacket(packets []gopacket.Packet, serverIP string) (int, uint) {
	var packetNum int
	var overflow uint
	for i, packet := range packets {
		// only look at packets from the server
		if t := packet.Layer(layers.LayerTypeIPv4); t != nil {
			ip, _ := t.(*layers.IPv4)
			if ip.SrcIP.String() != serverIP {
				continue
			}
		} else {
			continue
		}

		// only look at packets that contain an application layer
		if packet.ApplicationLayer() == nil {
			continue
		}

		// fmt.Printf("packet %d\n", i+1)
		payload := packet.ApplicationLayer().Payload()
		// the following are true, unless it is an overflow from a previous packet.
		// payload[0] will be one of the content type of the TLS packet
		// payload[1:3] will be the TLS version
		// payload[3:5] will be the length of the TLS record (could be multiple packets, or less than the full packet)
		// payload[5] is the Handshake type IF payload[0] == 22
		// thus we can check for multiple TLS records in a single packet or across multiple packets (likely what will happen with certificate)
		// here we check if the packet has the beginning of the certificate
		// check is complicated, if first byte (after overflow) is 20, 21, 22, 23, or 255 then it is (probably) a TLS packet and we can continue looking for the public
		// signature key, if not look for the tlsRecordLength and see if the next record is in this packet, repeat.
		// if record extends to next packet we need to loop to next packet from the same person with a payload and repeat
		// var certPayload []byte
		var keepOverflow bool
		for !keepOverflow && !(payload[overflow+0] == 0x16 && payload[overflow+5] == 0x0c) { // test for beginning of certificate
			tlsRecordLength := sliceToUint(payload[overflow+3 : overflow+5])
			// fmt.Printf("len(payload): %d, overflow: %d\n", len(payload), overflow)
			// fmt.Printf("contentType: 0x%02x, handshakeType: 0x%02x, recordLength: %d\n", payload[overflow+0], payload[overflow+5], tlsRecordLength)
			overflow += tlsRecordLength + 5
			if overflow > uint(len(payload)) {
				overflow -= uint(len(payload))
				keepOverflow = true
			}
		}

		// here we've either found the beginning of the certificate OR we've reached the end of the TCP packet, one last check
		if keepOverflow { // if this is set then the TLS record flows into the next packet and it needs to be checked at an offset
			continue
		} else if overflow == uint(len(payload)) { // if keepOverflow is not set AND overflow is the end of the payload, then the TLS record does not overflow and overflow must be set to 0
			overflow = 0
			continue
		}
		// if we've reached here keepOverflow is not set and we've not reached the end of the packet, so it must be that we've found the certificate
		packetNum = i
		break
	}

	return packetNum, overflow
}

func findCertificatePacket(packets []gopacket.Packet, serverIP string) (int, uint) {
	var packetNum int
	var overflow uint
	for i, packet := range packets {
		// only look at packets from the server
		if t := packet.Layer(layers.LayerTypeIPv4); t != nil {
			ip, _ := t.(*layers.IPv4)
			if ip.SrcIP.String() != serverIP {
				continue
			}
		} else {
			continue
		}

		// only look at packets that contain an application layer
		if packet.ApplicationLayer() == nil {
			continue
		}

		// fmt.Printf("packet %d\n", i+1)
		payload := packet.ApplicationLayer().Payload()
		// the following are true, unless it is an overflow from a previous packet.
		// payload[0] will be one of the content type of the TLS packet
		// payload[1:3] will be the TLS version
		// payload[3:5] will be the length of the TLS record (could be multiple packets, or less than the full packet)
		// payload[5] is the Handshake type IF payload[0] == 22
		// thus we can check for multiple TLS records in a single packet or across multiple packets (likely what will happen with certificate)
		// here we check if the packet has the beginning of the certificate
		// check is complicated, if first byte (after overflow) is 20, 21, 22, 23, or 255 then it is (probably) a TLS packet and we can continue looking for the public
		// signature key, if not look for the tlsRecordLength and see if the next record is in this packet, repeat.
		// if record extends to next packet we need to loop to next packet from the same person with a payload and repeat
		// var certPayload []byte
		var keepOverflow bool
		for !keepOverflow && !(payload[overflow+0] == 0x16 && payload[overflow+5] == 0x0b) { // test for beginning of certificate
			tlsRecordLength := sliceToUint(payload[overflow+3 : overflow+5])
			// fmt.Printf("contentType: 0x%02x, handshakeType: 0x%02x\n", payload[overflow+0], payload[overflow+5])
			overflow += tlsRecordLength + 5
			if overflow > uint(len(payload)) {
				overflow -= uint(len(payload))
				keepOverflow = true
			}
		}

		// here we've either found the beginning of the certificate OR we've reached the end of the TCP packet, one last check
		if keepOverflow { // if this is set then the TLS record flows into the next packet and it needs to be checked at an offset
			continue
		} else if overflow == uint(len(payload)) { // if keepOverflow is not set AND overflow is the end of the payload, then the TLS record does not overflow and overflow must be set to 0
			overflow = 0
			continue
		}
		// if we've reached here keepOverflow is not set and we've not reached the end of the packet, so it must be that we've found the certificate
		// fmt.Printf("found certificate\n")
		packetNum = i
		break
	}

	return packetNum, overflow
}

func getPackets(packets chan gopacket.Packet) []gopacket.Packet {
	var ret []gopacket.Packet
	for packet := range packets {
		ret = append(ret, packet)
	}

	return ret
}

func printSliceInHex(s []byte) {
	for _, v := range s {
		fmt.Printf("%02x ", v)
	}
	fmt.Printf("\n")
}

// Finds the client and server randoms from TLS packets (assumes that client/server hellos are at the beginning of TCP packet)
func findRandoms(packets []gopacket.Packet) ([]byte, []byte) {
	var randoms [][]byte
	for _, packet := range packets {
		if isTLSPacket(packet) {
			payload := packet.ApplicationLayer().Payload()
			// Assumes that client and server hellos will be the beginning of packet
			// check that it is a TLS hand shake message and then whether it is a client or server hello
			if payload[5] == 0x01 || payload[5] == 0x02 {
				randoms = append(randoms, findRandom(payload[5:]))
			}
		}
	}

	return randoms[0], randoms[1]
}

// Finds the client/server random from a payload of a packet that has already been tessted to ensure it is a TLS packet
func findRandom(payload []byte) []byte {
	var ret []byte
	if payload[0] != 0x01 && payload[0] != 0x02 {
		fmt.Printf("wrong type of payload, needs to be client or Server hello\n")
		fmt.Printf("first byte must be 0x01 or 0x02, got: %02x\n", payload[0])
		return ret
	}
	// fmt.Printf("packet is a client/server hello packet\n")
	// helloLength := (uint(payload[1]) << 16) | (uint(payload[2]) << 8) | uint(payload[3])
	helloLength := sliceToUint(payload[1:4])
	// fmt.Printf("hello length: %d\n", helloLength)
	// ensure helloLength is less than packetLength
	if helloLength > uint(len(payload[4:])) {
		panic("hello spans multiple packets")
	}
	ret = payload[6:38]

	return ret
}

// Tests whether a given packet is a TLS packet by checking for an Application layer who's first byte is one of the
// content-type bytes of TLS packets
func isTLSPacket(packet gopacket.Packet) bool {
	// slightly flawed idea, doesn't consider that TLS packets can spread out between multiple TCP packets
	// only checks whether packet's payload is the beginning of a TLS packet
	tlsLayer := packet.ApplicationLayer()

	if tlsLayer != nil {
		payload := tlsLayer.Payload()
		switch payload[0] {
		case 20, 21, 22, 23, 255:
			return true
		default:
			return false
		}
	} else {
		return false
	}
}
