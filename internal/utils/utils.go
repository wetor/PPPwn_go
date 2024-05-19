package utils

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket/pcap"
)

func P8(val uint8) []byte {
	buf := make([]byte, 1)
	buf[0] = val
	return buf
}

func P16(val uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, val)
	return buf
}

func P16be(val uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return buf
}

func P32(val uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, val)
	return buf
}

func P32be(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return buf
}

func P64(val uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	return buf
}

func P64be(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	return buf
}

func ToBytes(val uint64, length int, byteOrder binary.ByteOrder) []byte {
	bytes := make([]byte, 8)
	byteOrder.PutUint64(bytes, val)
	return bytes[:length]
}

func SplitBytes(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}

	return chunks
}

func ShowInterfaces() error {
	allInterfaces, err := pcap.FindAllDevs()
	if err != nil {
		return err
	}

	for _, item := range allInterfaces {
		fmt.Printf("Name: \"%s\", Description: \"%s\"\n", item.Name, item.Description)
	}
	return nil
}

// IPv4UDPChecksum 计算IPv4 UDP包的校验和
func IPv4UDPChecksum(srcIP, dstIP []byte, protocol uint8, udpHeader []byte) uint16 {
	// Pseudo header
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP)
	copy(pseudoHeader[4:8], dstIP)
	pseudoHeader[9] = protocol
	udpLength := len(udpHeader)
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(udpLength))

	// Combine pseudo header and UDP header
	data := append(pseudoHeader, udpHeader...)

	// Calculate checksum
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		if i+1 >= len(data) {
			sum += uint32(data[i]) << 8
		} else {
			sum += uint32(data[i])<<8 | uint32(data[i+1])
		}

	}

	// Add carry
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}

	// Take the one's complement
	checksum := uint16(^sum)
	return checksum
}
