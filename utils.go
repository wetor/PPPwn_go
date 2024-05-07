package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func p8(val uint8) []byte {
	buf := make([]byte, 1)
	buf[0] = val
	return buf
}

func p16(val uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, val)
	return buf
}

func p16be(val uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, val)
	return buf
}

func p32(val uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, val)
	return buf
}

func p32be(val uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, val)
	return buf
}

func p64(val uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, val)
	return buf
}

func p64be(val uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, val)
	return buf
}

func toBytes(val uint64, length int, byteOrder binary.ByteOrder) []byte {
	bytes := make([]byte, 8)
	byteOrder.PutUint64(bytes, val)
	return bytes[:length]
}

func mac2str(val []byte) string {
	macBytes := make([]string, len(val))
	for i, b := range val {
		macBytes[i] = fmt.Sprintf("%02x", b)
	}
	mac := strings.Join(macBytes, ":")
	return mac
}

func str2mac(val string) []byte {
	strs := strings.Split(val, ":")
	macBytes := make([]byte, len(strs))
	for i, s := range strs {
		b, _ := strconv.ParseInt(s, 16, 16)
		macBytes[i] = byte(b)
	}
	return macBytes
}

func padiFindHostUniq(raw []byte) []byte {
	key := []byte{0x01, 0x03}
	nIdx := bytes.Index(raw, key)
	if nIdx == -1 {
		return nil
	}
	nLen := int(binary.BigEndian.Uint16(raw[nIdx+2 : nIdx+4]))
	return append(key, raw[nIdx+2:nIdx+4+nLen]...)
}
