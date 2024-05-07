package main

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	Handle *pcap.Handle
	Source *gopacket.PacketSource
}

func NewPacket(iface string) *Packet {
	handle, err := pcap.OpenLive(iface, 1024, false, -1*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	return &Packet{
		Handle: handle,
		Source: gopacket.NewPacketSource(handle, handle.LinkType()),
	}
}

type SendParams struct {
	SrcMac    net.HardwareAddr
	DstMac    net.HardwareAddr
	Payload   []byte
	Code      layers.PPPoECode
	SessionId uint16
	Protocol  layers.EthernetType
	Length    uint16
}

func (p *Packet) Send(params *SendParams) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{}
	err := gopacket.SerializeLayers(buffer, options,
		&layers.Ethernet{
			SrcMAC:       params.SrcMac,
			DstMAC:       params.DstMac,
			EthernetType: params.Protocol,
		},
		&layers.PPPoE{
			Version:   uint8(1),
			Type:      uint8(1),
			Code:      params.Code,
			SessionId: params.SessionId,
			Length:    params.Length,
		},
		gopacket.Payload(params.Payload),
	)
	if err != nil {
		log.Fatal(err)
	}

	_ = p.Handle.WritePacketData(buffer.Bytes())

}

func (p *Packet) Receive() chan gopacket.Packet {
	return p.Source.Packets()
}
