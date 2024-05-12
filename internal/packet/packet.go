package packet

import (
	"log"
	"net"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	lcp2 "github.com/wetor/PPPwn_go/internal/lcp"
	pppoe2 "github.com/wetor/PPPwn_go/internal/pppoe"
)

type Packet struct {
	Handle *pcap.Handle
	Source *gopacket.PacketSource
}

func NewPacket(iface, bpfFilyer string) *Packet {
	handle, err := pcap.OpenLive(iface, 2048, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetBPFFilter(bpfFilyer)
	if err != nil {
		log.Fatal(err)
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.DecodeOptions.NoCopy = true
	source.DecodeOptions.Lazy = true
	source.DecodeOptions.DecodeStreamsAsDatagrams = true
	return &Packet{
		Handle: handle,
		Source: source,
	}
}

type SendParams struct {
	FixLengths, ComputeChecksums bool
	Layers                       []gopacket.SerializableLayer
}

func (p *Packet) Send(params *SendParams) error {
	data, err := p.ToBytes(params)
	if err != nil {
		return nil
	}
	return p.Handle.WritePacketData(data)
}

func (p *Packet) ToBytes(params *SendParams) ([]byte, error) {
	buffer := gopacket.NewSerializeBuffer()
	options := gopacket.SerializeOptions{
		FixLengths:       params.FixLengths,
		ComputeChecksums: params.ComputeChecksums,
	}
	err := gopacket.SerializeLayers(buffer, options, params.Layers...)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

type SendLCPParams struct {
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   layers.EthernetType
	SessionID      uint16
	LCP            *lcp2.Pkt
}

func (p *Packet) SendLCP(params *SendLCPParams) error {
	return p.Send(&SendParams{
		FixLengths:       true,
		ComputeChecksums: false,
		Layers: []gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC:       params.SrcMAC,
				DstMAC:       params.DstMAC,
				EthernetType: params.EthernetType,
			},
			&pppoe2.Pkt{
				SessionID: params.SessionID,
			},
			&layers.PPP{
				PPPType: params.LCP.Proto,
			},
			params.LCP,
		},
	})
}

type SendPPPoEParams struct {
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   layers.EthernetType
	PPPoE          *pppoe2.Pkt
}

func (p *Packet) SendPPPoE(params *SendPPPoEParams) error {
	return p.Send(&SendParams{
		FixLengths:       true,
		ComputeChecksums: false,
		Layers: []gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC:       params.SrcMAC,
				DstMAC:       params.DstMAC,
				EthernetType: params.EthernetType,
			},
			params.PPPoE,
		},
	})
}

type SendICMPv6Params struct {
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   layers.EthernetType
	SrcIP          net.IP
	DstIP          net.IP
	HopLimit       uint8
	ICMPv6Type     uint8
	Layers         []gopacket.SerializableLayer
}

func (p *Packet) SendICMPv6(params *SendICMPv6Params) error {
	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      params.SrcIP,
		DstIP:      params.DstIP,
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   params.HopLimit,
	}
	icmpv6 := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(params.ICMPv6Type, 0),
	}
	err := icmpv6.SetNetworkLayerForChecksum(ipv6)
	if err != nil {
		return err
	}
	layer := []gopacket.SerializableLayer{
		&layers.Ethernet{
			SrcMAC:       params.SrcMAC,
			DstMAC:       params.DstMAC,
			EthernetType: params.EthernetType,
		},
		ipv6,
		icmpv6,
	}
	layer = append(layer, params.Layers...)
	return p.Send(&SendParams{
		FixLengths:       true,
		ComputeChecksums: true,
		Layers:           layer,
	})
}

type LayerValue struct {
	Layer gopacket.LayerType
	Value any
	Check func(val any) bool
}

type ReceiveParams struct {
	Layer []*LayerValue
}

func (p *Packet) Receive(params *ReceiveParams) {
	for packet := range p.Source.Packets() {
		checkNum := len(params.Layer)
		for _, layerValue := range params.Layer {
			if layer := packet.Layer(layerValue.Layer); layer != nil {
				if layerValue.Value != nil {
					reflect.ValueOf(layerValue.Value).Elem().Set(reflect.ValueOf(layer))
				}
				if layerValue.Check(layer) {
					checkNum--
				}
			}
		}
		if checkNum == 0 {
			break
		}
	}
}

func (p *Packet) ReceivePPPoE(etype layers.EthernetType, code layers.PPPoECode) (eth *layers.Ethernet, pkt *pppoe2.Pkt) {
	p.Receive(&ReceiveParams{
		Layer: []*LayerValue{
			{
				Layer: layers.LayerTypeEthernet,
				Check: func(val any) bool {
					if packet, ok := val.(*layers.Ethernet); ok {
						if packet.EthernetType == etype {
							eth = packet
							return true
						}
					}
					return false
				},
			},
			{
				Layer: pppoe2.LayerTypePPPoE,
				Check: func(val any) bool {
					if packet, ok := val.(*pppoe2.Pkt); ok {
						if packet.Code == code {
							pkt = packet
							return true
						}
					}
					return false
				},
			},
		},
	})
	return
}

func (p *Packet) ReceiveLCP(ptype layers.PPPType, code lcp2.MsgCode) (ppp *layers.PPP, pkt *lcp2.Pkt) {
	p.Receive(&ReceiveParams{
		Layer: []*LayerValue{
			{
				Layer: layers.LayerTypePPP,
				Check: func(val any) bool {
					if packet, ok := val.(*layers.PPP); ok {
						if packet.PPPType == ptype {
							ppp = packet
							return true
						}
					}
					return false
				},
			},
			{
				Layer: lcp2.LayerTypeLCP,
				Check: func(val any) bool {
					if packet, ok := val.(*lcp2.Pkt); ok {
						if packet.Code == code {
							pkt = packet
							return true
						}
					}
					return false
				},
			},
		},
	})
	return
}

func (p *Packet) ReceiveEthPPPoELCP(ptype layers.PPPType, code lcp2.MsgCode) (eth *layers.Ethernet, poe *pppoe2.Pkt, ppp *layers.PPP, pkt *lcp2.Pkt) {
	p.Receive(&ReceiveParams{
		Layer: []*LayerValue{
			{
				Layer: layers.LayerTypeEthernet,
				Check: func(val any) bool {
					if packet, ok := val.(*layers.Ethernet); ok {
						eth = packet
						return true
					}
					return false
				},
			},
			{
				Layer: pppoe2.LayerTypePPPoE,
				Check: func(val any) bool {
					if packet, ok := val.(*pppoe2.Pkt); ok {
						poe = packet
						return true
					}
					return false
				},
			},
			{
				Layer: layers.LayerTypePPP,
				Check: func(val any) bool {
					if packet, ok := val.(*layers.PPP); ok {
						if packet.PPPType == ptype {
							ppp = packet
							return true
						}
					}
					return false
				},
			},
			{
				Layer: lcp2.LayerTypeLCP,
				Check: func(val any) bool {
					if packet, ok := val.(*lcp2.Pkt); ok {
						if packet.Code == code {
							pkt = packet
							return true
						}
					}
					return false
				},
			},
		},
	})
	return
}
