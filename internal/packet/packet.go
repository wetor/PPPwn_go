package packet

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"reflect"
	"sync"

	"github.com/wetor/PPPwn_go/internal/errors"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/wetor/PPPwn_go/internal/lcp"
	"github.com/wetor/PPPwn_go/internal/logger"
	"github.com/wetor/PPPwn_go/internal/pppoe"
)

type Packet struct {
	Handle *pcap.Handle
	Source *gopacket.PacketSource
}

func NewPacket(iface, bpfFilyer string) *Packet {
	handle, err := pcap.OpenLive(iface, 2048, true, pcap.BlockForever)
	if err != nil {
		logger.Fatal(err)
	}
	err = handle.SetBPFFilter(bpfFilyer)
	if err != nil {
		logger.Fatal(err)
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	source.DecodeOptions.NoCopy = true
	source.DecodeOptions.Lazy = true
	source.DecodeOptions.DecodeStreamsAsDatagrams = true
	//source.DecodeOptions.SkipDecodeRecovery = true
	return &Packet{
		Handle: handle,
		Source: source,
	}
}

type SendParams struct {
	FixLengths, ComputeChecksums, Log bool
	Layers                            []gopacket.SerializableLayer
}

func (p *Packet) Send(params *SendParams) error {
	data, err := p.ToBytes(params)
	if err != nil {
		return err
	}
	if params.Log {
		logger.Debugf("Send \n-- SEND PACKET DATA (%d bytes) ------------------------------------\n%v", len(data), hex.Dump(data))
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
	LCP            *lcp.Pkt
}

func (p *Packet) SendLCP(params *SendLCPParams) error {
	return p.Send(&SendParams{
		Log:              true,
		FixLengths:       true,
		ComputeChecksums: false,
		Layers: []gopacket.SerializableLayer{
			&layers.Ethernet{
				SrcMAC:       params.SrcMAC,
				DstMAC:       params.DstMAC,
				EthernetType: params.EthernetType,
			},
			&pppoe.Pkt{
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
	PPPoE          *pppoe.Pkt
}

func (p *Packet) SendPPPoE(params *SendPPPoEParams) error {
	return p.Send(&SendParams{
		Log:              true,
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
	Ctx   context.Context
	Log   bool
	Layer []*LayerValue
}

func (p *Packet) Receive(params *ReceiveParams) (err error) {
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-params.Ctx.Done():
				err = errors.ReceiveTimeoutError
				return
			case packet := <-p.Source.Packets():
				checkNum := len(params.Layer)
				for _, layerValue := range params.Layer {
					if layer := packet.Layer(layerValue.Layer); layer != nil {
						if layerValue.Value != nil {
							reflect.ValueOf(layerValue.Value).Elem().Set(reflect.ValueOf(layer).Elem())
						}
						if layerValue.Check(layer) {
							checkNum--
						}
					}
				}
				if checkNum == 0 {
					if params.Log {
						logger.Debugf("Receive \n-- FULL PACKET DATA (%d bytes) ------------------------------------\n%v", len(packet.Data()), hex.Dump(packet.Data()))
					}
					err = nil
					return
				}
			}
		}
	}()
	wg.Wait()
	return
}

func (p *Packet) ReceivePPPoE(ctx context.Context, etype layers.EthernetType, code layers.PPPoECode, targetMac net.HardwareAddr) (eth *layers.Ethernet, pkt *pppoe.Pkt, err error) {
	err = p.Receive(&ReceiveParams{
		Ctx: ctx,
		Log: true,
		Layer: []*LayerValue{
			{
				Layer: layers.LayerTypeEthernet,
				Check: func(val any) bool {
					if packet, ok := val.(*layers.Ethernet); ok {
						if packet.EthernetType == etype {
							if targetMac != nil && bytes.Compare(targetMac, packet.SrcMAC) != 0 {
								return false
							}
							eth = packet
							return true
						}
					}
					return false
				},
			},
			{
				Layer: pppoe.LayerTypePPPoE,
				Check: func(val any) bool {
					if packet, ok := val.(*pppoe.Pkt); ok {
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

func (p *Packet) ReceiveLCP(ctx context.Context, ptype layers.PPPType, code lcp.MsgCode) (ppp *layers.PPP, pkt *lcp.Pkt, err error) {
	err = p.Receive(&ReceiveParams{
		Ctx: ctx,
		Log: true,
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
				Layer: lcp.LayerTypeLCP,
				Check: func(val any) bool {
					if packet, ok := val.(*lcp.Pkt); ok {
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

func (p *Packet) ReceiveICMPv6NS(ctx context.Context, log bool) (icmpv6 *layers.ICMPv6, ns *layers.ICMPv6NeighborSolicitation, err error) {
	err = p.Receive(&ReceiveParams{
		Ctx: ctx,
		Log: log,
		Layer: []*LayerValue{
			{
				Layer: layers.LayerTypeICMPv6,
				Check: func(val any) bool {
					if packet, ok := val.(*layers.ICMPv6); ok {
						icmpv6 = packet
						return true
					}
					return false
				},
			},
			{
				Layer: layers.LayerTypeICMPv6NeighborSolicitation,
				Check: func(val any) bool {
					if packet, ok := val.(*layers.ICMPv6NeighborSolicitation); ok {
						ns = packet
						return true
					}
					return false
				},
			},
		},
	})
	return
}

func (p *Packet) ReceiveEthPPPoELCP(ctx context.Context, ptype layers.PPPType, code lcp.MsgCode) (eth *layers.Ethernet, poe *pppoe.Pkt, ppp *layers.PPP, pkt *lcp.Pkt, err error) {
	err = p.Receive(&ReceiveParams{
		Ctx: ctx,
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
				Layer: pppoe.LayerTypePPPoE,
				Check: func(val any) bool {
					if packet, ok := val.(*pppoe.Pkt); ok {
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
				Layer: lcp.LayerTypeLCP,
				Check: func(val any) bool {
					if packet, ok := val.(*lcp.Pkt); ok {
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
