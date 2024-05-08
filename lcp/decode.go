package lcp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	LayerTypeLCP  = gopacket.RegisterLayerType(152, gopacket.LayerTypeMetadata{Name: "LCP", Decoder: gopacket.DecodeFunc(decodeLCP)})
	LayerTypeIPCP = gopacket.RegisterLayerType(153, gopacket.LayerTypeMetadata{Name: "IPCP", Decoder: gopacket.DecodeFunc(decodeLCP)})
)

func init() {
	layers.PPPTypeMetadata[ProtoLCP] = layers.EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLCP), Name: "LCP"}
	layers.PPPTypeMetadata[ProtoIPCP] = layers.EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLCP), Name: "IPCP"}
}

func decodeLCP(data []byte, p gopacket.PacketBuilder) error {
	pkt := &Pkt{}
	err := pkt.Parse(data)
	pkt.BaseLayer = layers.BaseLayer{Contents: data[:4], Payload: pkt.Payload}
	if err != nil {
		return err
	}
	p.AddLayer(pkt)
	return p.NextDecoder(gopacket.DecodeFunc(decodeLCP))
}
