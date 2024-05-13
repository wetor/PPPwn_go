package pppoe

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypePPPoE = gopacket.OverrideLayerType(26, gopacket.LayerTypeMetadata{Name: "PPPoE", Decoder: gopacket.DecodeFunc(decodePPPoE)})

func init() {
	layers.EthernetTypeMetadata[layers.EthernetTypePPPoEDiscovery] = layers.EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoEDiscovery", LayerType: LayerTypePPPoE}
	layers.EthernetTypeMetadata[layers.EthernetTypePPPoESession] = layers.EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoESession", LayerType: LayerTypePPPoE}
}

func decodePPPoE(data []byte, p gopacket.PacketBuilder) error {
	pppoe := &Pkt{}
	err := pppoe.Parse(data)
	if err != nil {
		return err
	}
	pppoe.BaseLayer = layers.BaseLayer{Contents: data[:6], Payload: pppoe.Payload}
	p.AddLayer(pppoe)
	return p.NextDecoder(pppoe.Code)
}
