package lcp

import (
	"fmt"
	"github.com/google/gopacket/layers"
)

// MsgCode is the LCP message Code
type MsgCode uint8

// LCP message codes
const (
	CodeConfigureRequest MsgCode = 1
	CodeConfigureAck     MsgCode = 2
	CodeConfigureNak     MsgCode = 3
	CodeConfigureReject  MsgCode = 4
	CodeTerminateRequest MsgCode = 5
	CodeTerminateAck     MsgCode = 6
	CodeCodeReject       MsgCode = 7
	CodeProtocolReject   MsgCode = 8
	CodeEchoRequest      MsgCode = 9
	CodeEchoReply        MsgCode = 10
	CodeDiscardRequest   MsgCode = 11
)

func (code MsgCode) String() string {
	switch code {
	case CodeConfigureRequest:
		return "ConfReq"
	case CodeConfigureAck:
		return "ConfACK"
	case CodeConfigureNak:
		return "ConfNak"
	case CodeConfigureReject:
		return "ConfReject"
	case CodeTerminateRequest:
		return "TermReq"
	case CodeTerminateAck:
		return "TermACK"
	case CodeCodeReject:
		return "CodeReject"
	case CodeProtocolReject:
		return "ProtoReject"
	case CodeEchoRequest:
		return "EchoReq"
	case CodeEchoReply:
		return "EchoReply"
	case CodeDiscardRequest:
		return "DiscardReq"

	}
	return "unknown"
}

// LCPOptionType is the LCP option type
type LCPOptionType uint8

// LCP option types
const (
	OpTypeMaximumReceiveUnit                LCPOptionType = 1
	OpTypeAuthenticationProtocol            LCPOptionType = 3
	OpTypeQualityProtocol                   LCPOptionType = 4
	OpTypeMagicNumber                       LCPOptionType = 5
	OpTypeProtocolFieldCompression          LCPOptionType = 7
	OpTypeAddressandControlFieldCompression LCPOptionType = 8
)

func (op LCPOptionType) String() string {
	switch op {
	case OpTypeMaximumReceiveUnit:
		return "MRU"
	case OpTypeAuthenticationProtocol:
		return "AuthProto"
	case OpTypeQualityProtocol:
		return "QualityProto"
	case OpTypeMagicNumber:
		return "MagicNum"
	case OpTypeProtocolFieldCompression:
		return "ProtoFieldComp"
	case OpTypeAddressandControlFieldCompression:
		return "AddContrlFieldComp"
	}
	return fmt.Sprintf("unknown (%d)", uint8(op))
}

// State is the the LCP protocl state
type State uint32

// LCP protocol state as defined in RFC1661
const (
	StateInitial State = iota
	StateStarting
	StateClosed
	StateStopped
	StateClosing
	StateStopping
	StateReqSent
	StateAckRcvd
	StateAckSent
	StateOpened
	StateEchoReqSent
)

func (s State) String() string {
	switch s {
	case StateInitial:
		return "Initial"
	case StateStarting:
		return "Starting"
	case StateClosed:
		return "Closed"
	case StateStopped:
		return "Stopped"
	case StateClosing:
		return "Closing"
	case StateStopping:
		return "Stopping"
	case StateReqSent:
		return "ReqSent"
	case StateAckRcvd:
		return "AckRcvd"
	case StateAckSent:
		return "AckSent"
	case StateOpened:
		return "Opened"
	case StateEchoReqSent:
		return "EchoReqSent"
	}
	return fmt.Sprintf("unknow (%d)", s)
}

// CHAPAuthAlg is the auth alg of CHAP
type CHAPAuthAlg uint8

// list of CHAP alg
const (
	AlgNone            CHAPAuthAlg = 0
	AlgCHAPwithMD5     CHAPAuthAlg = 5
	AlgSHA1            CHAPAuthAlg = 6
	AlgCHAPwithSHA256  CHAPAuthAlg = 7
	AlgCHAPwithSHA3256 CHAPAuthAlg = 8
	AlgMSCHAP          CHAPAuthAlg = 128
	AlgMSCHAP2         CHAPAuthAlg = 129
)

func (alg CHAPAuthAlg) String() string {
	switch alg {
	case AlgNone:
		return ""
	case AlgCHAPwithMD5:
		return "AlgCHAPwithMD5"
	case AlgSHA1:
		return "AlgSHA1"
	case AlgCHAPwithSHA256:
		return "AlgCHAPwithSHA256"
	case AlgCHAPwithSHA3256:
		return "AlgCHAPwithSHA3256"
	case AlgMSCHAP:
		return "AlgMSCHAP"
	case AlgMSCHAP2:
		return "AlgMSCHAP2"
	}
	return fmt.Sprintf("unknown (%x)", uint8(alg))
}

// LayerNotifyEvent is the tlu/tld/tls/tlf event defined in RFC1661
type LayerNotifyEvent uint8

// list of LayerNotifyEvent
const (
	LCPLayerNotifyUp LayerNotifyEvent = iota
	LCPLayerNotifyDown
	LCPLayerNotifyStarted
	LCPLayerNotifyFinished
)

func (n LayerNotifyEvent) String() string {
	switch n {
	case LCPLayerNotifyUp:
		return "up"
	case LCPLayerNotifyDown:
		return "down"
	case LCPLayerNotifyStarted:
		return "started"
	case LCPLayerNotifyFinished:
		return "finished"
	}
	return fmt.Sprintf("unknown (%d)", n)
}

// IPCPOptionType is the option type for IPCP
type IPCPOptionType uint8

// list of IPCP option type
const (
	OpIPAddresses                IPCPOptionType = 1
	OpIPCompressionProtocol      IPCPOptionType = 2
	OpIPAddress                  IPCPOptionType = 3
	OpMobileIPv4                 IPCPOptionType = 4
	OpPrimaryDNSServerAddress    IPCPOptionType = 129
	OpPrimaryNBNSServerAddress   IPCPOptionType = 130
	OpSecondaryDNSServerAddress  IPCPOptionType = 131
	OpSecondaryNBNSServerAddress IPCPOptionType = 132
)

func (o IPCPOptionType) String() string {
	switch o {
	case OpIPAddresses:
		return "IPAddresses"
	case OpIPCompressionProtocol:
		return "IPCompressionProtocol"
	case OpIPAddress:
		return "IPAddress"
	case OpMobileIPv4:
		return "MobileIPv4"
	case OpPrimaryDNSServerAddress:
		return "PrimaryDNSServerAddress"
	case OpPrimaryNBNSServerAddress:
		return "PrimaryNBNSServerAddress"
	case OpSecondaryDNSServerAddress:
		return "SecondaryDNSServerAddress"
	case OpSecondaryNBNSServerAddress:
		return "SecondaryNBNSServerAddress"
	}
	return fmt.Sprintf("unknown (%d)", o)
}

// layers.PPPType is the PPP protocol number

// list of PPP protocol number
const (
	ProtoNone                                        layers.PPPType = 0
	ProtoPAD                                         layers.PPPType = 0x1
	ProtoIPv4                                        layers.PPPType = 0x21
	ProtoIPv6                                        layers.PPPType = 0x57
	ProtoLCP                                         layers.PPPType = 0xc021
	ProtoPAP                                         layers.PPPType = 0xc023
	ProtoCHAP                                        layers.PPPType = 0xc223
	ProtoEAP                                         layers.PPPType = 0xc227
	ProtoIPCP                                        layers.PPPType = 0x8021
	ProtoIPv6CP                                      layers.PPPType = 0x8057
	ProtoROHCsmallCID                                layers.PPPType = 0x3
	ProtoROHClargeCID                                layers.PPPType = 0x5
	ProtoOSINetworkLayer                             layers.PPPType = 0x23
	ProtoXeroxNSIDP                                  layers.PPPType = 0x25
	ProtoDECnetPhaseIV                               layers.PPPType = 0x27
	ProtoAppletalk                                   layers.PPPType = 0x29
	ProtoNovellIPX                                   layers.PPPType = 0x002b
	ProtoVanJacobsonCompressedTCPIP                  layers.PPPType = 0x002d
	ProtoVanJacobsonUncompressedTCPIP                layers.PPPType = 0x002f
	ProtoBridgingPDU                                 layers.PPPType = 0x31
	ProtoStreamProtocol                              layers.PPPType = 0x33
	ProtoBanyanVines                                 layers.PPPType = 0x35
	ProtoUnassigned                                  layers.PPPType = 0x37
	ProtoAppleTalkEDDP                               layers.PPPType = 0x39
	ProtoAppleTalkSmartBuffered                      layers.PPPType = 0x003b
	ProtoMultiLink                                   layers.PPPType = 0x003d
	ProtoNETBIOSFraming                              layers.PPPType = 0x003f
	ProtoCiscoSystems                                layers.PPPType = 0x41
	ProtoAscomTimeplex                               layers.PPPType = 0x43
	ProtoFujitsuLinkBackupandLoadBalancing           layers.PPPType = 0x45
	ProtoDCARemoteLan                                layers.PPPType = 0x47
	ProtoSerialDataTransportProtocol                 layers.PPPType = 0x49
	ProtoSNAover802                                  layers.PPPType = 0x004b
	ProtoSNA                                         layers.PPPType = 0x004d
	ProtoIPv6HeaderCompression                       layers.PPPType = 0x004f
	ProtoKNXBridgingData                             layers.PPPType = 0x51
	ProtoEncryption                                  layers.PPPType = 0x53
	ProtoIndividualLinkEncryption                    layers.PPPType = 0x55
	ProtoPPPMuxing                                   layers.PPPType = 0x59
	ProtoVendorSpecificNetworkProtocol               layers.PPPType = 0x005b
	ProtoTRILLNetworkProtocol                        layers.PPPType = 0x005d
	ProtoRTPIPHCFullHeader                           layers.PPPType = 0x61
	ProtoRTPIPHCCompressedTCP                        layers.PPPType = 0x63
	ProtoRTPIPHCCompressedNonTCP                     layers.PPPType = 0x65
	ProtoRTPIPHCCompressedUDP8                       layers.PPPType = 0x67
	ProtoRTPIPHCCompressedRTP8                       layers.PPPType = 0x69
	ProtoStampedeBridging                            layers.PPPType = 0x006f
	ProtoMPPlus                                      layers.PPPType = 0x73
	ProtoNTCITSIPI                                   layers.PPPType = 0x00c1
	ProtoSinglelinkcompressioninmultilink            layers.PPPType = 0x00fb
	ProtoCompresseddatagram                          layers.PPPType = 0x00fd
	ProtoHelloPackets8021d                           layers.PPPType = 0x201
	ProtoIBMSourceRoutingBPDU                        layers.PPPType = 0x203
	ProtoDECLANBridge100SpanningTree                 layers.PPPType = 0x205
	ProtoCiscoDiscoveryProtocol                      layers.PPPType = 0x207
	ProtoNetcsTwinRouting                            layers.PPPType = 0x209
	ProtoSTPScheduledTransferProtocol                layers.PPPType = 0x020b
	ProtoEDPExtremeDiscoveryProtocol                 layers.PPPType = 0x020d
	ProtoOpticalSupervisoryChannelProtocol           layers.PPPType = 0x211
	ProtoOpticalSupervisoryChannelProtocolAlias      layers.PPPType = 0x213
	ProtoLuxcom                                      layers.PPPType = 0x231
	ProtoSigmaNetworkSystems                         layers.PPPType = 0x233
	ProtoAppleClientServerProtocol                   layers.PPPType = 0x235
	ProtoMPLSUnicast                                 layers.PPPType = 0x281
	ProtoMPLSMulticast                               layers.PPPType = 0x283
	ProtoIEEEp12844standarddatapackets               layers.PPPType = 0x285
	ProtoETSITETRANetworkProtocolType1               layers.PPPType = 0x287
	ProtoMultichannelFlowTreatmentProtocol           layers.PPPType = 0x289
	ProtoRTPIPHCCompressedTCPNoDelta                 layers.PPPType = 0x2063
	ProtoRTPIPHCContextState                         layers.PPPType = 0x2065
	ProtoRTPIPHCCompressedUDP16                      layers.PPPType = 0x2067
	ProtoRTPIPHCCompressedRTP16                      layers.PPPType = 0x2069
	ProtoCrayCommunicationsControlProtocol           layers.PPPType = 0x4001
	ProtoCDPDMobileNetworkRegistrationProtocol       layers.PPPType = 0x4003
	ProtoExpandacceleratorprotocol                   layers.PPPType = 0x4005
	ProtoODSICPNCP                                   layers.PPPType = 0x4007
	ProtoDOCSISDLL                                   layers.PPPType = 0x4009
	ProtoCetaceanNetworkDetectionProtocol            layers.PPPType = 0x400B
	ProtoStackerLZS                                  layers.PPPType = 0x4021
	ProtoRefTekProtocol                              layers.PPPType = 0x4023
	ProtoFibreChannel                                layers.PPPType = 0x4025
	ProtoOpenDOF                                     layers.PPPType = 0x4027
	ProtoVendorSpecificProtocol                      layers.PPPType = 0x405b
	ProtoTRILLLinkStateProtocol                      layers.PPPType = 0x405d
	ProtoOSINetworkLayerControlProtocol              layers.PPPType = 0x8023
	ProtoXeroxNSIDPControlProtocol                   layers.PPPType = 0x8025
	ProtoDECnetPhaseIVControlProtocol                layers.PPPType = 0x8027
	ProtoAppletalkControlProtocol                    layers.PPPType = 0x8029
	ProtoNovellIPXControlProtocol                    layers.PPPType = 0x802b
	ProtoBridgingNCP                                 layers.PPPType = 0x8031
	ProtoStreamProtocolControlProtocol               layers.PPPType = 0x8033
	ProtoBanyanVinesControlProtocol                  layers.PPPType = 0x8035
	ProtoMultiLinkControlProtocol                    layers.PPPType = 0x803d
	ProtoNETBIOSFramingControlProtocol               layers.PPPType = 0x803f
	ProtoCiscoSystemsControlProtocol                 layers.PPPType = 0x8041
	ProtoAscomTimeplexAlias                          layers.PPPType = 0x8043
	ProtoFujitsuLBLBControlProtocol                  layers.PPPType = 0x8045
	ProtoDCARemoteLanNetworkControlProtocol          layers.PPPType = 0x8047
	ProtoSerialDataControlProtocol                   layers.PPPType = 0x8049
	ProtoSNAover802Control                           layers.PPPType = 0x804b
	ProtoSNAControlProtocol                          layers.PPPType = 0x804d
	ProtoIP6HeaderCompressionControlProtocol         layers.PPPType = 0x804f
	ProtoKNXBridgingControlProtocol                  layers.PPPType = 0x8051
	ProtoEncryptionControlProtocol                   layers.PPPType = 0x8053
	ProtoIndividualLinkEncryptionControlProtocol     layers.PPPType = 0x8055
	ProtoPPPMuxingControlProtocol                    layers.PPPType = 0x8059
	ProtoVendorSpecificNetworkControlProtocol        layers.PPPType = 0x805b
	ProtoTRILLNetworkControlProtocol                 layers.PPPType = 0x805d
	ProtoStampedeBridgingControlProtocol             layers.PPPType = 0x806f
	ProtoMPPlusControlProtocol                       layers.PPPType = 0x8073
	ProtoNTCITSIPIControlProtocol                    layers.PPPType = 0x80c1
	Protosinglelinkcompressioninmultilinkcontrol     layers.PPPType = 0x80fb
	ProtoCompressionControlProtocol                  layers.PPPType = 0x80fd
	ProtoCiscoDiscoveryProtocolControl               layers.PPPType = 0x8207
	ProtoNetcsTwinRoutingAlias                       layers.PPPType = 0x8209
	ProtoSTPControlProtocol                          layers.PPPType = 0x820b
	ProtoEDPCPExtremeDiscoveryProtocolCtrlPrtcl      layers.PPPType = 0x820d
	ProtoAppleClientServerProtocolControl            layers.PPPType = 0x8235
	ProtoMPLSCP                                      layers.PPPType = 0x8281
	ProtoIEEEp12844standardProtocolControl           layers.PPPType = 0x8285
	ProtoETSITETRATNP1ControlProtocol                layers.PPPType = 0x8287
	ProtoMultichannelFlowTreatmentProtocolAlias      layers.PPPType = 0x8289
	ProtoLinkQualityReport                           layers.PPPType = 0xc025
	ProtoShivaPasswordAuthenticationProtocol         layers.PPPType = 0xc027
	ProtoCallBackControlProtocol                     layers.PPPType = 0xc029
	ProtoBACPBandwidthAllocationControlProtocolAlias layers.PPPType = 0xc02b
	ProtoBAP                                         layers.PPPType = 0xc02d
	ProtoVendorSpecificAuthenticationProtocol        layers.PPPType = 0xc05b
	ProtoContainerControlProtocol                    layers.PPPType = 0xc081
	ProtoRSAAuthenticationProtocol                   layers.PPPType = 0xc225
	ProtoMitsubishiSecurityInfoExchPtcl              layers.PPPType = 0xc229
	ProtoStampedeBridgingAuthorizationProtocol       layers.PPPType = 0xc26f
	ProtoProprietaryAuthenticationProtocol           layers.PPPType = 0xc281
	ProtoProprietaryAuthenticationProtocolAlias      layers.PPPType = 0xc283
	ProtoProprietaryNodeIDAuthenticationProtocol     layers.PPPType = 0xc481
)

// func (proto layers.PPPType) String() string {
// 	switch proto {
// 	case ProtoPAD:
// 		return "PADDING"
// 	case ProtoIPv4:
// 		return "IPv4"
// 	case ProtoIPv6:
// 		return "IPv6"
// 	case ProtoLCP:
// 		return "LCP"
// 	case ProtoPAP:
// 		return "PAP"
// 	case ProtoCHAP:
// 		return "CHAP"
// 	case ProtoEAP:
// 		return "EAP"
// 	case ProtoIPCP:
// 		return "IPCP"
// 	case ProtoIPv6CP:
// 		return "IPv6CP"
// 	case ProtoROHCsmallCID:
// 		return "ROHCsmallCID"
// 	case ProtoROHClargeCID:
// 		return "ROHClargeCID"
// 	case ProtoOSINetworkLayer:
// 		return "OSINetworkLayer"
// 	case ProtoXeroxNSIDP:
// 		return "XeroxNSIDP"
// 	case ProtoDECnetPhaseIV:
// 		return "DECnetPhaseIV"
// 	case ProtoAppletalk:
// 		return "Appletalk"
// 	case ProtoNovellIPX:
// 		return "NovellIPX"
// 	case ProtoVanJacobsonCompressedTCPIP:
// 		return "VanJacobsonCompressedTCPIP"
// 	case ProtoVanJacobsonUncompressedTCPIP:
// 		return "VanJacobsonUncompressedTCPIP"
// 	case ProtoBridgingPDU:
// 		return "BridgingPDU"
// 	case ProtoStreamProtocol:
// 		return "StreamProtocol"
// 	case ProtoBanyanVines:
// 		return "BanyanVines"
// 	case ProtoUnassigned:
// 		return "Unassigned"
// 	case ProtoAppleTalkEDDP:
// 		return "AppleTalkEDDP"
// 	case ProtoAppleTalkSmartBuffered:
// 		return "AppleTalkSmartBuffered"
// 	case ProtoMultiLink:
// 		return "MultiLink"
// 	case ProtoNETBIOSFraming:
// 		return "NETBIOSFraming"
// 	case ProtoCiscoSystems:
// 		return "CiscoSystems"
// 	case ProtoAscomTimeplex:
// 		return "AscomTimeplex"
// 	case ProtoFujitsuLinkBackupandLoadBalancing:
// 		return "FujitsuLinkBackupandLoadBalancing"
// 	case ProtoDCARemoteLan:
// 		return "DCARemoteLan"
// 	case ProtoSerialDataTransportProtocol:
// 		return "SerialDataTransportProtocol"
// 	case ProtoSNAover802:
// 		return "SNAover802"
// 	case ProtoSNA:
// 		return "SNA"
// 	case ProtoIPv6HeaderCompression:
// 		return "IPv6HeaderCompression"
// 	case ProtoKNXBridgingData:
// 		return "KNXBridgingData"
// 	case ProtoEncryption:
// 		return "Encryption"
// 	case ProtoIndividualLinkEncryption:
// 		return "IndividualLinkEncryption"
// 	case ProtoPPPMuxing:
// 		return "PPPMuxing"
// 	case ProtoVendorSpecificNetworkProtocol:
// 		return "VendorSpecificNetworkProtocol"
// 	case ProtoTRILLNetworkProtocol:
// 		return "TRILLNetworkProtocol"
// 	case ProtoRTPIPHCFullHeader:
// 		return "RTPIPHCFullHeader"
// 	case ProtoRTPIPHCCompressedTCP:
// 		return "RTPIPHCCompressedTCP"
// 	case ProtoRTPIPHCCompressedNonTCP:
// 		return "RTPIPHCCompressedNonTCP"
// 	case ProtoRTPIPHCCompressedUDP8:
// 		return "RTPIPHCCompressedUDP8"
// 	case ProtoRTPIPHCCompressedRTP8:
// 		return "RTPIPHCCompressedRTP8"
// 	case ProtoStampedeBridging:
// 		return "StampedeBridging"
// 	case ProtoMPPlus:
// 		return "MPPlus"
// 	case ProtoNTCITSIPI:
// 		return "NTCITSIPI"
// 	case ProtoSinglelinkcompressioninmultilink:
// 		return "Singlelinkcompressioninmultilink"
// 	case ProtoCompresseddatagram:
// 		return "Compresseddatagram"
// 	case ProtoHelloPackets8021d:
// 		return "HelloPackets8021d"
// 	case ProtoIBMSourceRoutingBPDU:
// 		return "IBMSourceRoutingBPDU"
// 	case ProtoDECLANBridge100SpanningTree:
// 		return "DECLANBridge100SpanningTree"
// 	case ProtoCiscoDiscoveryProtocol:
// 		return "CiscoDiscoveryProtocol"
// 	case ProtoNetcsTwinRouting:
// 		return "NetcsTwinRouting"
// 	case ProtoSTPScheduledTransferProtocol:
// 		return "STPScheduledTransferProtocol"
// 	case ProtoEDPExtremeDiscoveryProtocol:
// 		return "EDPExtremeDiscoveryProtocol"
// 	case ProtoOpticalSupervisoryChannelProtocol:
// 		return "OpticalSupervisoryChannelProtocol"
// 	case ProtoOpticalSupervisoryChannelProtocolAlias:
// 		return "OpticalSupervisoryChannelProtocolAlias"
// 	case ProtoLuxcom:
// 		return "Luxcom"
// 	case ProtoSigmaNetworkSystems:
// 		return "SigmaNetworkSystems"
// 	case ProtoAppleClientServerProtocol:
// 		return "AppleClientServerProtocol"
// 	case ProtoMPLSUnicast:
// 		return "MPLSUnicast"
// 	case ProtoMPLSMulticast:
// 		return "MPLSMulticast"
// 	case ProtoIEEEp12844standarddatapackets:
// 		return "IEEEp12844standarddatapackets"
// 	case ProtoETSITETRANetworkProtocolType1:
// 		return "ETSITETRANetworkProtocolType1"
// 	case ProtoMultichannelFlowTreatmentProtocol:
// 		return "MultichannelFlowTreatmentProtocol"
// 	case ProtoRTPIPHCCompressedTCPNoDelta:
// 		return "RTPIPHCCompressedTCPNoDelta"
// 	case ProtoRTPIPHCContextState:
// 		return "RTPIPHCContextState"
// 	case ProtoRTPIPHCCompressedUDP16:
// 		return "RTPIPHCCompressedUDP16"
// 	case ProtoRTPIPHCCompressedRTP16:
// 		return "RTPIPHCCompressedRTP16"
// 	case ProtoCrayCommunicationsControlProtocol:
// 		return "CrayCommunicationsControlProtocol"
// 	case ProtoCDPDMobileNetworkRegistrationProtocol:
// 		return "CDPDMobileNetworkRegistrationProtocol"
// 	case ProtoExpandacceleratorprotocol:
// 		return "Expandacceleratorprotocol"
// 	case ProtoODSICPNCP:
// 		return "ODSICPNCP"
// 	case ProtoDOCSISDLL:
// 		return "DOCSISDLL"
// 	case ProtoCetaceanNetworkDetectionProtocol:
// 		return "CetaceanNetworkDetectionProtocol"
// 	case ProtoStackerLZS:
// 		return "StackerLZS"
// 	case ProtoRefTekProtocol:
// 		return "RefTekProtocol"
// 	case ProtoFibreChannel:
// 		return "FibreChannel"
// 	case ProtoOpenDOF:
// 		return "OpenDOF"
// 	case ProtoVendorSpecificProtocol:
// 		return "VendorSpecificProtocol"
// 	case ProtoTRILLLinkStateProtocol:
// 		return "TRILLLinkStateProtocol"
// 	case ProtoOSINetworkLayerControlProtocol:
// 		return "OSINetworkLayerControlProtocol"
// 	case ProtoXeroxNSIDPControlProtocol:
// 		return "XeroxNSIDPControlProtocol"
// 	case ProtoDECnetPhaseIVControlProtocol:
// 		return "DECnetPhaseIVControlProtocol"
// 	case ProtoAppletalkControlProtocol:
// 		return "AppletalkControlProtocol"
// 	case ProtoNovellIPXControlProtocol:
// 		return "NovellIPXControlProtocol"
// 	case ProtoBridgingNCP:
// 		return "BridgingNCP"
// 	case ProtoStreamProtocolControlProtocol:
// 		return "StreamProtocolControlProtocol"
// 	case ProtoBanyanVinesControlProtocol:
// 		return "BanyanVinesControlProtocol"
// 	case ProtoMultiLinkControlProtocol:
// 		return "MultiLinkControlProtocol"
// 	case ProtoNETBIOSFramingControlProtocol:
// 		return "NETBIOSFramingControlProtocol"
// 	case ProtoCiscoSystemsControlProtocol:
// 		return "CiscoSystemsControlProtocol"
// 	case ProtoAscomTimeplexAlias:
// 		return "AscomTimeplexAlias"
// 	case ProtoFujitsuLBLBControlProtocol:
// 		return "FujitsuLBLBControlProtocol"
// 	case ProtoDCARemoteLanNetworkControlProtocol:
// 		return "DCARemoteLanNetworkControlProtocol"
// 	case ProtoSerialDataControlProtocol:
// 		return "SerialDataControlProtocol"
// 	case ProtoSNAover802Control:
// 		return "SNAover802Control"
// 	case ProtoSNAControlProtocol:
// 		return "SNAControlProtocol"
// 	case ProtoIP6HeaderCompressionControlProtocol:
// 		return "IP6HeaderCompressionControlProtocol"
// 	case ProtoKNXBridgingControlProtocol:
// 		return "KNXBridgingControlProtocol"
// 	case ProtoEncryptionControlProtocol:
// 		return "EncryptionControlProtocol"
// 	case ProtoIndividualLinkEncryptionControlProtocol:
// 		return "IndividualLinkEncryptionControlProtocol"
// 	case ProtoPPPMuxingControlProtocol:
// 		return "PPPMuxingControlProtocol"
// 	case ProtoVendorSpecificNetworkControlProtocol:
// 		return "VendorSpecificNetworkControlProtocol"
// 	case ProtoTRILLNetworkControlProtocol:
// 		return "TRILLNetworkControlProtocol"
// 	case ProtoStampedeBridgingControlProtocol:
// 		return "StampedeBridgingControlProtocol"
// 	case ProtoMPPlusControlProtocol:
// 		return "MPPlusControlProtocol"
// 	case ProtoNTCITSIPIControlProtocol:
// 		return "NTCITSIPIControlProtocol"
// 	case Protosinglelinkcompressioninmultilinkcontrol:
// 		return "singlelinkcompressioninmultilinkcontrol"
// 	case ProtoCompressionControlProtocol:
// 		return "CompressionControlProtocol"
// 	case ProtoCiscoDiscoveryProtocolControl:
// 		return "CiscoDiscoveryProtocolControl"
// 	case ProtoNetcsTwinRoutingAlias:
// 		return "NetcsTwinRoutingAlias"
// 	case ProtoSTPControlProtocol:
// 		return "STPControlProtocol"
// 	case ProtoEDPCPExtremeDiscoveryProtocolCtrlPrtcl:
// 		return "EDPCPExtremeDiscoveryProtocolCtrlPrtcl"
// 	case ProtoAppleClientServerProtocolControl:
// 		return "AppleClientServerProtocolControl"
// 	case ProtoMPLSCP:
// 		return "MPLSCP"
// 	case ProtoIEEEp12844standardProtocolControl:
// 		return "IEEEp12844standardProtocolControl"
// 	case ProtoETSITETRATNP1ControlProtocol:
// 		return "ETSITETRATNP1ControlProtocol"
// 	case ProtoMultichannelFlowTreatmentProtocolAlias:
// 		return "MultichannelFlowTreatmentProtocolAlias"
// 	case ProtoLinkQualityReport:
// 		return "LinkQualityReport"
// 	case ProtoShivaPasswordAuthenticationProtocol:
// 		return "ShivaPasswordAuthenticationProtocol"
// 	case ProtoCallBackControlProtocol:
// 		return "CallBackControlProtocol"
// 	case ProtoBACPBandwidthAllocationControlProtocolAlias:
// 		return "BACPBandwidthAllocationControlProtocolAlias"
// 	case ProtoBAP:
// 		return "BAP"
// 	case ProtoVendorSpecificAuthenticationProtocol:
// 		return "VendorSpecificAuthenticationProtocol"
// 	case ProtoContainerControlProtocol:
// 		return "ContainerControlProtocol"
// 	case ProtoRSAAuthenticationProtocol:
// 		return "RSAAuthenticationProtocol"
// 	case ProtoMitsubishiSecurityInfoExchPtcl:
// 		return "MitsubishiSecurityInfoExchPtcl"
// 	case ProtoStampedeBridgingAuthorizationProtocol:
// 		return "StampedeBridgingAuthorizationProtocol"
// 	case ProtoProprietaryAuthenticationProtocol:
// 		return "ProprietaryAuthenticationProtocol"
// 	case ProtoProprietaryAuthenticationProtocolAlias:
// 		return "ProprietaryAuthenticationProtocolAlias"
// 	case ProtoProprietaryNodeIDAuthenticationProtocol:
// 		return "ProprietaryNodeIDAuthenticationProtocol"
// 	}
// 	return fmt.Sprintf("unknown (%x)", uint16(proto))
// }

// IPCP6OptionType is the option type for IPv6CP
type IPCP6OptionType uint8

// list of IPv6CP option type
const (
	IP6CPOpIPv6CompressionProtocol IPCP6OptionType = 0x2
	IP6CPOpInterfaceIdentifier     IPCP6OptionType = 0x1
)

func (code IPCP6OptionType) String() string {
	switch code {

	case IP6CPOpIPv6CompressionProtocol:
		return "IPv6CompressionProtocol"

	case IP6CPOpInterfaceIdentifier:
		return "InterfaceIdentifier"

	}
	return fmt.Sprintf("unknown (%d)", code)
}
