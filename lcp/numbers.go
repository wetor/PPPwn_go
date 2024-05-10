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
	ProtoNone   layers.PPPType = 0
	ProtoPAD    layers.PPPType = 0x1
	ProtoIPv4   layers.PPPType = 0x21
	ProtoIPv6   layers.PPPType = 0x57
	ProtoLCP    layers.PPPType = 0xc021
	ProtoPAP    layers.PPPType = 0xc023
	ProtoCHAP   layers.PPPType = 0xc223
	ProtoEAP    layers.PPPType = 0xc227
	ProtoIPCP   layers.PPPType = 0x8021
	ProtoIPv6CP layers.PPPType = 0x8057
)

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
