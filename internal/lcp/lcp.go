// Package lcp implements PPP, LCP, IPCP and IPv6CP
package lcp

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

// LayerNotifyHandler is the handler function to handle Layer event (tlu/tld/tls/tlf as defined in RFC1661)
type LayerNotifyHandler func(ctx context.Context, evt LayerNotifyEvent)

const (
	// DefaultRestartCounter is the default LCP restart counter value
	DefaultRestartCounter = 3
	// DefaultRestartTimerDuration is the default restart timer
	DefaultRestartTimerDuration = 10 * time.Second
	// DefaultKeepAliveInterval is the default LCP keepalive interval to send
	DefaultKeepAliveInterval = 5 * time.Second
	// DefaultMRU is the default LCP MRU value
	DefaultMRU = 1500
	// DefaultAuthProto is the default auth protocol
	DefaultAuthProto = ProtoCHAP
	// DefaultMagicNum is the default LCP magic number
	DefaultMagicNum LCPOpMagicNum = 0
)

func newOwnDefaultOptions() (r Options) {
	defaultMRUOp := LCPOpMRU(DefaultMRU)
	magicNum := LCPOpMagicNum(rand.Uint32())

	r = Options{
		&defaultMRUOp,
		&magicNum,
		// &defaultAuthProto,
	}
	return
}

// OwnOptionRule is rule that used to handle own LCP options, user could provide implementation of this interface to get custom behavior
type OwnOptionRule interface {
	// HandlerConfRej is the handler function to handle received Conf-Reject
	HandlerConfRej(rcvd Options)
	// HandlerConfNAK is the handler function to handle received Conf-Nak
	HandlerConfNAK(rcvd Options)
	// GetOptions returns current own options
	GetOptions() Options
	// GetOption returns current option with type o
	GetOption(o uint8) Option
}

// DefaultOwnOptionRule is the default OwnOptionRule implementation;
// use NewDefaultOwnOptionRule() to create instance;
// using following options: MRU, AuthProto, MagicNumber with default value;
type DefaultOwnOptionRule struct {
	ownOptions Options
	mux        *sync.RWMutex
}

// NewDefaultOwnOptionRule returns a new DefaultOwnOptionRule
func NewDefaultOwnOptionRule() *DefaultOwnOptionRule {
	return &DefaultOwnOptionRule{
		mux:        new(sync.RWMutex),
		ownOptions: newOwnDefaultOptions(),
	}
}

// GetOptions implements OwnOptionRule
func (own *DefaultOwnOptionRule) GetOptions() Options {
	own.mux.RLock()
	defer own.mux.RUnlock()
	return own.ownOptions
}

// GetOption implements OwnOptionRule
func (own *DefaultOwnOptionRule) GetOption(o uint8) Option {
	own.mux.RLock()
	defer own.mux.RUnlock()
	for _, op := range own.ownOptions {
		if op.Type() == o {
			return op
		}
	}
	return nil
}

// HandlerConfRej implements OwnOptionRule, remove all options listed in conf-rej
func (own *DefaultOwnOptionRule) HandlerConfRej(rcvd Options) {
	own.mux.Lock()
	defer own.mux.Unlock()
	for _, op := range rcvd {
		own.ownOptions.Del(op.Type())
	}
}

// HandlerConfNAK implements OwnOptionRule, accept all options listed in conf-nak
func (own *DefaultOwnOptionRule) HandlerConfNAK(rcvd Options) {
	own.mux.Lock()
	defer own.mux.Unlock()
	own.ownOptions.Replace(rcvd)
}

// PeerOptionRule is rule that use for handle received config-req from peer
type PeerOptionRule interface {
	// HandlerConfReq is the handler function to handle received Conf-Request.
	// if a recived option needs to be naked or rejected, include it in returned nak/reject LCPOptions
	HandlerConfReq(rcvd Options) (nak, reject Options)
	// GetOptions return current peer's options
	GetOptions() Options
}

// DefaultPeerOptionRule is the default PeerOptionRule implementation.
type DefaultPeerOptionRule struct {
	// AuthOp is the required Auth Protocol Option (PAP or CHAP)
	AuthOp         *LCPOpAuthProto
	currentOptions Options
}

// NewDefaultPeerOptionRule create a new DefaultPeerOptionRule instance with specified authp (
func NewDefaultPeerOptionRule(authp layers.PPPType) (*DefaultPeerOptionRule, error) {
	var op *LCPOpAuthProto
	switch authp {
	case ProtoCHAP:
		op = NewCHAPAuthOp()
	case ProtoPAP:
		op = NewPAPAuthOp()
	default:
		return nil, fmt.Errorf("unsupported auth protocol: %v", authp)
	}
	r := new(DefaultPeerOptionRule)
	r.AuthOp = op
	return r, nil
}

// GetOptions implements PeerOptionRule.
func (rule *DefaultPeerOptionRule) GetOptions() Options {
	return rule.currentOptions
}

// HandlerConfReq implements PeerOptionRule, if config-request include an auth-proto option that is different from required one, it will be NAKed;
// Option in conf-req other than auth-proto, magic number and MRU will be rejected.
func (rule *DefaultPeerOptionRule) HandlerConfReq(rcvd Options) (nak, reject Options) {
	rule.currentOptions = rcvd
	for _, o := range rcvd {
		switch LCPOptionType(o.Type()) {
		case OpTypeAuthenticationProtocol:
			if !o.Equal(rule.AuthOp) {
				nak = append(nak, rule.AuthOp)
			}
		case OpTypeMagicNumber, OpTypeMaximumReceiveUnit:
		default:
			reject = append(reject, o)
		}
	}
	return
}

func getCallerName() (fname, callername string, linenum int) {
	fpcs := make([]uintptr, 1)
	// Skip 2 levels to get the caller
	n := runtime.Callers(3, fpcs)
	if n == 0 {
		return
	}

	caller := runtime.FuncForPC(fpcs[0] - 1)
	if caller == nil {
		return
	}
	fname, linenum = caller.FileLine(fpcs[0] - 1)
	callername = caller.Name()
	return

}

// Options is a slice of LCPOption
type Options []Option

// Get return all options with type t
func (options Options) Get(t uint8) (r Options) {
	for _, o := range options {
		if o.Type() == t {
			r = append(r, o)
		}
	}
	return
}

// GetFirst return 1st option with type t
func (options Options) GetFirst(t uint8) Option {
	for _, o := range options {
		if o.Type() == t {
			return o
		}
	}
	return nil
}

// Del removes all options with type t
func (options *Options) Del(t uint8) {
	for i, o := range *options {
		if o.Type() == t {
			*options = append((*options)[:i], (*options)[i+1:]...)
		}
	}
}

// Append append newoptions
func (options *Options) Append(newoptions Options) {
	*options = append(*options, newoptions...)
}

// Replace removes all options with all options in newoptions, and append newoptions
func (options *Options) Replace(newoptions Options) {
	for _, o := range newoptions {
		options.Del(o.Type())
	}
	options.Append(newoptions)
}
