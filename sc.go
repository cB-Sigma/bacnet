package bacnet

// BACnet Secure Connect (ASHRAE 135-2024 Annex AB): the BVLC-SC message
// encoding of AB.2, the common error checks of AB.3.1.5 and the VMAC and
// Device UUID of AB.1.5. The hub connector is scnode.go, the hub function
// schub.go and the TLS profile sctls.go.

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

// BVLC-SC functions (Table AB-1).
const (
	SCResult          = 0x00
	scEncapsulated    = 0x01
	SCAddrResolution  = 0x02
	scAddrResACK      = 0x03
	scAdvertisement   = 0x04
	scAdvSolicitation = 0x05
	SCConnectRequest  = 0x06
	SCConnectAccept   = 0x07
	SCDisconnectReq   = 0x08
	SCDisconnectACK   = 0x09
	SCHeartbeatReq    = 0x0a
	SCHeartbeatACK    = 0x0b
	scProprietary     = 0x0c
)

// Control flags (AB.2.2); bits 7..4 are reserved.
const (
	scFlagOrig     = 0x08
	scFlagDest     = 0x04
	scFlagDestOpts = 0x02
	scFlagDataOpts = 0x01
)

// Header marker bits (AB.2.3). Bit 6 is 'Must Understand' in destination
// options and 'Every Segment' in data options.
const (
	scOptMore  = 0x80
	scOptFlag6 = 0x40
	scOptData  = 0x20
	scOptType  = 0x1f
)

// Header option types (Table AB-3, AB.2.3.1).
const (
	SCOptSecurePath  = 1
	SCOptHello       = 2
	SCOptIdentity    = 3
	scOptHint        = 4
	scOptToken       = 5
	SCOptProprietary = 31
)

// Error class and the error codes (clause 21, BACnetErrorCode) of
// BACnet/SC.
const (
	ErrClassCommunication          = 7
	ErrCodeOptionalNotSupported    = 45
	errCodeParameterOutOfRange     = 80
	ErrCodeBVLCFunctionUnknown     = 143
	errCodeBVLCProprietaryUnknown  = 144
	errCodeHeaderEncodingError     = 145
	ErrCodeHeaderNotUnderstood     = 146
	errCodeMessageIncomplete       = 147
	errCodeNotABACnetSCHub         = 148
	errCodePayloadExpected         = 149
	errCodeUnexpectedData          = 150
	ErrCodeNodeDuplicateVMAC       = 151
	errCodeInconsistentParameters  = 7
	ErrCodeWebsocketSchemeNotSupp  = 166
	errCodeWebsocketClosedByPeer   = 169
	errCodeWebsocketEndpointLeaves = 170
	errCodeWebsocketProtocolError  = 171
	errCodeWebsocketDataNotAccept  = 172
	errCodeWebsocketClosedAbnormal = 173
	errCodeWebsocketDataInconsist  = 174
	errCodeWebsocketAgainstPolicy  = 175
	errCodeWebsocketFrameTooLong   = 176
	errCodeWebsocketExtMissing     = 177
	errCodeWebsocketReqUnavailable = 178
	errCodeWebsocketError          = 179
	ErrCodeTLSError                = 188
	errCodeTCPError                = 197
	errCodeHTTPError               = 165
)

// WebSocket subprotocols (AB.7.1).
const (
	SCHubProtocol    = "hub.bsc.bacnet.org"
	SCDirectProtocol = "dc.bsc.bacnet.org"
)

// VMAC is a BACnet/SC node's 6-octet virtual MAC address (AB.1.5.2,
// H.7.3). It is a net.Addr so it can stand where a B/IP address does.
type VMAC [6]byte

// broadcastVMAC is the Local Broadcast VMAC (AB.1.5.2).
var broadcastVMAC = VMAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func (v VMAC) Network() string { return "bacnet-sc" }
func (v VMAC) String() string  { return strings.ToUpper(hex.EncodeToString(v[:])) }

// RandomVMAC is a Random-48 VMAC (H.7.3): the low four bits of the first
// octet are B'0010', the other 44 bits random.
func RandomVMAC() VMAC {
	var v VMAC
	_, _ = rand.Read(v[:])
	v[0] = v[0]&0xf0 | 0x02
	return v
}

// ParseVMAC reads 12 hex digits (colons or dashes allowed between
// octets). The broadcast and all-zero VMACs are not node addresses.
func ParseVMAC(s string) (VMAC, error) {
	var v VMAC
	b, err := hex.DecodeString(strings.NewReplacer(":", "", "-", "").Replace(s))
	if err != nil || len(b) != 6 {
		return v, fmt.Errorf("VMAC %q is not 6 octets in hex", s)
	}
	copy(v[:], b)
	if v == broadcastVMAC || v == (VMAC{}) {
		return v, fmt.Errorf("VMAC %s is reserved", v)
	}
	return v, nil
}

// ParseUUID reads an RFC 4122 UUID in its text form.
func ParseUUID(s string) ([16]byte, error) {
	var u [16]byte
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return u, fmt.Errorf("device UUID %q is not a UUID", s)
	}
	copy(u[:], b)
	return u, nil
}

// NewUUID is a random (version 4) UUID.
func NewUUID() [16]byte {
	var u [16]byte
	_, _ = rand.Read(u[:])
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	return u
}

func UUIDString(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// SCOption is one header option (AB.2.3). flag is bit 6 of the marker:
// 'Must Understand' for a destination option, 'Every Segment' for a data
// option. hasData says whether 'Header Length' and 'Header Data' follow.
type SCOption struct {
	Typ     byte
	Flag    bool
	HasData bool
	Data    []byte
}

// SCMsg is a BVLC-SC message (Table AB-2). orig and dest are nil when
// absent.
type SCMsg struct {
	Fn       byte
	ID       uint16
	orig     *VMAC
	dest     *VMAC
	DestOpts []SCOption
	dataOpts []SCOption
	Payload  []byte
}

func (m SCMsg) broadcast() bool { return m.dest != nil && *m.dest == broadcastVMAC }

func encodeOptions(b []byte, opts []SCOption) []byte {
	for i, o := range opts {
		mk := o.Typ & scOptType
		if i < len(opts)-1 {
			mk |= scOptMore
		}
		if o.Flag {
			mk |= scOptFlag6
		}
		if o.HasData {
			mk |= scOptData
		}
		b = append(b, mk)
		if o.HasData {
			b = binary.BigEndian.AppendUint16(b, uint16(len(o.Data)))
			b = append(b, o.Data...)
		}
	}
	return b
}

// Encode is the message's octets (AB.2.1). Empty option lists are left
// Out.
func (m SCMsg) Encode() []byte {
	flags := byte(0)
	if m.orig != nil {
		flags |= scFlagOrig
	}
	if m.dest != nil {
		flags |= scFlagDest
	}
	if len(m.DestOpts) > 0 {
		flags |= scFlagDestOpts
	}
	if len(m.dataOpts) > 0 {
		flags |= scFlagDataOpts
	}
	b := []byte{m.Fn, flags, byte(m.ID >> 8), byte(m.ID)}
	if m.orig != nil {
		b = append(b, m.orig[:]...)
	}
	if m.dest != nil {
		b = append(b, m.dest[:]...)
	}
	b = encodeOptions(b, m.DestOpts)
	b = encodeOptions(b, m.dataOpts)
	return append(b, m.Payload...)
}

// scNAK is why a received message is refused (AB.3.1.4, AB.3.1.5): the
// error code of a BVLC-Result NAK in class COMMUNICATION and the header
// Marker at fault (0 when none). silent means no NAK is returned at all
// (a message without a message ID).
type scNAK struct {
	code   uint16
	marker byte
	silent bool
	why    string
}

func (e *scNAK) Error() string { return fmt.Sprintf("BVLC-SC error code %d: %s", e.code, e.why) }

func nak(code uint16, why string, a ...any) *scNAK {
	return &scNAK{code: code, why: fmt.Sprintf(why, a...)}
}

// decodeOptions reads a header option list; the last option has 'More
// Options' clear.
func decodeOptions(b []byte, data bool) ([]SCOption, []byte, *scNAK) {
	var opts []SCOption
	for {
		if len(b) == 0 {
			return nil, nil, nak(errCodeMessageIncomplete, "header option list ends early")
		}
		mk := b[0]
		b = b[1:]
		o := SCOption{Typ: mk & scOptType, Flag: mk&scOptFlag6 != 0, HasData: mk&scOptData != 0}
		if o.Typ == 0 {
			e := nak(errCodeHeaderEncodingError, "header option type 0")
			e.marker = mk
			return nil, nil, e
		}
		if o.HasData {
			if len(b) < 2 {
				return nil, nil, nak(errCodeMessageIncomplete, "header length missing")
			}
			n := int(binary.BigEndian.Uint16(b))
			if len(b) < 2+n {
				return nil, nil, nak(errCodeMessageIncomplete, "header data shorter than its length")
			}
			o.Data, b = b[2:2+n], b[2+n:]
		}
		if e := checkOption(o, mk, data); e != nil {
			return nil, nil, e
		}
		opts = append(opts, o)
		if mk&scOptMore == 0 {
			return opts, b, nil
		}
	}
}

// checkOption applies the encodings of the standard header options
// (AB.2.3.1, AB.2.3.2).
func checkOption(o SCOption, mk byte, data bool) *scNAK {
	bad := func(why string) *scNAK {
		e := nak(errCodeHeaderEncodingError, "%s", why)
		e.marker = mk
		return e
	}
	switch o.Typ {
	case SCOptSecurePath:
		if o.HasData {
			return bad("the Secure Path option carries no data")
		}
	case SCOptHello:
		if !o.HasData || len(o.Data) != 1 {
			return bad("the Hello option carries one octet")
		}
	case SCOptIdentity:
		if !o.HasData || len(o.Data) != 3 {
			return bad("the Identity option carries three octets")
		}
	case SCOptProprietary:
		if !o.HasData || len(o.Data) < 3 {
			return bad("a proprietary option carries a vendor identifier and a type")
		}
	}
	return nil
}

// payloadRule is what a function's payload must be: required says one
// must be present, fixed a length it must have (0 for any), none that it
// must be absent; dataOpts whether data options may be present; peerOnly
// whether the addresses are always absent (connection messages).
type payloadRule struct {
	required, none, dataOpts, peerOnly bool
	fixed, min                         int
}

var scRules = map[byte]payloadRule{
	SCResult:          {required: true, min: 2},
	scEncapsulated:    {required: true, dataOpts: true, min: 1},
	SCAddrResolution:  {none: true},
	scAddrResACK:      {},
	scAdvertisement:   {required: true, fixed: 6},
	scAdvSolicitation: {none: true},
	SCConnectRequest:  {required: true, fixed: 26, peerOnly: true},
	SCConnectAccept:   {required: true, fixed: 26, peerOnly: true},
	SCDisconnectReq:   {none: true, peerOnly: true},
	SCDisconnectACK:   {none: true, peerOnly: true},
	SCHeartbeatReq:    {none: true, peerOnly: true},
	SCHeartbeatACK:    {none: true, peerOnly: true},
	scProprietary:     {required: true, min: 3},
}

// DecodeSC decodes and checks a BVLC-SC message (AB.2, AB.3.1.5). On an
// error the partly decoded message (function, ID and addresses, when
// read) comes back with it so a NAK can be addressed.
func DecodeSC(b []byte) (SCMsg, *scNAK) {
	var m SCMsg
	if len(b) < 4 {
		return m, &scNAK{silent: true, why: "no message ID"}
	}
	m.Fn, m.ID = b[0], binary.BigEndian.Uint16(b[2:])
	flags := b[1]
	b = b[4:]
	if flags&scFlagOrig != 0 {
		if len(b) < 6 {
			return m, nak(errCodeMessageIncomplete, "originating virtual address cut short")
		}
		v := VMAC(b[:6])
		m.orig, b = &v, b[6:]
	}
	if flags&scFlagDest != 0 {
		if len(b) < 6 {
			return m, nak(errCodeMessageIncomplete, "destination virtual address cut short")
		}
		v := VMAC(b[:6])
		m.dest, b = &v, b[6:]
	}
	rule, known := scRules[m.Fn]
	if !known {
		return m, nak(ErrCodeBVLCFunctionUnknown, "BVLC function %d", m.Fn)
	}
	if flags&0xf0 != 0 {
		return m, nak(errCodeParameterOutOfRange, "reserved control flags set")
	}
	if rule.peerOnly && (m.orig != nil || m.dest != nil) {
		return m, nak(errCodeParameterOutOfRange, "addresses on a connection message")
	}
	if !rule.dataOpts && flags&scFlagDataOpts != 0 {
		return m, nak(errCodeParameterOutOfRange, "data options on a message without an NPDU")
	}
	var e *scNAK
	if flags&scFlagDestOpts != 0 {
		if m.DestOpts, b, e = decodeOptions(b, false); e != nil {
			return m, e
		}
	}
	if flags&scFlagDataOpts != 0 {
		if m.dataOpts, b, e = decodeOptions(b, true); e != nil {
			return m, e
		}
	}
	m.Payload = b
	switch {
	case rule.required && len(b) == 0:
		return m, nak(errCodePayloadExpected, "function %d needs a payload", m.Fn)
	case rule.none && len(b) > 0:
		return m, nak(errCodeUnexpectedData, "function %d has no payload", m.Fn)
	case rule.fixed > 0 && len(b) < rule.fixed, len(b) < rule.min:
		return m, nak(errCodeMessageIncomplete, "payload of %d octets is too short", len(b))
	case rule.fixed > 0 && len(b) > rule.fixed:
		return m, nak(errCodeUnexpectedData, "payload of %d octets is too long", len(b))
	}
	if m.Fn == SCResult {
		if err := checkResult(b); err != nil {
			return m, err
		}
	}
	if m.Fn == scAddrResACK && !utf8.Valid(b) {
		return m, nak(errCodeParameterOutOfRange, "WebSocket URIs are not UTF-8")
	}
	return m, nil
}

// mustUnderstand returns a NAK for the first destination option with
// 'Must Understand' set that this node does not support (AB.3.1.4). None
// of the standard destination options is one the IPE acts on.
func (m SCMsg) mustUnderstand() *scNAK {
	for i, o := range m.DestOpts {
		if o.Flag && o.Typ != SCOptHello {
			e := nak(ErrCodeHeaderNotUnderstood, "destination option %d must be understood", o.Typ)
			e.marker = o.Typ | scOptFlag6
			if o.HasData {
				e.marker |= scOptData
			}
			if i < len(m.DestOpts)-1 {
				e.marker |= scOptMore
			}
			return e
		}
	}
	return nil
}

// scResultInfo is a decoded BVLC-Result payload (AB.2.4).
type scResultInfo struct {
	Fn      byte
	NAK     bool
	Marker  byte
	Class   uint16
	Code    uint16
	details string
}

func checkResult(b []byte) *scNAK {
	switch b[1] {
	case 0:
		if len(b) > 2 {
			return nak(errCodeUnexpectedData, "an ACK has nothing after the result code")
		}
	case 1:
		if len(b) < 7 {
			return nak(errCodeMessageIncomplete, "a NAK needs marker, class and code")
		}
		if !utf8.Valid(b[7:]) {
			return nak(errCodeParameterOutOfRange, "error details are not UTF-8")
		}
	default:
		return nak(errCodeParameterOutOfRange, "result code %d", b[1])
	}
	return nil
}

func DecodeResult(b []byte) scResultInfo {
	r := scResultInfo{Fn: b[0], NAK: b[1] == 1}
	if r.NAK {
		r.Marker = b[2]
		r.Class, r.Code = binary.BigEndian.Uint16(b[3:]), binary.BigEndian.Uint16(b[5:])
		r.details = string(b[7:])
	}
	return r
}

// resultPayload is a BVLC-Result payload: an ACK when e is nil.
func resultPayload(fn byte, e *scNAK, details string) []byte {
	if e == nil {
		return []byte{fn, 0}
	}
	b := []byte{fn, 1, e.marker}
	b = binary.BigEndian.AppendUint16(b, ErrClassCommunication)
	b = binary.BigEndian.AppendUint16(b, e.code)
	return append(b, details...)
}

// isResponse reports the response messages of AB.2, which get no
// BVLC-Result back.
func isResponse(fn byte) bool {
	switch fn {
	case SCResult, scAddrResACK, SCConnectAccept, SCDisconnectACK, SCHeartbeatACK:
		return true
	}
	return false
}

// SCConnect is the payload of Connect-Request and Connect-Accept
// (AB.2.10, AB.2.11).
type SCConnect struct {
	VMAC    VMAC
	UUID    [16]byte
	MaxBVLC uint16
	MaxNPDU uint16
}

func (c SCConnect) Bytes() []byte {
	b := append(c.VMAC[:0:0], c.VMAC[:]...)
	b = append(b, c.UUID[:]...)
	b = binary.BigEndian.AppendUint16(b, c.MaxBVLC)
	return binary.BigEndian.AppendUint16(b, c.MaxNPDU)
}

func DecodeConnect(b []byte) (SCConnect, error) {
	var c SCConnect
	if len(b) != 26 {
		return c, errors.New("connect payload is not 26 octets")
	}
	copy(c.VMAC[:], b)
	copy(c.UUID[:], b[6:])
	c.MaxBVLC, c.MaxNPDU = binary.BigEndian.Uint16(b[22:]), binary.BigEndian.Uint16(b[24:])
	return c, nil
}

// scAdvert is the Advertisement payload (AB.2.8).
type scAdvert struct {
	hubStatus     byte // 0 none, 1 primary, 2 failover
	acceptsDirect bool
	maxBVLC       uint16
	maxNPDU       uint16
}

func (a scAdvert) bytes() []byte {
	d := byte(0)
	if a.acceptsDirect {
		d = 1
	}
	b := []byte{a.hubStatus, d}
	b = binary.BigEndian.AppendUint16(b, a.maxBVLC)
	return binary.BigEndian.AppendUint16(b, a.maxNPDU)
}

func decodeAdvert(b []byte) (scAdvert, *scNAK) {
	a := scAdvert{hubStatus: b[0], acceptsDirect: b[1] == 1, maxBVLC: binary.BigEndian.Uint16(b[2:]), maxNPDU: binary.BigEndian.Uint16(b[4:])}
	if b[0] > 2 || b[1] > 1 {
		return a, nak(errCodeParameterOutOfRange, "advertisement status out of range")
	}
	return a, nil
}

// websocketCloseCode maps a WebSocket close status (RFC 6455 7.4.1) to
// its BACnet error code (AB.7.5.5).
func websocketCloseCode(status int) uint16 {
	switch status {
	case 1000:
		return errCodeWebsocketClosedByPeer
	case 1001:
		return errCodeWebsocketEndpointLeaves
	case 1002:
		return errCodeWebsocketProtocolError
	case 1003:
		return errCodeWebsocketDataNotAccept
	case 1006:
		return errCodeWebsocketClosedAbnormal
	case 1007:
		return errCodeWebsocketDataInconsist
	case 1008:
		return errCodeWebsocketAgainstPolicy
	case 1009:
		return errCodeWebsocketFrameTooLong
	case 1010:
		return errCodeWebsocketExtMissing
	case 1011:
		return errCodeWebsocketReqUnavailable
	}
	return errCodeWebsocketError
}
