package bacnet

// BACnet/IP wire encoding (ASHRAE 135): the BVLC header of Annex J, the
// NPDU of clause 6.2, the APDU headers of clause 20.1 and the tagged
// primitive encodings of clause 20.2, with the routing fields of clause 6,
// the network layer messages that find a router, foreign-device BVLL
// messages and segmented APDU headers. Only what the IPE needs is here.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
)

// BVLC functions (Annex J.2).
const (
	bvlcType            = 0x81
	BVLCResult          = 0x00
	BVLCForwardedNPDU   = 0x04
	BVLCRegisterFD      = 0x05
	BVLCDistributeBcast = 0x09
	BVLCOriginalUnicast = 0x0a
	BVLCOriginalBcast   = 0x0b
)

// BVLC-Result codes (Annex J.2.1) the IPE acts on.
const (
	ResultOK            = 0x0000
	ResultRegisterFDNAK = 0x0030
	ResultDistributeNAK = 0x0060
)

// Network layer message types (clause 6.2.4, 6.4).
const (
	NlWhoIsRouter   = 0x00
	NlIAmRouter     = 0x01
	nlRejectMessage = 0x03
)

// APDU types (clause 20.1), high nibble of the first octet.
const (
	PDUConfirmed   = 0x0
	PDUUnconfirmed = 0x1
	PDUSimpleACK   = 0x2
	PDUComplexACK  = 0x3
	PDUSegmentACK  = 0x4
	PDUError       = 0x5
	PDUReject      = 0x6
	PDUAbort       = 0x7
)

// Service choices (clause 21).
const (
	SvcConfirmedCOV         = 1
	SvcSubscribeCOV         = 5
	SvcReadRange            = 26
	SvcReadProperty         = 12
	SvcReadPropertyMultiple = 14
	SvcWriteProperty        = 15
	SvcUnconfirmedCOV       = 2 // unconfirmed services
	SvcIAm                  = 0
	SvcWhoIs                = 8
)

// Segmentation support as I-Am states it (clause 21, BACnetSegmentation).
const (
	SegBoth     = 0
	SegTransmit = 1
	SegReceive  = 2
	SegNone     = 3
)

// Property identifiers used by the IPE.
const (
	PropNumberOfStates   = 74
	PropOutOfService     = 81
	PropPresentValue     = 85
	PropStateText        = 110
	PropStatusFlags      = 111
	PropUnits            = 117
	PropLogBuffer        = 131
	PropRecordCount      = 141
	PropTotalRecordCount = 145
	PropPulseRate        = 186
	PropScale            = 187
)

// Object types the IPE maps.
const (
	AnalogInput  = 0
	AnalogOutput = 1
	AnalogValue  = 2
	BinaryInput  = 3
	BinaryOutput = 4
	BinaryValue  = 5
	// Multistate objects (clauses 12.18, 12.19, 12.20), the trend log
	// (12.25) and the accumulator (12.1).
	MultiStateInput  = 13
	MultiStateOutput = 14
	TrendLog         = 20
	MultiStateValue  = 19
	Accumulator      = 23
)

// Application tag numbers (clause 20.2.1.4).
const (
	tagNull        = 0
	tagBoolean     = 1
	tagUnsigned    = 2
	TagSigned      = 3
	tagReal        = 4
	tagDouble      = 5
	tagOctetString = 6
	TagCharString  = 7
	tagBitString   = 8
	tagEnumerated  = 9
	TagDate        = 10
	TagTime        = 11
	TagObjectID    = 12
)

// ContextValue is a primitive context-tagged value inside a property
// value (a CHOICE such as the accumulator's scale), left undecoded.
type ContextValue struct {
	Num  byte
	Data []byte
}

// Enumerated is an application-tagged enumerated value.
type Enumerated uint32

// BitString is an application-tagged bit string; bit 0 is the first bit.
type BitString struct {
	Len  int
	Bits []bool
}

// ObjectID names one object in a device.
type ObjectID struct {
	Type     uint16
	Instance uint32
}

func (o ObjectID) raw() uint32 { return uint32(o.Type)<<22 | o.Instance&0x3fffff }

func ObjectIDFrom(v uint32) ObjectID { return ObjectID{Type: uint16(v >> 22), Instance: v & 0x3fffff} }

// ---- encoding ---------------------------------------------------------------

// Enc builds tagged content.
type Enc struct{ B []byte }

// Header writes a tag octet (clause 20.2.1) for content of length n.
func (e *Enc) Header(num byte, context bool, n int) {
	first := byte(0)
	if context {
		first = 0x08
	}
	var ext []byte
	if num <= 14 {
		first |= num << 4
	} else {
		first |= 0xf0
		ext = append(ext, num)
	}
	switch {
	case n <= 4:
		first |= byte(n)
	case n <= 253:
		first |= 5
		ext = append(ext, byte(n))
	case n <= 65535:
		first |= 5
		ext = append(ext, 254, byte(n>>8), byte(n))
	default:
		first |= 5
		ext = append(ext, 255, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	e.B = append(e.B, first)
	e.B = append(e.B, ext...)
}

func (e *Enc) Open(num byte)  { e.B = append(e.B, num<<4|0x0e) }
func (e *Enc) Close(num byte) { e.B = append(e.B, num<<4|0x0f) }

func unsignedBytes(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 7 && b[i] == 0 {
		i++
	}
	return b[i:]
}

func SignedBytes(v int64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(v))
	i := 0
	// Drop redundant sign octets.
	for i < 7 && ((b[i] == 0 && b[i+1]&0x80 == 0) || (b[i] == 0xff && b[i+1]&0x80 != 0)) {
		i++
	}
	return b[i:]
}

func (e *Enc) CtxUnsigned(num byte, v uint64) {
	c := unsignedBytes(v)
	e.Header(num, true, len(c))
	e.B = append(e.B, c...)
}

func (e *Enc) CtxObjectID(num byte, o ObjectID) {
	e.Header(num, true, 4)
	e.B = binary.BigEndian.AppendUint32(e.B, o.raw())
}

func (e *Enc) CtxBool(num byte, v bool) {
	e.Header(num, true, 1)
	if v {
		e.B = append(e.B, 1)
	} else {
		e.B = append(e.B, 0)
	}
}

// App writes v as an application-tagged value. Go types map as: nil Null,
// bool Boolean, uint64/uint32/uint Unsigned, int64/int Signed, float32
// Real, float64 Double, Enumerated, BitString, string CharacterString
// (UTF-8), ObjectID.
func (e *Enc) App(v any) error {
	switch x := v.(type) {
	case nil:
		e.Header(tagNull, false, 0)
	case bool:
		// A boolean's value lives in the length field (clause 20.2.3).
		if x {
			e.B = append(e.B, tagBoolean<<4|1)
		} else {
			e.B = append(e.B, tagBoolean<<4)
		}
	case uint:
		return e.App(uint64(x))
	case uint32:
		return e.App(uint64(x))
	case uint64:
		c := unsignedBytes(x)
		e.Header(tagUnsigned, false, len(c))
		e.B = append(e.B, c...)
	case int:
		return e.App(int64(x))
	case int64:
		c := SignedBytes(x)
		e.Header(TagSigned, false, len(c))
		e.B = append(e.B, c...)
	case float32:
		e.Header(tagReal, false, 4)
		e.B = binary.BigEndian.AppendUint32(e.B, math.Float32bits(x))
	case float64:
		e.Header(tagDouble, false, 8)
		e.B = binary.BigEndian.AppendUint64(e.B, math.Float64bits(x))
	case string:
		e.Header(TagCharString, false, len(x)+1)
		e.B = append(e.B, 0) // character set: UTF-8
		e.B = append(e.B, x...)
	case BitString:
		n := (x.Len + 7) / 8
		c := make([]byte, 1+n)
		c[0] = byte(n*8 - x.Len) // unused bits in the last octet
		for i := 0; i < x.Len && i < len(x.Bits); i++ {
			if x.Bits[i] {
				c[1+i/8] |= 0x80 >> (i % 8)
			}
		}
		e.Header(tagBitString, false, len(c))
		e.B = append(e.B, c...)
	case Enumerated:
		c := unsignedBytes(uint64(x))
		e.Header(tagEnumerated, false, len(c))
		e.B = append(e.B, c...)
	case ObjectID:
		e.Header(TagObjectID, false, 4)
		e.B = binary.BigEndian.AppendUint32(e.B, x.raw())
	default:
		return fmt.Errorf("no BACnet encoding for %T", v)
	}
	return nil
}

// ---- decoding ---------------------------------------------------------------

// Tag is one decoded tag with its content.
type Tag struct {
	Num     byte
	Context bool
	Open    bool
	Close   bool
	Lvt     uint32 // length, or the value of an application boolean
	Data    []byte
}

var errShort = errors.New("truncated BACnet data")

// ReadTag decodes one tag and its content from b.
func ReadTag(b []byte) (Tag, []byte, error) {
	if len(b) == 0 {
		return Tag{}, nil, errShort
	}
	t := Tag{Num: b[0] >> 4, Context: b[0]&0x08 != 0, Lvt: uint32(b[0] & 0x07)}
	b = b[1:]
	if t.Num == 15 {
		if len(b) == 0 {
			return t, nil, errShort
		}
		t.Num, b = b[0], b[1:]
	}
	switch {
	case t.Lvt == 6 && t.Context:
		t.Open = true
		return t, b, nil
	case t.Lvt == 7 && t.Context:
		t.Close = true
		return t, b, nil
	case t.Lvt == 5:
		if len(b) == 0 {
			return t, nil, errShort
		}
		switch b[0] {
		case 254:
			if len(b) < 3 {
				return t, nil, errShort
			}
			t.Lvt, b = uint32(binary.BigEndian.Uint16(b[1:])), b[3:]
		case 255:
			if len(b) < 5 {
				return t, nil, errShort
			}
			t.Lvt, b = binary.BigEndian.Uint32(b[1:]), b[5:]
		default:
			t.Lvt, b = uint32(b[0]), b[1:]
		}
	}
	if !t.Context && t.Num == tagBoolean {
		return t, b, nil // no content octets
	}
	if uint32(len(b)) < t.Lvt {
		return t, nil, errShort
	}
	t.Data, b = b[:t.Lvt], b[t.Lvt:]
	return t, b, nil
}

func BeUnsigned(d []byte) (uint64, error) {
	if len(d) == 0 || len(d) > 8 {
		return 0, fmt.Errorf("unsigned of %d octets", len(d))
	}
	var v uint64
	for _, x := range d {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// AppValue decodes an application-tagged value (see enc.app for types).
// Types the IPE does not use come back as their raw octets.
func AppValue(t Tag) (any, error) {
	if t.Context {
		return nil, fmt.Errorf("context tag %d where an application value was expected", t.Num)
	}
	d := t.Data
	switch t.Num {
	case tagNull:
		return nil, nil
	case tagBoolean:
		return t.Lvt != 0, nil
	case tagUnsigned:
		return BeUnsigned(d)
	case TagSigned:
		if len(d) == 0 || len(d) > 8 {
			return nil, errShort
		}
		v := int64(int8(d[0]))
		for _, x := range d[1:] {
			v = v<<8 | int64(x)
		}
		return v, nil
	case tagReal:
		if len(d) != 4 {
			return nil, errShort
		}
		return math.Float32frombits(binary.BigEndian.Uint32(d)), nil
	case tagDouble:
		if len(d) != 8 {
			return nil, errShort
		}
		return math.Float64frombits(binary.BigEndian.Uint64(d)), nil
	case TagCharString:
		if len(d) == 0 {
			return nil, errShort
		}
		if d[0] != 0 {
			return nil, fmt.Errorf("character set %d is not supported", d[0])
		}
		return string(d[1:]), nil
	case tagBitString:
		if len(d) == 0 {
			return nil, errShort
		}
		n := (len(d)-1)*8 - int(d[0])
		if n < 0 {
			return nil, errShort
		}
		bs := BitString{Len: n, Bits: make([]bool, n)}
		for i := range n {
			bs.Bits[i] = d[1+i/8]&(0x80>>(i%8)) != 0
		}
		return bs, nil
	case tagEnumerated:
		v, err := BeUnsigned(d)
		return Enumerated(v), err
	case TagObjectID:
		if len(d) != 4 {
			return nil, errShort
		}
		return ObjectIDFrom(binary.BigEndian.Uint32(d)), nil
	default:
		return append([]byte(nil), d...), nil
	}
}

// ValuesUntilClose decodes application values up to the closing tag num,
// returning them and what follows the closing tag.
func ValuesUntilClose(b []byte, num byte) ([]any, []byte, error) {
	var out []any
	for {
		t, rest, err := ReadTag(b)
		if err != nil {
			return nil, nil, err
		}
		if t.Close && t.Num == num {
			return out, rest, nil
		}
		if t.Open || t.Close || t.Context {
			// Constructed values are not used by the IPE: skip them;
			// primitive context-tagged ones are kept undecoded.
			if t.Open {
				if rest, err = SkipConstructed(rest, t.Num); err != nil {
					return nil, nil, err
				}
				b = rest
				continue
			}
			if !t.Close {
				out = append(out, ContextValue{Num: t.Num, Data: t.Data})
			}
			b = rest
			continue
		}
		v, err := AppValue(t)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, v)
		b = rest
	}
}

func SkipConstructed(b []byte, num byte) ([]byte, error) {
	depth := 1
	for depth > 0 {
		t, rest, err := ReadTag(b)
		if err != nil {
			return nil, err
		}
		if t.Open {
			depth++
		} else if t.Close {
			depth--
		}
		b = rest
	}
	return b, nil
}

// ---- BVLC / NPDU / APDU -----------------------------------------------------

// NPDU is a decoded BVLC frame and NPDU: the routing fields of clause 6.2,
// a network layer message (clause 6.4) or an APDU in data.
type NPDU struct {
	Fn          byte         // BVLC function
	Origin      *net.UDPAddr // Forwarded-NPDU: the original B/IP source
	Result      uint16       // BVLC-Result code (fn == bvlcResult)
	ExpectReply bool
	Dnet        uint16 // 0: no destination specifier
	DADR        []byte
	Hop         byte
	Snet        uint16 // 0: no source specifier
	SADR        []byte
	NetMsg      bool
	MsgType     byte
	Data        []byte     // APDU, or the network message's content
	Opts        []SCOption // BACnet/SC data options that came with the NPDU
}

// EncodeNPDU builds a BVLC frame of function fn around an NPDU. A
// Forwarded-NPDU carries n.origin; a destination gets n.hop as its hop
// Count.
func EncodeNPDU(fn byte, n NPDU) []byte {
	b := []byte{bvlcType, fn, 0, 0}
	if fn == BVLCForwardedNPDU {
		b = append(b, BIPAddr(n.Origin)...)
	}
	b = append(b, NPDUBytes(n)...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// NPDUBytes is the NPDU of clause 6.2 alone (version, control octet,
// DNET/DLEN/DADR, SNET/SLEN/SADR, hop count, message type and data), as
// every data link carries it.
func NPDUBytes(n NPDU) []byte {
	ctl := byte(0)
	if n.NetMsg {
		ctl |= 0x80
	}
	if n.Dnet != 0 {
		ctl |= 0x20
	}
	if n.Snet != 0 {
		ctl |= 0x08
	}
	if n.ExpectReply {
		ctl |= 0x04
	}
	b := []byte{0x01, ctl}
	if n.Dnet != 0 {
		b = binary.BigEndian.AppendUint16(b, n.Dnet)
		b = append(b, byte(len(n.DADR)))
		b = append(b, n.DADR...)
	}
	if n.Snet != 0 {
		b = binary.BigEndian.AppendUint16(b, n.Snet)
		b = append(b, byte(len(n.SADR)))
		b = append(b, n.SADR...)
	}
	if n.Dnet != 0 {
		b = append(b, n.Hop)
	}
	if n.NetMsg {
		b = append(b, n.MsgType)
	}
	return append(b, n.Data...)
}

// BIPAddr is the six-octet B/IP address (Annex J.1.2) of an IPv4 address.
func BIPAddr(a *net.UDPAddr) []byte {
	b := make([]byte, 6)
	if a != nil {
		if ip4 := a.IP.To4(); ip4 != nil {
			copy(b, ip4)
		}
		binary.BigEndian.PutUint16(b[4:], uint16(a.Port))
	}
	return b
}

// BVLC builds a BVLL message without an NPDU (Register-Foreign-Device,
// BVLC-Result).
func BVLC(fn byte, payload []byte) []byte {
	n := 4 + len(payload)
	return append([]byte{bvlcType, fn, byte(n >> 8), byte(n)}, payload...)
}

// Frame wraps an APDU in an NPDU without routing information and a BVLC
// Original-Unicast-NPDU header.
func Frame(apdu []byte, expectReply bool) []byte {
	return EncodeNPDU(BVLCOriginalUnicast, NPDU{ExpectReply: expectReply, Data: apdu})
}

// DecodeFrame decodes the BVLC header and the NPDU. BVLL functions that
// carry no NPDU (other than BVLC-Result) come back with their payload in
// data; hasNPDU tells them apart.
func DecodeFrame(b []byte) (NPDU, error) {
	var n NPDU
	if len(b) < 4 || b[0] != bvlcType {
		return n, errors.New("not a BACnet/IP frame")
	}
	if l := int(binary.BigEndian.Uint16(b[2:])); l != len(b) {
		return n, fmt.Errorf("BVLC length %d does not match %d received", l, len(b))
	}
	n.Fn = b[1]
	b = b[4:]
	switch n.Fn {
	case BVLCResult:
		if len(b) < 2 {
			return n, errShort
		}
		n.Result = binary.BigEndian.Uint16(b)
		return n, nil
	case BVLCOriginalUnicast, BVLCOriginalBcast, BVLCDistributeBcast:
	case BVLCForwardedNPDU:
		if len(b) < 6 {
			return n, errShort
		}
		n.Origin = &net.UDPAddr{IP: net.IPv4(b[0], b[1], b[2], b[3]), Port: int(binary.BigEndian.Uint16(b[4:]))}
		b = b[6:]
	default:
		n.Data = b
		return n, nil
	}
	return DecodeNPDU(n, b)
}

// DecodeNPDU decodes the NPDU of clause 6.2 in b into n (whose BVLC
// fields are already set).
func DecodeNPDU(n NPDU, b []byte) (NPDU, error) {
	if len(b) < 2 || b[0] != 0x01 {
		return n, errors.New("unsupported NPDU version")
	}
	ctl := b[1]
	b = b[2:]
	n.ExpectReply = ctl&0x04 != 0
	addr := func() (uint16, []byte, error) {
		if len(b) < 3 || len(b) < 3+int(b[2]) {
			return 0, nil, errShort
		}
		nw, a := binary.BigEndian.Uint16(b), append([]byte(nil), b[3:3+int(b[2])]...)
		b = b[3+int(b[2]):]
		return nw, a, nil
	}
	var err error
	if ctl&0x20 != 0 {
		if n.Dnet, n.DADR, err = addr(); err != nil {
			return n, err
		}
	}
	if ctl&0x08 != 0 {
		if n.Snet, n.SADR, err = addr(); err != nil {
			return n, err
		}
	}
	if ctl&0x20 != 0 {
		if len(b) < 1 {
			return n, errShort
		}
		n.Hop, b = b[0], b[1:]
	}
	if ctl&0x80 != 0 {
		if len(b) < 1 {
			return n, errShort
		}
		n.NetMsg, n.MsgType, b = true, b[0], b[1:]
		if n.MsgType >= 0x80 { // proprietary: vendor ID follows
			if len(b) < 2 {
				return n, errShort
			}
			b = b[2:]
		}
	}
	n.Data = b
	return n, nil
}

// Unframe strips BVLC and NPDU, returning the APDU. Network-layer
// messages and BVLL messages without an APDU return nil, nil.
func Unframe(b []byte) ([]byte, error) {
	n, err := DecodeFrame(b)
	if err != nil || n.NetMsg || !hasNPDU(n.Fn) {
		return nil, err
	}
	return n.Data, nil
}

// hasNPDU reports whether BVLC function fn carries an NPDU.
func hasNPDU(fn byte) bool {
	switch fn {
	case BVLCOriginalUnicast, BVLCOriginalBcast, BVLCForwardedNPDU, BVLCDistributeBcast:
		return true
	}
	return false
}

// PCI flags of the APDU headers (clause 20.1).
const (
	flagSEG = 0x08 // segmented message
	flagMOR = 0x04 // more follows
	flagSA  = 0x02 // segmented response accepted (Confirmed-Request)
	flagNAK = 0x02 // negative acknowledgement (Segment-ACK)
	flagSRV = 0x01 // sent by the server (Segment-ACK, Abort)
)

// Segmentation limits of the IPE as a requester.
const (
	MaxSegments = 64 // stated in requests as code 6
	MaxWindow   = 16 // the largest window the IPE accepts or proposes
	ownMaxAPDU  = 5  // code for 1476 octets
)

// apduSizes are the max-APDU-length-accepted codes 0..5 (clause 20.1.2.5).
var apduSizes = [...]int{50, 128, 206, 480, 1024, 1476}

func apduSizeCode(n int) byte {
	c := byte(0)
	for i, s := range apduSizes {
		if n >= s {
			c = byte(i)
		}
	}
	return c
}

// Confirmed builds an unsegmented Confirmed-Request APDU. It accepts a
// segmented response of up to 64 segments of up to 1476 octets.
func Confirmed(invokeID, service byte, req []byte) []byte {
	return confirmedMax(invokeID, service, ownMaxAPDU, req)
}

// confirmedMax is confirmed stating max APDU code maxCode.
func confirmedMax(invokeID, service, maxCode byte, req []byte) []byte {
	return append([]byte{PDUConfirmed<<4 | flagSA, 6<<4 | maxCode, invokeID, service}, req...)
}

// ConfirmedSegment builds one segment of a segmented Confirmed-Request.
func ConfirmedSegment(invokeID, service, seq, window byte, more bool, part []byte) []byte {
	h := byte(PDUConfirmed<<4 | flagSEG | flagSA)
	if more {
		h |= flagMOR
	}
	return append([]byte{h, 6<<4 | ownMaxAPDU, invokeID, seq, window, service}, part...)
}

// ComplexACKSegment builds one segment of a segmented Complex-ACK.
func ComplexACKSegment(invokeID, service, seq, window byte, more bool, part []byte) []byte {
	h := byte(PDUComplexACK<<4 | flagSEG)
	if more {
		h |= flagMOR
	}
	return append([]byte{h, invokeID, seq, window, service}, part...)
}

// SegmentACK builds a Segment-ACK; srv is set when a server sends it.
func SegmentACK(invokeID, seq, window byte, nak, srv bool) []byte {
	h := byte(PDUSegmentACK << 4)
	if nak {
		h |= flagNAK
	}
	if srv {
		h |= flagSRV
	}
	return []byte{h, invokeID, seq, window}
}

// abortPDU builds an Abort; srv is set when a server sends it.
func EncodeAbort(invokeID, reason byte, srv bool) []byte {
	h := byte(PDUAbort << 4)
	if srv {
		h |= flagSRV
	}
	return []byte{h, invokeID, reason}
}

// Abort reasons the IPE sends (clause 20.1.9, 21).
const (
	AbortOther          = 0
	AbortBufferOverflow = 1
	abortInvalidAPDU    = 2 // invalid-apdu-in-this-state
	AbortSegNotSupp     = 4 // segmentation-not-supported
)

// Reject reasons (clause 21, BACnetRejectReason) the IPE sends.
const RejectUnrecognizedService = 9

// APDU is a decoded APDU header with its service data.
type APDU struct {
	Typ      byte
	InvokeID byte
	Service  byte
	Data     []byte
	Reason   byte       // reject and abort reason
	Attrs    []SCOption // BACnet/SC data options (data attributes) of the request

	Seg, More bool // segmented, more follows
	Seq       byte // sequence number (segments, Segment-ACK)
	Window    byte // proposed (segments) or actual (Segment-ACK) window size
	NAK, Srv  bool // Segment-ACK and Abort flags
	Sa        bool // Confirmed-Request: segmented response accepted
	MaxResp   int  // Confirmed-Request: largest APDU the requester accepts
	MaxSegs   int  // Confirmed-Request: most segments the requester accepts (255: unspecified or more than 64)
}

func ParseAPDU(b []byte) (APDU, error) {
	if len(b) < 2 {
		return APDU{}, errShort
	}
	a := APDU{Typ: b[0] >> 4}
	switch a.Typ {
	case PDUConfirmed:
		a.Seg, a.More, a.Sa = b[0]&flagSEG != 0, b[0]&flagMOR != 0, b[0]&flagSA != 0
		if c := int(b[1] & 0x0f); c < len(apduSizes) {
			a.MaxResp = apduSizes[c]
		} else {
			a.MaxResp = apduSizes[0]
		}
		// max-segments-accepted (20.1.2.4): 0 unspecified, 1..6 two to 64, 7 more than 64.
		if c := int(b[1]>>4) & 7; c >= 1 && c <= 6 {
			a.MaxSegs = 1 << c
		} else {
			a.MaxSegs = 255
		}
		if a.Seg {
			if len(b) < 6 {
				return a, errShort
			}
			a.InvokeID, a.Seq, a.Window, a.Service, a.Data = b[2], b[3], b[4], b[5], b[6:]
			break
		}
		if len(b) < 4 {
			return a, errShort
		}
		a.InvokeID, a.Service, a.Data = b[2], b[3], b[4:]
	case PDUUnconfirmed:
		a.Service, a.Data = b[1], b[2:]
	case PDUSimpleACK:
		if len(b) < 3 {
			return a, errShort
		}
		a.InvokeID, a.Service = b[1], b[2]
	case PDUComplexACK:
		a.Seg, a.More = b[0]&flagSEG != 0, b[0]&flagMOR != 0
		if a.Seg {
			if len(b) < 5 {
				return a, errShort
			}
			a.InvokeID, a.Seq, a.Window, a.Service, a.Data = b[1], b[2], b[3], b[4], b[5:]
			break
		}
		if len(b) < 3 {
			return a, errShort
		}
		a.InvokeID, a.Service, a.Data = b[1], b[2], b[3:]
	case PDUError:
		if len(b) < 3 {
			return a, errShort
		}
		a.InvokeID, a.Service, a.Data = b[1], b[2], b[3:]
	case PDUReject, PDUAbort:
		if len(b) < 3 {
			return a, errShort
		}
		a.InvokeID, a.Reason, a.Srv = b[1], b[2], b[0]&flagSRV != 0
	case PDUSegmentACK:
		if len(b) < 4 {
			return a, errShort
		}
		a.NAK, a.Srv = b[0]&flagNAK != 0, b[0]&flagSRV != 0
		a.InvokeID, a.Seq, a.Window = b[1], b[2], b[3]
	default:
		return a, fmt.Errorf("unknown APDU type %d", a.Typ)
	}
	return a, nil
}

// ErrorPDU is a BACnet Error reply (error class and code, clause 18).
type ErrorPDU struct{ Class, Code uint32 }

func (e *ErrorPDU) Error() string {
	return fmt.Sprintf("the device answered error class %d code %d", e.Class, e.Code)
}

// RejectPDU is a BACnet Reject reply.
type RejectPDU struct{ Reason byte }

func (e *RejectPDU) Error() string {
	return fmt.Sprintf("the device rejected the request (reason %d)", e.Reason)
}

// AbortPDU is a BACnet Abort reply.
type AbortPDU struct{ Reason byte }

func (e *AbortPDU) Error() string {
	return fmt.Sprintf("the device aborted the request (reason %d)", e.Reason)
}

// ErrorFrom decodes the class and code of an Error APDU; for services
// whose error is constructed it takes the first two enumerations found.
func ErrorFrom(data []byte) error {
	var vals []uint32
	for len(data) > 0 && len(vals) < 2 {
		t, rest, err := ReadTag(data)
		if err != nil {
			break
		}
		if !t.Context && t.Num == tagEnumerated {
			v, _ := BeUnsigned(t.Data)
			vals = append(vals, uint32(v))
		}
		data = rest
	}
	if len(vals) < 2 {
		return &ErrorPDU{}
	}
	return &ErrorPDU{Class: vals[0], Code: vals[1]}
}

// ErrorAPDU builds an Error reply with an error class and code.
func ErrorAPDU(id, svc byte, class, code uint32) []byte {
	var e Enc
	_ = e.App(Enumerated(class))
	_ = e.App(Enumerated(code))
	return append([]byte{PDUError << 4, id, svc}, e.B...)
}

// ---- services ---------------------------------------------------------------

// EncodeReadProperty is the ReadProperty request (clause 15.5).
func EncodeReadProperty(o ObjectID, prop uint32) []byte {
	var e Enc
	e.CtxObjectID(0, o)
	e.CtxUnsigned(1, uint64(prop))
	return e.B
}

// PropRef names one property of one object.
type PropRef struct {
	Object ObjectID
	Prop   uint32
}

// PropResult is one property's value or error.
type PropResult struct {
	PropRef
	Values []any
	Err    error
}

func DecodeReadPropertyAck(b []byte) (PropResult, error) {
	var r PropResult
	t, b, err := ReadTag(b)
	if err != nil || !t.Context || t.Num != 0 || len(t.Data) != 4 {
		return r, errors.New("ReadProperty-ACK without an object identifier")
	}
	r.Object = ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
	t, b, err = ReadTag(b)
	if err != nil || !t.Context || t.Num != 1 {
		return r, errors.New("ReadProperty-ACK without a property identifier")
	}
	p, _ := BeUnsigned(t.Data)
	r.Prop = uint32(p)
	t, b, err = ReadTag(b)
	if err == nil && t.Context && t.Num == 2 {
		t, b, err = ReadTag(b) // array index
	}
	if err != nil || !t.Open || t.Num != 3 {
		return r, errors.New("ReadProperty-ACK without a value")
	}
	r.Values, _, err = ValuesUntilClose(b, 3)
	return r, err
}

// EncodeReadPropertyMultiple is the ReadPropertyMultiple request (clause
// 15.7), properties grouped by object in the order given.
func EncodeReadPropertyMultiple(refs []PropRef) []byte {
	var e Enc
	for i := 0; i < len(refs); {
		o := refs[i].Object
		e.CtxObjectID(0, o)
		e.Open(1)
		for ; i < len(refs) && refs[i].Object == o; i++ {
			e.CtxUnsigned(0, uint64(refs[i].Prop))
		}
		e.Close(1)
	}
	return e.B
}

func DecodeReadPropertyMultipleAck(b []byte) ([]PropResult, error) {
	var out []PropResult
	for len(b) > 0 {
		t, rest, err := ReadTag(b)
		if err != nil || !t.Context || t.Num != 0 || len(t.Data) != 4 {
			return nil, errors.New("ReadPropertyMultiple-ACK: object identifier expected")
		}
		o := ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
		t, rest, err = ReadTag(rest)
		if err != nil || !t.Open || t.Num != 1 {
			return nil, errors.New("ReadPropertyMultiple-ACK: result list expected")
		}
		b = rest
		for {
			t, rest, err = ReadTag(b)
			if err != nil {
				return nil, err
			}
			if t.Close && t.Num == 1 {
				b = rest
				break
			}
			if !t.Context || t.Num != 2 {
				return nil, errors.New("ReadPropertyMultiple-ACK: property identifier expected")
			}
			p, _ := BeUnsigned(t.Data)
			r := PropResult{PropRef: PropRef{Object: o, Prop: uint32(p)}}
			t, rest, err = ReadTag(rest)
			if err == nil && t.Context && t.Num == 3 {
				t, rest, err = ReadTag(rest)
			}
			if err != nil || !t.Open {
				return nil, errors.New("ReadPropertyMultiple-ACK: value or error expected")
			}
			switch t.Num {
			case 4:
				r.Values, rest, err = ValuesUntilClose(rest, 4)
			case 5:
				var vals []any
				vals, rest, err = ValuesUntilClose(rest, 5)
				e := &ErrorPDU{}
				if len(vals) == 2 {
					c, _ := vals[0].(Enumerated)
					d, _ := vals[1].(Enumerated)
					e.Class, e.Code = uint32(c), uint32(d)
				}
				r.Err = e
			default:
				err = errors.New("ReadPropertyMultiple-ACK: unexpected tag")
			}
			if err != nil {
				return nil, err
			}
			out = append(out, r)
			b = rest
		}
	}
	return out, nil
}

// EncodeWriteProperty is the WriteProperty request (clause 15.9);
// Priority 0 leaves the priority out.
func EncodeWriteProperty(o ObjectID, prop uint32, value any, priority int) ([]byte, error) {
	var e Enc
	e.CtxObjectID(0, o)
	e.CtxUnsigned(1, uint64(prop))
	e.Open(3)
	if err := e.App(value); err != nil {
		return nil, err
	}
	e.Close(3)
	if priority > 0 {
		e.CtxUnsigned(4, uint64(priority))
	}
	return e.B, nil
}

// encodeSubscribeCOV is the SubscribeCOV request (clause 13.14), for
// Confirmed or unconfirmed notifications.
func encodeSubscribeCOV(process uint32, o ObjectID, confirmed bool, lifetime uint32) []byte {
	var e Enc
	e.CtxUnsigned(0, uint64(process))
	e.CtxObjectID(1, o)
	e.CtxBool(2, confirmed)
	e.CtxUnsigned(3, uint64(lifetime))
	return e.B
}

// COVNotification is a decoded COV notification (clause 13.7 / 13.8).
type COVNotification struct {
	Process uint32
	Device  ObjectID
	Object  ObjectID
	Values  map[uint32][]any
}

func DecodeCOVNotification(b []byte) (COVNotification, error) {
	n := COVNotification{Values: map[uint32][]any{}}
	for i := byte(0); i < 4; i++ {
		t, rest, err := ReadTag(b)
		if err != nil || !t.Context || t.Num != i {
			return n, errors.New("COV notification: header field expected")
		}
		switch i {
		case 0:
			v, _ := BeUnsigned(t.Data)
			n.Process = uint32(v)
		case 1, 2:
			if len(t.Data) != 4 {
				return n, errShort
			}
			o := ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
			if i == 1 {
				n.Device = o
			} else {
				n.Object = o
			}
		}
		b = rest
	}
	t, b, err := ReadTag(b)
	if err != nil || !t.Open || t.Num != 4 {
		return n, errors.New("COV notification: value list expected")
	}
	for {
		t, rest, err := ReadTag(b)
		if err != nil {
			return n, err
		}
		if t.Close && t.Num == 4 {
			return n, nil
		}
		if !t.Context || t.Num != 0 {
			return n, errors.New("COV notification: property identifier expected")
		}
		p, _ := BeUnsigned(t.Data)
		t, rest, err = ReadTag(rest)
		if err == nil && t.Context && t.Num == 1 {
			t, rest, err = ReadTag(rest)
		}
		if err != nil || !t.Open || t.Num != 2 {
			return n, errors.New("COV notification: value expected")
		}
		vals, rest, err := ValuesUntilClose(rest, 2)
		if err != nil {
			return n, err
		}
		n.Values[uint32(p)] = vals
		if t, r2, err := ReadTag(rest); err == nil && t.Context && t.Num == 3 && !t.Open && !t.Close {
			rest = r2 // priority
		}
		b = rest
	}
}

// EncodeCOVNotification builds an UnconfirmedCOVNotification request.
func EncodeCOVNotification(n COVNotification, remaining uint32) ([]byte, error) {
	var e Enc
	e.CtxUnsigned(0, uint64(n.Process))
	e.CtxObjectID(1, n.Device)
	e.CtxObjectID(2, n.Object)
	e.CtxUnsigned(3, uint64(remaining))
	e.Open(4)
	for _, p := range []uint32{PropPresentValue, PropStatusFlags} {
		vals, ok := n.Values[p]
		if !ok {
			continue
		}
		e.CtxUnsigned(0, uint64(p))
		e.Open(2)
		for _, v := range vals {
			if err := e.App(v); err != nil {
				return nil, err
			}
		}
		e.Close(2)
	}
	e.Close(4)
	return e.B, nil
}

// EncodeWhoIs is a Who-Is request (clause 16.10) for one device instance.
func EncodeWhoIs(instance uint32) []byte {
	var e Enc
	e.CtxUnsigned(0, uint64(instance))
	e.CtxUnsigned(1, uint64(instance))
	return e.B
}

// IAm is a decoded I-Am request (clause 16.10).
type IAm struct {
	Device       ObjectID
	MaxAPDU      uint64
	Segmentation Enumerated
	Vendor       uint64
	// Irregular says what did not follow clause 16.10 (defaulted).
	Irregular string
}

func EncodeIAm(i IAm) []byte {
	var e Enc
	_ = e.App(i.Device)
	_ = e.App(i.MaxAPDU)
	_ = e.App(i.Segmentation)
	_ = e.App(i.Vendor)
	return e.B
}

func DecodeIAm(b []byte) (IAm, error) {
	var vals []any
	for len(b) > 0 && len(vals) < 4 {
		t, rest, err := ReadTag(b)
		if err != nil {
			return IAm{}, err
		}
		v, err := AppValue(t)
		if err != nil {
			return IAm{}, err
		}
		vals = append(vals, v)
		b = rest
	}
	// The device identifier is required; a missing or oddly typed max
	// APDU, segmentation or vendor (an old or vendor stack) is defaulted
	// (1476, no segmentation, 0) and noted in irregular.
	var i IAm
	if len(vals) == 0 {
		return IAm{}, errors.New("malformed I-Am")
	}
	var ok bool
	if i.Device, ok = vals[0].(ObjectID); !ok {
		return IAm{}, errors.New("malformed I-Am")
	}
	i.MaxAPDU, i.Segmentation = 1476, SegNone
	var odd []string
	get := func(n int, name string, set func(any) bool) {
		if n >= len(vals) {
			odd = append(odd, name+" missing")
		} else if !set(vals[n]) {
			odd = append(odd, fmt.Sprintf("%s is %T", name, vals[n]))
		}
	}
	get(1, "max APDU", func(v any) bool {
		x, ok := v.(uint64)
		if ok {
			i.MaxAPDU = x
		}
		return ok
	})
	get(2, "segmentation", func(v any) bool {
		switch x := v.(type) {
		case Enumerated:
			i.Segmentation = x
		case uint64:
			i.Segmentation = Enumerated(x)
		default:
			return false
		}
		return true
	})
	get(3, "vendor", func(v any) bool {
		x, ok := v.(uint64)
		if ok {
			i.Vendor = x
		}
		return ok
	})
	i.Irregular = strings.Join(odd, "; ")
	return i, nil
}

// Error class and code answered for a notification the IPE did not
// subscribe to: services (5), unknown-subscription (79).
const (
	ErrClassServices           = 5
	ErrCodeUnknownSubscription = 79
)
