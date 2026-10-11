package bacnet

// Request encodings and answer decodings of the services behind the
// device-management, file and alarm commands and reads (clauses 13 to 16;
// productions of clause 21): GetAlarmSummary (13.10), GetEventInformation
// (13.12), SubscribeCOVProperty (13.15), AtomicReadFile (14.1),
// AtomicWriteFile (14.2), AddListElement (15.1), WritePropertyMultiple
// (15.10), DeviceCommunicationControl (16.1), ReinitializeDevice (16.4),
// TimeSynchronization and UTCTimeSynchronization (16.7, 16.8) and
// Who-Has / I-Have (16.9).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Service choices (clause 21).
const (
	SvcGetAlarmSummary      = 3
	SvcAtomicReadFile       = 6
	SvcAtomicWriteFile      = 7
	SvcAddListElement       = 8
	SvcWritePropertyMulti   = 16
	SvcDeviceCommControl    = 17
	SvcReinitializeDevice   = 20
	SvcSubscribeCOVProperty = 28
	SvcGetEventInformation  = 29

	SvcIHave          = 1 // unconfirmed
	SvcTimeSync       = 6 // unconfirmed
	SvcWhoHas         = 7 // unconfirmed
	SvcUTCTimeSync    = 9 // unconfirmed
	ObjNotificationCl = 15
	ObjFile           = 10
	ObjDevice         = 8
	PropRecipientList = 102
)

// ---- time synchronisation ----------------------------------------------------

// EncodeTimeSync is the TimeSynchronization or UTCTimeSynchronization
// Request: a BACnetDateTime (the device's local time, or UTC).
func EncodeTimeSync(t time.Time, loc *time.Location) []byte {
	var e Enc
	e.dateTime(t, loc)
	return e.B
}

// ---- remote device management -------------------------------------------------

// DeviceCommunicationControl enable-disable values (16.1; disable (1) is
// deprecated).
var DCCStates = map[string]uint64{"enable": 0, "disable-initiation": 2}

// EncodeDCC is the DeviceCommunicationControl request; minutes 0 leaves
// the duration out (indefinite).
func EncodeDCC(minutes uint16, state uint64, password string) []byte {
	var e Enc
	if minutes > 0 {
		e.CtxUnsigned(0, uint64(minutes))
	}
	e.CtxEnum(1, state)
	if password != "" {
		e.CtxString(2, password)
	}
	return e.B
}

// ReinitStates are the reinitialized-state-of-device values (16.4).
var ReinitStates = map[string]uint64{"coldstart": 0, "warmstart": 1, "start-backup": 2, "end-backup": 3,
	"start-restore": 4, "end-restore": 5, "abort-restore": 6, "activate-changes": 7}

func EncodeReinitialize(state uint64, password string) []byte {
	var e Enc
	e.CtxEnum(0, state)
	if password != "" {
		e.CtxString(1, password)
	}
	return e.B
}

func (e *Enc) CtxEnum(num byte, v uint64) {
	c := unsignedBytes(v)
	e.Header(num, true, len(c))
	e.B = append(e.B, c...)
}

func (e *Enc) CtxString(num byte, s string) {
	e.Header(num, true, len(s)+1)
	e.B = append(e.B, 0) // UTF-8
	e.B = append(e.B, s...)
}

// ---- Who-Has / I-Have ---------------------------------------------------------

// EncodeWhoHas asks for an object by name or identifier, optionally
// within a device instance range.
func EncodeWhoHas(low, high *uint32, name string, id *ObjectID) []byte {
	var e Enc
	if low != nil && high != nil {
		e.CtxUnsigned(0, uint64(*low))
		e.CtxUnsigned(1, uint64(*high))
	}
	if id != nil {
		e.CtxObjectID(2, *id)
	} else {
		e.CtxString(3, name)
	}
	return e.B
}

type iHave struct {
	Device, Object ObjectID
	Name           string
}

func DecodeIHave(b []byte) (iHave, error) {
	var h iHave
	var vals []any
	for len(b) > 0 {
		t, rest, err := ReadTag(b)
		if err != nil {
			return h, err
		}
		v, err := AppValue(t)
		if err != nil {
			return h, err
		}
		vals = append(vals, v)
		b = rest
	}
	var ok [3]bool
	if len(vals) == 3 {
		h.Device, ok[0] = vals[0].(ObjectID)
		h.Object, ok[1] = vals[1].(ObjectID)
		h.Name, ok[2] = vals[2].(string)
	}
	if ok != [3]bool{true, true, true} {
		return h, errors.New("malformed I-Have")
	}
	return h, nil
}

// ---- files --------------------------------------------------------------------

// EncodeAtomicReadFile reads count octets (stream) or records (record
// access) from start.
func EncodeAtomicReadFile(file ObjectID, record bool, start int64, count uint64) []byte {
	var e Enc
	_ = e.App(file)
	n := byte(0)
	if record {
		n = 1
	}
	e.Open(n)
	_ = e.App(start)
	_ = e.App(count)
	e.Close(n)
	return e.B
}

// fileRead is an AtomicReadFile-ACK.
type fileRead struct {
	Eof     bool
	Record  bool
	Start   int64
	Data    []byte   // stream access
	Records [][]byte // record access
}

func DecodeAtomicReadFileAck(b []byte) (fileRead, error) {
	var f fileRead
	t, b, err := ReadTag(b)
	if err != nil || t.Context || t.Num != tagBoolean {
		return f, errors.New("AtomicReadFile-ACK: end-of-file expected")
	}
	f.Eof = t.Lvt != 0
	t, b, err = ReadTag(b)
	if err != nil || !t.Open || t.Num > 1 {
		return f, errors.New("AtomicReadFile-ACK: access method expected")
	}
	f.Record = t.Num == 1
	vals, rest, err := ValuesUntilClose(b, t.Num)
	if err != nil || len(rest) != 0 || len(vals) < 2 {
		return f, errors.New("AtomicReadFile-ACK: malformed access method")
	}
	var ok bool
	if f.Start, ok = vals[0].(int64); !ok {
		return f, errors.New("AtomicReadFile-ACK: start is not an Integer")
	}
	if !f.Record {
		if f.Data, ok = vals[1].([]byte); !ok || len(vals) != 2 {
			return f, errors.New("AtomicReadFile-ACK: file data is not an OctetString")
		}
		return f, nil
	}
	n, ok := vals[1].(uint64)
	if !ok || uint64(len(vals)-2) != n {
		return f, errors.New("AtomicReadFile-ACK: record count does not match the records")
	}
	for _, v := range vals[2:] {
		r, ok := v.([]byte)
		if !ok {
			return f, errors.New("AtomicReadFile-ACK: a record is not an OctetString")
		}
		f.Records = append(f.Records, r)
	}
	return f, nil
}

// EncodeAtomicWriteFile writes data at start (stream) or records at start
// (record access; -1 appends).
func EncodeAtomicWriteFile(file ObjectID, start int64, data []byte, records [][]byte) []byte {
	var e Enc
	_ = e.App(file)
	if records == nil {
		e.Open(0)
		_ = e.App(start)
		e.Octets(data)
		e.Close(0)
		return e.B
	}
	e.Open(1)
	_ = e.App(start)
	_ = e.App(uint64(len(records)))
	for _, r := range records {
		e.Octets(r)
	}
	e.Close(1)
	return e.B
}

func (e *Enc) Octets(b []byte) {
	e.Header(tagOctetString, false, len(b))
	e.B = append(e.B, b...)
}

// DecodeAtomicWriteFileAck is the start position or record the data was
// written at.
func DecodeAtomicWriteFileAck(b []byte) (int64, bool, error) {
	t, rest, err := ReadTag(b)
	if err != nil || !t.Context || t.Num > 1 || len(rest) != 0 || len(t.Data) == 0 || len(t.Data) > 8 {
		return 0, false, errors.New("AtomicWriteFile-ACK: a start position or record expected")
	}
	v := int64(int8(t.Data[0]))
	for _, x := range t.Data[1:] {
		v = v<<8 | int64(x)
	}
	return v, t.Num == 1, nil
}

// ---- WritePropertyMultiple ----------------------------------------------------

// PropWrite is one property value of a WriteAccessSpecification.
type PropWrite struct {
	Object   ObjectID
	Prop     uint32
	Value    any
	Priority int
}

// EncodeWritePropertyMultiple groups consecutive writes to one object.
func EncodeWritePropertyMultiple(ws []PropWrite) ([]byte, error) {
	var e Enc
	for i := 0; i < len(ws); {
		o := ws[i].Object
		e.CtxObjectID(0, o)
		e.Open(1)
		for ; i < len(ws) && ws[i].Object == o; i++ {
			e.CtxUnsigned(0, uint64(ws[i].Prop))
			e.Open(2)
			if err := e.App(ws[i].Value); err != nil {
				return nil, err
			}
			e.Close(2)
			if ws[i].Priority > 0 {
				e.CtxUnsigned(3, uint64(ws[i].Priority))
			}
		}
		e.Close(1)
	}
	return e.B, nil
}

// WPMError is the first failed write of a WritePropertyMultiple-Error
// (clause 21): the error and the object and property it failed on.
type WPMError struct {
	ErrorPDU
	Object ObjectID
	Prop   uint32
}

func (e *WPMError) Error() string {
	return fmt.Sprintf("the write of property %d of object %d:%d failed: error class %d code %d", e.Prop, e.Object.Type, e.Object.Instance, e.Class, e.Code)
}

func DecodeWPMError(b []byte) error {
	t, rest, err := ReadTag(b)
	if err != nil || !t.Open || t.Num != 0 {
		return ErrorFrom(b)
	}
	vals, rest, err := ValuesUntilClose(rest, 0)
	if err != nil || len(vals) != 2 {
		return ErrorFrom(b)
	}
	c, _ := vals[0].(Enumerated)
	d, _ := vals[1].(Enumerated)
	e := &WPMError{ErrorPDU: ErrorPDU{Class: uint32(c), Code: uint32(d)}}
	if t, rest, err = ReadTag(rest); err == nil && t.Open && t.Num == 1 {
		if t, rest, err = ReadTag(rest); err == nil && t.Context && t.Num == 0 && len(t.Data) == 4 {
			e.Object = ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
		}
		if t, _, err = ReadTag(rest); err == nil && t.Context && t.Num == 1 {
			p, _ := BeUnsigned(t.Data)
			e.Prop = uint32(p)
		}
	}
	return e
}

// ---- SubscribeCOVProperty -----------------------------------------------------

func EncodeSubscribeCOVProperty(process uint32, o ObjectID, confirmed bool, lifetime uint32, prop uint32, increment *float32) []byte {
	var e Enc
	e.CtxUnsigned(0, uint64(process))
	e.CtxObjectID(1, o)
	e.CtxBool(2, confirmed)
	e.CtxUnsigned(3, uint64(lifetime))
	e.Open(4)
	e.CtxUnsigned(0, uint64(prop))
	e.Close(4)
	if increment != nil {
		e.Header(5, true, 4)
		e.B = binary.BigEndian.AppendUint32(e.B, math.Float32bits(*increment))
	}
	return e.B
}

// ---- alarm summaries ----------------------------------------------------------

// AlarmSummary is one entry of GetAlarmSummary-ACK or
// GetEventInformation-ACK.
type AlarmSummary struct {
	Object       ObjectID
	State        uint32
	Acked        BitString  // acknowledged-transitions
	Stamps       [][]byte   // GetEventInformation: the three time stamps as encoded
	Notify       *uint32    // GetEventInformation
	Enable       *BitString // GetEventInformation
	Priorities   []uint64   // GetEventInformation
	HasEventInfo bool
}

func DecodeGetAlarmSummaryAck(b []byte) ([]AlarmSummary, error) {
	var out []AlarmSummary
	for len(b) > 0 {
		var vals [3]any
		for i := range vals {
			t, rest, err := ReadTag(b)
			if err != nil {
				return nil, err
			}
			if vals[i], err = AppValue(t); err != nil {
				return nil, err
			}
			b = rest
		}
		o, ok1 := vals[0].(ObjectID)
		s, ok2 := vals[1].(Enumerated)
		a, ok3 := vals[2].(BitString)
		if !ok1 || !ok2 || !ok3 {
			return nil, errors.New("GetAlarmSummary-ACK: object, state and transitions expected")
		}
		out = append(out, AlarmSummary{Object: o, State: uint32(s), Acked: a})
	}
	return out, nil
}

// EncodeGetEventInformation asks for the summaries after last (nil: from
// the start).
func EncodeGetEventInformation(last *ObjectID) []byte {
	if last == nil {
		return nil
	}
	var e Enc
	e.CtxObjectID(0, *last)
	return e.B
}

func DecodeGetEventInformationAck(b []byte) ([]AlarmSummary, bool, error) {
	bad := func(what string) ([]AlarmSummary, bool, error) {
		return nil, false, fmt.Errorf("GetEventInformation-ACK: %s", what)
	}
	t, b, err := ReadTag(b)
	if err != nil || !t.Open || t.Num != 0 {
		return bad("list of event summaries expected")
	}
	var out []AlarmSummary
	for {
		t, rest, err := ReadTag(b)
		if err != nil {
			return bad("truncated")
		}
		if t.Close && t.Num == 0 {
			b = rest
			break
		}
		if !t.Context || t.Num != 0 || len(t.Data) != 4 {
			return bad("object identifier expected")
		}
		s := AlarmSummary{Object: ObjectIDFrom(binary.BigEndian.Uint32(t.Data)), HasEventInfo: true}
		b = rest
		if t, b, err = ReadTag(b); err != nil || !t.Context || t.Num != 1 {
			return bad("event state expected")
		}
		v, _ := BeUnsigned(t.Data)
		s.State = uint32(v)
		if t, b, err = ReadTag(b); err != nil || !t.Context || t.Num != 2 {
			return bad("acknowledged transitions expected")
		}
		if s.Acked, err = bits(t.Data); err != nil {
			return bad("acknowledged transitions")
		}
		if t, b, err = ReadTag(b); err != nil || !t.Open || t.Num != 3 {
			return bad("event time stamps expected")
		}
		for {
			t, rest, err := ReadTag(b)
			if err != nil {
				return bad("truncated time stamps")
			}
			if t.Close && t.Num == 3 {
				b = rest
				break
			}
			if !t.Context {
				return bad("time stamp choice expected")
			}
			start := b
			if t.Open {
				if rest, err = SkipConstructed(rest, t.Num); err != nil {
					return bad("time stamp")
				}
			}
			s.Stamps = append(s.Stamps, start[:len(start)-len(rest)])
			b = rest
		}
		if len(s.Stamps) != 3 {
			return bad("three event time stamps expected")
		}
		if t, b, err = ReadTag(b); err != nil || !t.Context || t.Num != 4 {
			return bad("notify type expected")
		}
		v, _ = BeUnsigned(t.Data)
		nt := uint32(v)
		s.Notify = &nt
		if t, b, err = ReadTag(b); err != nil || !t.Context || t.Num != 5 {
			return bad("event enable expected")
		}
		en, err := bits(t.Data)
		if err != nil {
			return bad("event enable")
		}
		s.Enable = &en
		if t, b, err = ReadTag(b); err != nil || !t.Open || t.Num != 6 {
			return bad("event priorities expected")
		}
		vals, rest, err := ValuesUntilClose(b, 6)
		if err != nil || len(vals) != 3 {
			return bad("three event priorities expected")
		}
		for _, p := range vals {
			u, _ := p.(uint64)
			s.Priorities = append(s.Priorities, u)
		}
		b = rest
		out = append(out, s)
	}
	t, _, err = ReadTag(b)
	if err != nil || !t.Context || t.Num != 1 || len(t.Data) != 1 {
		return bad("more-events expected")
	}
	return out, t.Data[0] != 0, nil
}

// ---- notification class recipients --------------------------------------------

// Destination is a BACnetDestination (clause 21) naming the IPE.
type Destination struct {
	Days      BitString // valid-days, 7 bits from Monday
	From, To  [4]byte   // Time octets
	Device    *ObjectID // recipient: device, or
	Net       uint16    // address: network (0 local) and MAC
	MAC       []byte
	Process   uint32
	Confirmed bool
	Trans     BitString // to-offnormal, to-fault, to-normal
}

func AllWeek() BitString {
	return BitString{Len: 7, Bits: []bool{true, true, true, true, true, true, true}}
}

func AllTransitions() BitString { return BitString{Len: 3, Bits: []bool{true, true, true}} }

// EncodeDestination is the list element of AddListElement on
// Recipient_List.
func EncodeDestination(d Destination) []byte {
	var e Enc
	_ = e.App(d.Days)
	e.Header(TagTime, false, 4)
	e.B = append(e.B, d.From[:]...)
	e.Header(TagTime, false, 4)
	e.B = append(e.B, d.To[:]...)
	if d.Device != nil {
		e.CtxObjectID(0, *d.Device)
	} else {
		e.Open(1)
		_ = e.App(uint64(d.Net))
		e.Octets(d.MAC)
		e.Close(1)
	}
	_ = e.App(uint64(d.Process))
	_ = e.App(d.Confirmed)
	_ = e.App(d.Trans)
	return e.B
}

// DecodeDestinations reads the values of Recipient_List (as
// ValuesUntilClose left them flattened, re-read from raw octets).
func DecodeDestinations(b []byte) ([]Destination, error) {
	var out []Destination
	for len(b) > 0 {
		var d Destination
		v, err := nextApp(&b)
		if err != nil {
			return nil, err
		}
		if d.Days, err = asBits(v); err != nil {
			return nil, err
		}
		for _, f := range []*[4]byte{&d.From, &d.To} {
			t, rest, err := ReadTag(b)
			if err != nil || t.Context || t.Num != TagTime || len(t.Data) != 4 {
				return nil, errors.New("destination: time expected")
			}
			copy(f[:], t.Data)
			b = rest
		}
		t, rest, err := ReadTag(b)
		if err != nil || !t.Context {
			return nil, errors.New("destination: recipient expected")
		}
		switch {
		case t.Num == 0 && len(t.Data) == 4:
			o := ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
			d.Device, b = &o, rest
		case t.Num == 1 && t.Open:
			vals, r2, err := ValuesUntilClose(rest, 1)
			if err != nil || len(vals) != 2 {
				return nil, errors.New("destination: address expected")
			}
			n, _ := vals[0].(uint64)
			d.Net = uint16(n)
			d.MAC, _ = vals[1].([]byte)
			b = r2
		default:
			return nil, errors.New("destination: recipient expected")
		}
		if v, err = nextApp(&b); err != nil {
			return nil, err
		}
		p, _ := v.(uint64)
		d.Process = uint32(p)
		if v, err = nextApp(&b); err != nil {
			return nil, err
		}
		d.Confirmed, _ = v.(bool)
		if v, err = nextApp(&b); err != nil {
			return nil, err
		}
		if d.Trans, err = asBits(v); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func nextApp(b *[]byte) (any, error) {
	t, rest, err := ReadTag(*b)
	if err != nil {
		return nil, err
	}
	*b = rest
	return AppValue(t)
}

func asBits(v any) (BitString, error) {
	b, ok := v.(BitString)
	if !ok {
		return b, errors.New("bit string expected")
	}
	return b, nil
}

// EncodeAddListElement adds elements (already encoded) to a list property.
func EncodeAddListElement(o ObjectID, prop uint32, elements []byte) []byte {
	var e Enc
	e.CtxObjectID(0, o)
	e.CtxUnsigned(1, uint64(prop))
	e.Open(3)
	e.B = append(e.B, elements...)
	e.Close(3)
	return e.B
}

// encodeReadPropertyRaw is ReadProperty; the ACK's value is taken raw
// (rawPropertyValue) for constructed types such as Recipient_List.
func RawPropertyValue(b []byte) ([]byte, error) {
	for i := 0; i < 2; i++ {
		t, rest, err := ReadTag(b)
		if err != nil || !t.Context {
			return nil, errors.New("ReadProperty-ACK: header expected")
		}
		b = rest
	}
	t, rest, err := ReadTag(b)
	if err == nil && t.Context && t.Num == 2 && !t.Open {
		t, rest, err = ReadTag(rest)
	}
	if err != nil || !t.Open || t.Num != 3 {
		return nil, errors.New("ReadProperty-ACK without a value")
	}
	raw, _, err := RawConstructed(rest, 3)
	return raw, err
}
