package bacnet

// ReadRange (clause 15.8) and the log records of a trend log's log-buffer
// (clause 12.25, BACnetLogRecord in clause 21).

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
)

// Range kinds of a ReadRange request: the context tag of the choice.
const (
	RangeAll        = 0 // no range: every item
	RangeByPosition = 3
	RangeBySequence = 6
	RangeByTime     = 7
)

// ReadRange is the range of a ReadRange request. ref is the reference
// index (by position) or sequence number; at is the reference time (by
// time, in the device's time zone loc); a negative count reads backwards.
type ReadRange struct {
	Kind  byte
	Ref   uint64
	At    time.Time
	Loc   *time.Location
	Count int32
}

// EncodeReadRange is the ReadRange request.
func EncodeReadRange(o ObjectID, prop uint32, r ReadRange) []byte {
	var e Enc
	e.CtxObjectID(0, o)
	e.CtxUnsigned(1, uint64(prop))
	switch r.Kind {
	case RangeByPosition, RangeBySequence:
		e.Open(r.Kind)
		_ = e.App(r.Ref)
		_ = e.App(int64(r.Count))
		e.Close(r.Kind)
	case RangeByTime:
		e.Open(r.Kind)
		e.dateTime(r.At, r.Loc)
		_ = e.App(int64(r.Count))
		e.Close(r.Kind)
	}
	return e.B
}

// dateTime writes a BACnetDateTime: an application Date and Time (clauses
// 20.2.12 and 20.2.13) in the device's local time.
func (e *Enc) dateTime(t time.Time, loc *time.Location) {
	if loc == nil {
		loc = time.UTC
	}
	t = t.In(loc)
	dow := byte(t.Weekday())
	if dow == 0 {
		dow = 7 // Monday is 1, Sunday 7
	}
	e.Header(TagDate, false, 4)
	e.B = append(e.B, byte(t.Year()-1900), byte(t.Month()), byte(t.Day()), dow)
	e.Header(TagTime, false, 4)
	e.B = append(e.B, byte(t.Hour()), byte(t.Minute()), byte(t.Second()), byte(t.Nanosecond()/1e7))
}

// DateTimeFrom decodes an application Date and Time. Unspecified (0xff)
// fields are taken as zero; an unspecified year is an error.
func DateTimeFrom(d, t []byte, loc *time.Location) (time.Time, error) {
	if len(d) != 4 || len(t) != 4 || d[0] == 0xff {
		return time.Time{}, errors.New("log record: date and time expected")
	}
	f := func(b byte, def int) int {
		if b == 0xff {
			return def
		}
		return int(b)
	}
	if loc == nil {
		loc = time.UTC
	}
	return time.Date(1900+int(d[0]), time.Month(f(d[1], 1)), f(d[2], 1),
		f(t[0], 0), f(t[1], 0), f(t[2], 0), f(t[3], 0)*1e7, loc), nil
}

// bits decodes the content octets of a bit string (unused-bits octet
// first).
func bits(d []byte) (BitString, error) {
	v, err := AppValue(Tag{Num: tagBitString, Lvt: uint32(len(d)), Data: d})
	if err != nil {
		return BitString{}, err
	}
	return v.(BitString), nil
}

// LogRecord is one record of a log buffer. kind names the log-datum
// choice: status, boolean, real, enumerated, unsigned, signed, bitstring,
// null, failure, time-change or any; value is its Go value (a BitString for
// status, bool, float32, Enumerated, uint64, int64, BitString, nil, an *ErrorPDU
// or float32 seconds for time-change; any is left out).
type LogRecord struct {
	At    time.Time
	Kind  string
	Value any
	Flags *BitString // status-flags, when the record has them
}

var datumKinds = [...]string{"status", "boolean", "real", "enumerated", "unsigned", "signed", "bitstring", "null", "failure", "time-change", "any"}

// rangeResult is a decoded ReadRange-ACK.
type rangeResult struct {
	FirstItem, LastItem, MoreItems bool
	Count                          uint64
	FirstSeq                       uint64
	HasFirstSeq                    bool
	Records                        []LogRecord
}

func DecodeReadRangeAck(b []byte, loc *time.Location) (rangeResult, error) {
	var r rangeResult
	next := func() (Tag, error) {
		t, rest, err := ReadTag(b)
		if err == nil {
			b = rest
		}
		return t, err
	}
	t, err := next()
	if err != nil || !t.Context || t.Num != 0 {
		return r, errors.New("ReadRange-ACK without an object identifier")
	}
	if t, err = next(); err != nil || !t.Context || t.Num != 1 {
		return r, errors.New("ReadRange-ACK without a property identifier")
	}
	if t, err = next(); err == nil && t.Context && t.Num == 2 && !t.Open {
		t, err = next() // array index
	}
	if err != nil || !t.Context || t.Num != 3 {
		return r, errors.New("ReadRange-ACK without result flags")
	}
	fl, err := bits(t.Data)
	if err != nil {
		return r, err
	}
	at := func(i int) bool { return i < len(fl.Bits) && fl.Bits[i] }
	r.FirstItem, r.LastItem, r.MoreItems = at(0), at(1), at(2)
	if t, err = next(); err != nil || !t.Context || t.Num != 4 {
		return r, errors.New("ReadRange-ACK without an item count")
	}
	if r.Count, err = BeUnsigned(t.Data); err != nil && len(t.Data) != 0 {
		return r, err
	}
	if t, err = next(); err != nil || !t.Open || t.Num != 5 {
		return r, errors.New("ReadRange-ACK without item data")
	}
	for {
		t, err := next()
		if err != nil {
			return r, err
		}
		if t.Close && t.Num == 5 {
			break
		}
		if !t.Open || t.Num != 0 {
			return r, errors.New("log record: timestamp expected")
		}
		rec, rest, err := DecodeLogRecord(b, loc)
		if err != nil {
			return r, err
		}
		b = rest
		r.Records = append(r.Records, rec)
	}
	if len(b) > 0 {
		t, err := next()
		if err != nil || !t.Context || t.Num != 6 {
			return r, errors.New("ReadRange-ACK: first sequence number expected")
		}
		if r.FirstSeq, err = BeUnsigned(t.Data); err != nil {
			return r, err
		}
		r.HasFirstSeq = true
	}
	if uint64(len(r.Records)) != r.Count {
		return r, fmt.Errorf("ReadRange-ACK: item count %d but %d records", r.Count, len(r.Records))
	}
	return r, nil
}

// DecodeLogRecord decodes a BACnetLogRecord after its timestamp's opening
// Tag.
func DecodeLogRecord(b []byte, loc *time.Location) (LogRecord, []byte, error) {
	var rec LogRecord
	d, b, err := ReadTag(b)
	if err != nil || d.Context || d.Num != TagDate {
		return rec, nil, errors.New("log record: date expected")
	}
	tm, b, err := ReadTag(b)
	if err != nil || tm.Context || tm.Num != TagTime {
		return rec, nil, errors.New("log record: time expected")
	}
	if rec.At, err = DateTimeFrom(d.Data, tm.Data, loc); err != nil {
		return rec, nil, err
	}
	t, b, err := ReadTag(b)
	if err != nil || !t.Close || t.Num != 0 {
		return rec, nil, errors.New("log record: end of timestamp expected")
	}
	if t, b, err = ReadTag(b); err != nil || !t.Open || t.Num != 1 {
		return rec, nil, errors.New("log record: log datum expected")
	}
	t, b, err = ReadTag(b)
	if err != nil || !t.Context || int(t.Num) >= len(datumKinds) {
		return rec, nil, errors.New("log record: unknown log datum")
	}
	rec.Kind = datumKinds[t.Num]
	switch {
	case t.Open && t.Num == 8: // failure: error class and code
		var vals []any
		if vals, b, err = ValuesUntilClose(b, 8); err != nil {
			return rec, nil, err
		}
		e := &ErrorPDU{}
		if len(vals) == 2 {
			c, _ := vals[0].(Enumerated)
			k, _ := vals[1].(Enumerated)
			e.Class, e.Code = uint32(c), uint32(k)
		}
		rec.Value = e
	case t.Open && t.Num == 10: // any value: skipped
		if b, err = SkipConstructed(b, 10); err != nil {
			return rec, nil, err
		}
	case t.Open:
		return rec, nil, errors.New("log record: malformed log datum")
	default:
		if rec.Value, err = datumValue(t); err != nil {
			return rec, nil, err
		}
	}
	if t, b, err = ReadTag(b); err != nil || !t.Close || t.Num != 1 {
		return rec, nil, errors.New("log record: end of log datum expected")
	}
	if len(b) > 0 {
		if t, rest, err := ReadTag(b); err == nil && t.Context && !t.Open && !t.Close && t.Num == 2 {
			fl, err := bits(t.Data)
			if err != nil {
				return rec, nil, err
			}
			rec.Flags, b = &fl, rest
		}
	}
	return rec, b, nil
}

// datumValue decodes a primitive log datum by its context tag.
func datumValue(t Tag) (any, error) {
	d := t.Data
	switch t.Num {
	case 0, 6: // log-status, bitstring
		return bits(d)
	case 1:
		if len(d) != 1 {
			return nil, errShort
		}
		return d[0] != 0, nil
	case 2, 9: // real, time-change
		if len(d) != 4 {
			return nil, errShort
		}
		return math.Float32frombits(binary.BigEndian.Uint32(d)), nil
	case 3:
		v, err := BeUnsigned(d)
		return Enumerated(v), err
	case 4:
		return BeUnsigned(d)
	case 5:
		return AppValue(Tag{Num: TagSigned, Lvt: uint32(len(d)), Data: d})
	case 7:
		return nil, nil
	}
	return nil, fmt.Errorf("log record: log datum %d", t.Num)
}

// EncodeLogRecord builds a BACnetLogRecord (for tests and the simulator).
func EncodeLogRecord(r LogRecord, loc *time.Location) ([]byte, error) {
	var e Enc
	e.Open(0)
	e.dateTime(r.At, loc)
	e.Close(0)
	e.Open(1)
	num := byte(len(datumKinds))
	for i, k := range datumKinds {
		if k == r.Kind {
			num = byte(i)
		}
	}
	prim := func(content []byte) {
		e.Header(num, true, len(content))
		e.B = append(e.B, content...)
	}
	switch x := r.Value.(type) {
	case nil:
		prim(nil)
	case bool:
		if x {
			prim([]byte{1})
		} else {
			prim([]byte{0})
		}
	case float32:
		prim(binary.BigEndian.AppendUint32(nil, math.Float32bits(x)))
	case Enumerated:
		prim(unsignedBytes(uint64(x)))
	case uint64:
		prim(unsignedBytes(x))
	case int64:
		prim(SignedBytes(x))
	case BitString:
		prim(BitContent(x))
	case *ErrorPDU:
		e.Open(num)
		_ = e.App(Enumerated(x.Class))
		_ = e.App(Enumerated(x.Code))
		e.Close(num)
	default:
		return nil, fmt.Errorf("no log datum for %T", r.Value)
	}
	if num >= byte(len(datumKinds)) {
		return nil, fmt.Errorf("unknown log datum %q", r.Kind)
	}
	e.Close(1)
	if r.Flags != nil {
		c := BitContent(*r.Flags)
		e.Header(2, true, len(c))
		e.B = append(e.B, c...)
	}
	return e.B, nil
}

// BitContent is a bit string's content octets.
func BitContent(x BitString) []byte {
	var a Enc
	_ = a.App(x)
	t, _, _ := ReadTag(a.B)
	return t.Data
}

// ReadRange reads items of a list property (a log buffer).
func (c *Client) ReadRange(ctx context.Context, t Target, o ObjectID, prop uint32, r ReadRange) (rangeResult, error) {
	a, err := c.Request(ctx, t, SvcReadRange, EncodeReadRange(o, prop, r))
	if err != nil {
		return rangeResult{}, err
	}
	if a.Typ != PDUComplexACK {
		return rangeResult{}, errors.New("ReadRange was not answered with a Complex-ACK")
	}
	return DecodeReadRangeAck(a.Data, r.Loc)
}

// Sequence numbers of log records count 1 to 2^32-1 and then start again
// at 1 (12.25.16).
const SeqMax = 1<<32 - 1

func SeqNext(s uint64) uint64 {
	if s >= SeqMax {
		return 1
	}
	return s + 1
}

// SeqAdd is s advanced by n, wrapping after 2^32-1 to 1.
func SeqAdd(s, n uint64) uint64 {
	if s == 0 {
		return n
	}
	return (s-1+n)%SeqMax + 1
}
