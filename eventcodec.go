package bacnet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"time"
)

const (
	SvcAcknowledgeAlarm = 0 // confirmed
)

var (
	EventStates = []string{"normal", "fault", "offnormal", "high-limit", "low-limit", "life-safety-alarm"}
)

func EnumName(names []string, v uint32) string {
	if int(v) < len(names) {
		return names[v]
	}
	return strconv.Itoa(int(v))
}

// EventNotification is a decoded event notification (the request of
// 13.8 and 13.9, clause 21). stamp is the BACnetTimeStamp as encoded
// (inside its opening and closing tag 3), kept to echo in AcknowledgeAlarm.
type EventNotification struct {
	Process     uint32
	Device      ObjectID
	Object      ObjectID
	Stamp       []byte
	Class       uint64
	Priority    uint64
	EventType   uint32
	Text        string
	Notify      uint32
	ACKRequired *bool
	From        *uint32
	To          uint32
}

// RawConstructed returns the content between an opening tag and its
// closing tag, and what follows.
func RawConstructed(b []byte, num byte) ([]byte, []byte, error) {
	rest, err := SkipConstructed(b, num)
	if err != nil {
		return nil, nil, err
	}
	return b[:len(b)-len(rest)-1-extTagLen(num)], rest, nil
}

func extTagLen(num byte) int {
	if num > 14 {
		return 1
	}
	return 0
}

func DecodeEventNotification(b []byte) (EventNotification, error) {
	var n EventNotification
	next := func(num byte, optional bool) (Tag, bool, error) {
		if len(b) == 0 {
			if optional {
				return Tag{}, false, nil
			}
			return Tag{}, false, fmt.Errorf("event notification: context tag %d missing", num)
		}
		t, rest, err := ReadTag(b)
		if err != nil {
			return t, false, err
		}
		if !t.Context || t.Num != num {
			if optional {
				return t, false, nil
			}
			return t, false, fmt.Errorf("event notification: context tag %d expected", num)
		}
		b = rest
		return t, true, nil
	}
	u := func(t Tag) uint64 { v, _ := BeUnsigned(t.Data); return v }
	oid := func(t Tag) (ObjectID, error) {
		if len(t.Data) != 4 {
			return ObjectID{}, errShort
		}
		return ObjectIDFrom(binary.BigEndian.Uint32(t.Data)), nil
	}
	t, _, err := next(0, false)
	if err != nil {
		return n, err
	}
	n.Process = uint32(u(t))
	if t, _, err = next(1, false); err != nil {
		return n, err
	}
	if n.Device, err = oid(t); err != nil {
		return n, err
	}
	if t, _, err = next(2, false); err != nil {
		return n, err
	}
	if n.Object, err = oid(t); err != nil {
		return n, err
	}
	if t, _, err = next(3, false); err != nil || !t.Open {
		return n, errors.New("event notification: timestamp expected")
	}
	if n.Stamp, b, err = RawConstructed(b, 3); err != nil {
		return n, err
	}
	for _, f := range []struct {
		num byte
		v   *uint64
	}{{4, &n.Class}, {5, &n.Priority}} {
		if t, _, err = next(f.num, false); err != nil {
			return n, err
		}
		*f.v = u(t)
	}
	if t, _, err = next(6, false); err != nil {
		return n, err
	}
	n.EventType = uint32(u(t))
	if t, ok, err := next(7, true); err != nil {
		return n, err
	} else if ok {
		v, err := AppValue(Tag{Num: TagCharString, Data: t.Data})
		if err == nil {
			n.Text, _ = v.(string)
		}
	}
	if t, _, err = next(8, false); err != nil {
		return n, err
	}
	n.Notify = uint32(u(t))
	if t, ok, err := next(9, true); err != nil {
		return n, err
	} else if ok {
		v := len(t.Data) == 1 && t.Data[0] != 0
		n.ACKRequired = &v
	}
	if t, ok, err := next(10, true); err != nil {
		return n, err
	} else if ok {
		v := uint32(u(t))
		n.From = &v
	}
	if n.Notify != 2 { // ack-notification has no to-state
		if t, _, err = next(11, false); err != nil {
			return n, err
		}
		n.To = uint32(u(t))
	} else if t, ok, _ := next(11, true); ok {
		n.To = uint32(u(t))
	}
	// event-values [12] are not decoded.
	return n, nil
}

// StampValue turns a BACnetTimeStamp into a reading value.
func StampValue(raw []byte, loc *time.Location) any {
	t, rest, err := ReadTag(raw)
	if err != nil || !t.Context {
		return nil
	}
	switch t.Num {
	case 0:
		return map[string]any{"time": timeString(t.Data)}
	case 1:
		v, _ := BeUnsigned(t.Data)
		return map[string]any{"sequenceNumber": v}
	case 2:
		d, r2, err := ReadTag(rest)
		if err != nil {
			return nil
		}
		tm, _, err := ReadTag(r2)
		if err != nil {
			return nil
		}
		at, err := DateTimeFrom(d.Data, tm.Data, loc)
		if err != nil {
			return nil
		}
		return map[string]any{"dateTime": at.UTC().Format(time.RFC3339Nano)}
	}
	return nil
}

func timeString(d []byte) string {
	if len(d) != 4 {
		return ""
	}
	return fmt.Sprintf("%02d:%02d:%02d.%02d", d[0], d[1], d[2], d[3])
}

// EncodeAcknowledgeAlarm is the AcknowledgeAlarm request (13.5): stamp is
// the event's BACnetTimeStamp as the notification gave it; the time of
// acknowledgment is a date and time with an unspecified day of week.
func EncodeAcknowledgeAlarm(process uint32, o ObjectID, state uint32, stamp []byte, source string, at time.Time) []byte {
	var e Enc
	e.CtxUnsigned(0, uint64(process))
	e.CtxObjectID(1, o)
	e.Header(2, true, len(unsignedBytes(uint64(state))))
	e.B = append(e.B, unsignedBytes(uint64(state))...)
	e.Open(3)
	e.B = append(e.B, stamp...)
	e.Close(3)
	e.Header(4, true, len(source)+1)
	e.B = append(e.B, 0)
	e.B = append(e.B, source...)
	e.Open(5)
	e.Open(2)
	e.B = append(e.B, TagDate<<4|4, byte(at.Year()-1900), byte(at.Month()), byte(at.Day()), 0xff)
	e.B = append(e.B, TagTime<<4|4, byte(at.Hour()), byte(at.Minute()), byte(at.Second()), byte(at.Nanosecond()/10_000_000))
	e.Close(2)
	e.Close(5)
	return e.B
}

// SequenceStamp is a BACnetTimeStamp of the sequence-number choice.
func SequenceStamp(seq uint64) []byte {
	var e Enc
	e.CtxUnsigned(1, seq)
	return e.B
}
