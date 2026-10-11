package bacnet

// Exact encodings from ASHRAE 135-2024 Annex F (APDU encoding examples)
// and Annex AB.2.17 (BVLC-SC examples), used as test vectors for the
// codec. Where Annex F itself is inconsistent (F- notes, PROVENANCE.md),
// the octets that the encoding rules of clause 20 give are used and the
// note says so.

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func hx(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func eqHex(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s:\n got %X\nwant %X", what, got, want)
	}
}

// Covers: SIG-IPE-1970
func TestAnnexFObjectAccessVectors(t *testing.T) {
	ai := func(i uint32) ObjectID { return ObjectID{Type: AnalogInput, Instance: i} }
	t.Run("F.3.5 ReadProperty request and ACK", func(t *testing.T) {
		req := confirmedWith(1, 0, SvcReadProperty, EncodeReadProperty(ai(5), PropPresentValue))
		eqHex(t, "request", req, hx(t, "00 00 01 0C 0C 00000005 19 55"))
		r, err := DecodeReadPropertyAck(hx(t, "0C 00000005 19 55 3E 44 4290999A 3F"))
		if err != nil || r.Object != ai(5) || r.Prop != PropPresentValue || len(r.Values) != 1 || r.Values[0] != float32(72.3) {
			t.Fatalf("ack = %+v, %v", r, err)
		}
	})
	t.Run("F.3.7 ReadPropertyMultiple example 1", func(t *testing.T) {
		req := EncodeReadPropertyMultiple([]PropRef{{ai(16), PropPresentValue}, {ai(16), 103}})
		eqHex(t, "request", req, hx(t, "0C 00000010 1E 09 55 09 67 1F"))
		rs, err := DecodeReadPropertyMultipleAck(hx(t, "0C 00000010 1E 29 55 4E 44 4290999A 4F 29 67 4E 91 00 4F 1F"))
		if err != nil || len(rs) != 2 || rs[0].Values[0] != float32(72.3) || rs[1].Values[0] != Enumerated(0) {
			t.Fatalf("ack = %+v, %v", rs, err)
		}
	})
	t.Run("F.3.7 ReadPropertyMultiple example 2 with a property access error", func(t *testing.T) {
		req := EncodeReadPropertyMultiple([]PropRef{{ai(33), PropPresentValue}, {ai(50), PropPresentValue}, {ai(35), PropPresentValue}})
		eqHex(t, "request", req, hx(t, "0C 00000021 1E 09 55 1F 0C 00000032 1E 09 55 1F 0C 00000023 1E 09 55 1F"))
		rs, err := DecodeReadPropertyMultipleAck(hx(t, `0C 00000021 1E 29 55 4E 44 42293333 4F 1F
			0C 00000032 1E 29 55 5E 91 01 91 1F 5F 1F
			0C 00000023 1E 29 55 4E 44 43D9D99A 4F 1F`))
		if err != nil || len(rs) != 3 {
			t.Fatalf("ack = %+v, %v", rs, err)
		}
		var e *ErrorPDU
		if rs[0].Values[0] != float32(42.3) || !errors.As(rs[1].Err, &e) || e.Class != 1 || e.Code != 31 || rs[2].Values[0] != float32(435.7) {
			t.Fatalf("results = %+v (error %v)", rs, rs[1].Err)
		}
	})
	t.Run("F.3.12 ReadPropertyMultiple ACK with an empty result list", func(t *testing.T) {
		// Annex F prints X'55' labelled 80 (OPTIONAL); OPTIONAL is 80,
		// X'50' (F-951). The ACK has no results.
		eqHex(t, "request", EncodeReadPropertyMultiple([]PropRef{{ai(19), 80}}), hx(t, "0C 00000013 1E 09 50 1F"))
		rs, err := DecodeReadPropertyMultipleAck(hx(t, "0C 00000013 1E 1F"))
		if err != nil || len(rs) != 0 {
			t.Fatalf("ack = %+v, %v", rs, err)
		}
	})
	t.Run("F.3.9 WriteProperty", func(t *testing.T) {
		b, err := EncodeWriteProperty(ObjectID{Type: AnalogValue, Instance: 1}, PropPresentValue, float32(180), 0)
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "request", confirmedWith(0x59, 4, SvcWriteProperty, b), hx(t, "00 04 59 0F 0C 00800001 19 55 3E 44 43340000 3F"))
		a, err := ParseAPDU(hx(t, "20 59 0F"))
		if err != nil || a.Typ != PDUSimpleACK || a.InvokeID != 0x59 || a.Service != SvcWriteProperty {
			t.Fatalf("simple ack = %+v, %v", a, err)
		}
	})
	t.Run("F.3.4 Error-PDU", func(t *testing.T) {
		a, err := ParseAPDU(hx(t, "50 58 0B 91 01 91 17"))
		if err != nil || a.Typ != PDUError || a.InvokeID != 0x58 || a.Service != 11 {
			t.Fatalf("apdu = %+v, %v", a, err)
		}
		var e *ErrorPDU
		if !errors.As(ErrorFrom(a.Data), &e) || e.Class != 1 || e.Code != 23 {
			t.Fatalf("error = %v", ErrorFrom(a.Data))
		}
		eqHex(t, "errorAPDU", ErrorAPDU(0x58, 11, 1, 23), hx(t, "50 58 0B 91 01 91 17"))
	})
	t.Run("F.3.8 ReadRange by time and its ACK", func(t *testing.T) {
		tl := ObjectID{Type: TrendLog, Instance: 1}
		at := time.Date(1998, 3, 23, 19, 52, 34, 0, time.UTC)
		req := EncodeReadRange(tl, PropLogBuffer, ReadRange{Kind: RangeByTime, At: at, Loc: time.UTC, Count: 4})
		eqHex(t, "request", req, hx(t, "0C 05000001 19 83 7E A4 62031701 B4 13342200 31 04 7F"))
		r, err := DecodeReadRangeAck(hx(t, `0C 05000001 19 83 3A 05C0 49 02 5E
			0E A4 62031701 B4 13361B00 0F 1E 2C 41900000 1F 2A 0400
			0E A4 62031701 B4 13381B00 0F 1E 2C 4190CCCD 1F 2A 0400
			5F 6B 013561`), time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		if !r.FirstItem || !r.LastItem || r.MoreItems || r.Count != 2 || !r.HasFirstSeq || r.FirstSeq != 79201 || len(r.Records) != 2 {
			t.Fatalf("result = %+v", r)
		}
		if !r.Records[0].At.Equal(time.Date(1998, 3, 23, 19, 54, 27, 0, time.UTC)) || r.Records[1].Value != float32(18.1) {
			t.Fatalf("records = %+v", r.Records)
		}
	})
}

// ConfirmedWith builds an unsegmented, SA=0 Confirmed-Request header as
// Annex F prints it (for comparison with the examples; the IPE itself
// always sets SA and states 64 segments of 1476 octets).
func confirmedWith(id, maxCode, svc byte, data []byte) []byte {
	return append([]byte{0x00, maxCode, id, svc}, data...)
}

// Covers: SIG-IPE-1971
func TestAnnexFCOVAndDiscoveryVectors(t *testing.T) {
	t.Run("F.1.10 SubscribeCOV", func(t *testing.T) {
		b := encodeSubscribeCOV(18, ObjectID{Type: AnalogInput, Instance: 10}, true, 0)
		eqHex(t, "request", confirmedWith(0x0f, 2, SvcSubscribeCOV, b), hx(t, "00 02 0F 05 09 12 1C 0000000A 29 01 39 00"))
	})
	cov := hx(t, "09 12 1C 02000004 2C 0000000A 39 00 4E 09 55 2E 44 42820000 2F 09 6F 2E 82 0400 2F 4F")
	check := func(t *testing.T, n COVNotification, err error) {
		t.Helper()
		if err != nil || n.Process != 18 || n.Device != (ObjectID{Type: 8, Instance: 4}) || n.Object != (ObjectID{Type: 0, Instance: 10}) {
			t.Fatalf("notification = %+v, %v", n, err)
		}
		if n.Values[PropPresentValue][0] != float32(65) {
			t.Fatalf("present-value = %v", n.Values[PropPresentValue])
		}
		bs, _ := n.Values[PropStatusFlags][0].(BitString)
		if bs.Len != 4 || bs.Bits[0] || bs.Bits[1] || bs.Bits[2] || bs.Bits[3] {
			t.Fatalf("status-flags = %+v", bs)
		}
	}
	t.Run("F.1.2 ConfirmedCOVNotification", func(t *testing.T) {
		a, err := ParseAPDU(append(hx(t, "00 02 0F 01"), cov...))
		if err != nil || a.Typ != PDUConfirmed || a.Service != SvcConfirmedCOV || a.MaxResp != 206 {
			t.Fatalf("apdu = %+v, %v", a, err)
		}
		n, err := DecodeCOVNotification(a.Data)
		check(t, n, err)
	})
	t.Run("F.1.3 UnconfirmedCOVNotification", func(t *testing.T) {
		a, err := ParseAPDU(append(hx(t, "10 02"), cov...))
		if err != nil || a.Typ != PDUUnconfirmed || a.Service != SvcUnconfirmedCOV {
			t.Fatalf("apdu = %+v, %v", a, err)
		}
		n, err := DecodeCOVNotification(a.Data)
		check(t, n, err)
		// Our encoder gives the same octets for the same notification.
		got, err := EncodeCOVNotification(n, 0)
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "encoded", got, cov)
	})
	t.Run("F.4.9 Who-Is and I-Am", func(t *testing.T) {
		eqHex(t, "Who-Is 3..3", EncodeWhoIs(3), hx(t, "09 03 19 03"))
		for _, v := range []struct {
			hex  string
			want IAm
		}{
			{"C4 02000003 22 0400 91 03 21 63", IAm{ObjectID{8, 3}, 1024, SegNone, 99, ""}},
			{"C4 02000001 22 01E0 91 01 21 63", IAm{ObjectID{8, 1}, 480, SegTransmit, 99, ""}},
			{"C4 02000002 21 CE 91 02 21 21", IAm{ObjectID{8, 2}, 206, SegReceive, 33, ""}},
			{"C4 02000004 21 80 91 00 21 42", IAm{ObjectID{8, 4}, 128, SegBoth, 66, ""}},
		} {
			got, err := DecodeIAm(hx(t, v.hex))
			if err != nil || got != v.want {
				t.Fatalf("I-Am %s = %+v, %v", v.hex, got, err)
			}
			eqHex(t, "I-Am encoding", EncodeIAm(v.want), hx(t, v.hex))
		}
	})
}

// Covers: SIG-IPE-1972
func TestClause21ReasonsAndErrorCodes(t *testing.T) {
	// BACnetRejectReason, BACnetAbortReason and BACnetErrorCode values the
	// IPE sends or checks, from clause 21 of the 2024 edition.
	for _, v := range []struct {
		name      string
		got, want int
	}{
		{"reject unrecognized-service", RejectUnrecognizedService, 9},
		{"abort other", AbortOther, 0},
		{"abort buffer-overflow", AbortBufferOverflow, 1},
		{"abort invalid-apdu-in-this-state", abortInvalidAPDU, 2},
		{"abort segmentation-not-supported", AbortSegNotSupp, 4},
		{"error class services", 5, 5},
		{"error code unknown-subscription", ErrCodeUnknownSubscription, 79},
		{"error class communication", ErrClassCommunication, 7},
		{"header-not-understood", ErrCodeHeaderNotUnderstood, 146},
		{"node-duplicate-vmac", ErrCodeNodeDuplicateVMAC, 151},
		{"optional-functionality-not-supported", ErrCodeOptionalNotSupported, 45},
		{"bvlc-function-unknown", ErrCodeBVLCFunctionUnknown, 143},
		{"message-incomplete", errCodeMessageIncomplete, 147},
		{"payload-expected", errCodePayloadExpected, 149},
		{"unexpected-data", errCodeUnexpectedData, 150},
		{"parameter-out-of-range", errCodeParameterOutOfRange, 80},
		{"websocket-scheme-not-supported", ErrCodeWebsocketSchemeNotSupp, 166},
	} {
		if v.got != v.want {
			t.Errorf("%s = %d, want %d", v.name, v.got, v.want)
		}
	}
	// The unknown-subscription Error the IPE returns for a notification
	// it did not subscribe to (13.6), encoded as an Error-PDU.
	eqHex(t, "Error-PDU", ErrorAPDU(7, SvcConfirmedCOV, 5, ErrCodeUnknownSubscription), hx(t, "50 07 01 91 05 91 4F"))
	// WebSocket close statuses map to error codes (AB.7.5.5).
	for status, code := range map[int]uint16{1000: 169, 1001: 170, 1002: 171, 1003: 172, 1006: 173, 1007: 174, 1008: 175, 1009: 176, 1010: 177, 1011: 178, 4000: 179} {
		if got := websocketCloseCode(status); got != code {
			t.Errorf("close %d -> %d, want %d", status, got, code)
		}
	}
}

// Covers: SIG-IPE-1973
func TestWindowFunctionsClause5(t *testing.T) {
	// The examples of 5.4.2.1 and 5.4.2.2 (ActualWindowSize 4).
	for _, v := range []struct {
		a, b byte
		want bool
	}{{0, 0, true}, {1, 0, true}, {3, 0, true}, {4, 0, false}, {4, 5, false}, {0, 255, true}} {
		if got := inWindow(v.a, v.b, 4); got != v.want {
			t.Errorf("InWindow(%d, %d) = %v", v.a, v.b, got)
		}
	}
	for _, v := range []struct {
		a, init, last byte
		want          bool
	}{{0, 0, 1, true}, {1, 0, 1, true}, {2, 0, 1, false}, {3, 0, 1, false}, {5, 3, 3, false}} {
		if got := duplicateInWindow(v.a, v.init, v.last); got != v.want {
			t.Errorf("DuplicateInWindow(%d, %d, %d) = %v", v.a, v.init, v.last, got)
		}
	}
}

// Covers: SIG-IPE-1974
func TestAnnexABMessageVectors(t *testing.T) {
	dest := VMAC{0x92, 0x7b, 0xf7, 0x1a, 0x96, 0xa2}
	ab5 := hx(t, `01 07 B5EC 927BF71A96A2
		BF 0007 022B BAC5ECC099
		3F 0003 0309 39
		01
		01 04 0000010C0C000000051955`)
	t.Run("Figure AB-5 Encapsulated-NPDU", func(t *testing.T) {
		m := SCMsg{Fn: scEncapsulated, ID: 0xb5ec, dest: &dest,
			DestOpts: []SCOption{
				{Typ: SCOptProprietary, HasData: true, Data: hx(t, "022B BAC5ECC099")},
				{Typ: SCOptProprietary, HasData: true, Data: hx(t, "0309 39")},
			},
			// AB-5 marks Secure Path X'01' (bit 6 clear); see F-954.
			dataOpts: []SCOption{{Typ: SCOptSecurePath}},
			Payload:  append(NPDUBytes(NPDU{ExpectReply: true}), hx(t, "0000010C0C000000051955")...),
		}
		eqHex(t, "encoded", m.Encode(), ab5)
		got, e := DecodeSC(ab5)
		if e != nil || got.Fn != scEncapsulated || got.ID != 0xb5ec || got.orig != nil || *got.dest != dest || len(got.DestOpts) != 2 || len(got.dataOpts) != 1 {
			t.Fatalf("decoded %+v, %v", got, e)
		}
		n, err := DecodeNPDU(NPDU{}, got.Payload)
		if err != nil || !n.ExpectReply || n.NetMsg {
			t.Fatalf("NPDU = %+v, %v", n, err)
		}
		a, err := ParseAPDU(n.Data)
		if err != nil || a.Service != SvcReadProperty || a.InvokeID != 1 {
			t.Fatalf("APDU = %+v, %v", a, err)
		}
		// The hub forwards it with the originating VMAC added and the
		// Destination removed (AB.5.3.2); ID and options unchanged.
		src := VMAC{0x02, 1, 2, 3, 4, 5}
		fwd := got
		fwd.orig, fwd.dest = &src, nil
		want := append(hx(t, "01 0B B5EC 020102030405"), ab5[10:]...)
		eqHex(t, "forwarded", fwd.Encode(), want)
	})
	t.Run("Figure AB-6 BVLC-Result NAK with error details", func(t *testing.T) {
		want := hx(t, "00 08 B5EC 927BF71A96A2 01 01 BF 0007 0111 556E6DC3B6676C69 6368657220436F646521")
		e := &scNAK{code: 0x0111, marker: 0xbf}
		m := SCMsg{Fn: SCResult, ID: 0xb5ec, orig: &dest, Payload: resultPayload(scEncapsulated, e, "Unmöglicher Code!")}
		eqHex(t, "encoded", m.Encode(), want)
		got, ne := DecodeSC(want)
		if ne != nil {
			t.Fatal(ne)
		}
		r := DecodeResult(got.Payload)
		if !r.NAK || r.Fn != scEncapsulated || r.Marker != 0xbf || r.Class != 7 || r.Code != 273 || r.details != "Unmöglicher Code!" {
			t.Fatalf("result = %+v", r)
		}
	})
	t.Run("Figure AB-7 BVLC-Result NAK without error details", func(t *testing.T) {
		want := hx(t, "00 08 B5EC 927BF71A96A2 01 01 3F 0007 0117")
		m := SCMsg{Fn: SCResult, ID: 0xb5ec, orig: &dest, Payload: resultPayload(scEncapsulated, &scNAK{code: 279, marker: 0x3f}, "")}
		eqHex(t, "encoded", m.Encode(), want)
		got, ne := DecodeSC(want)
		if ne != nil {
			t.Fatal(ne)
		}
		if r := DecodeResult(got.Payload); r.Code != 279 || r.details != "" {
			t.Fatalf("result = %+v", r)
		}
	})
	t.Run("connection messages", func(t *testing.T) {
		c := SCConnect{VMAC: VMAC{0x12, 1, 2, 3, 4, 5}, UUID: [16]byte{15: 1}, MaxBVLC: 1600, MaxNPDU: 1497}
		b := SCMsg{Fn: SCConnectRequest, ID: 7, Payload: c.Bytes()}.Encode()
		eqHex(t, "Connect-Request", b, hx(t, "06 00 0007 120102030405 00000000000000000000000000000001 0640 05D9"))
		m, e := DecodeSC(b)
		if e != nil {
			t.Fatal(e)
		}
		if got, _ := DecodeConnect(m.Payload); got != c {
			t.Fatalf("connect = %+v", got)
		}
		eqHex(t, "Heartbeat-Request", SCMsg{Fn: SCHeartbeatReq, ID: 0x1234}.Encode(), hx(t, "0A 00 1234"))
		eqHex(t, "Advertisement", SCMsg{Fn: scAdvertisement, ID: 2, Payload: scAdvert{1, false, 1600, 1497}.bytes()}.Encode(), hx(t, "04 00 0002 01 00 0640 05D9"))
	})
	t.Run("VMAC", func(t *testing.T) {
		for range 64 {
			v := RandomVMAC()
			if v[0]&0x0f != 0x02 {
				t.Fatalf("Random-48 VMAC %s: low bits of the first octet are not B'0010' (H.7.3)", v)
			}
		}
		if _, err := ParseVMAC("FFFFFFFFFFFF"); err == nil {
			t.Error("the broadcast VMAC was accepted as a node address")
		}
		if _, err := ParseVMAC("000000000000"); err == nil {
			t.Error("the unknown VMAC was accepted as a node address")
		}
		if v, err := ParseVMAC("02:aa:bb:cc:dd:ee"); err != nil || v.String() != "02AABBCCDDEE" {
			t.Errorf("parseVMAC = %s, %v", v, err)
		}
		u := NewUUID()
		if u[6]>>4 != 4 || u[8]>>6 != 2 {
			t.Errorf("UUID %s is not RFC 4122 version 4", UUIDString(u))
		}
	})
}

// Covers: SIG-IPE-1975
func TestSCMessageErrors(t *testing.T) {
	for _, v := range []struct {
		name   string
		hex    string
		code   uint16
		silent bool
	}{
		{"no message ID", "0A 00 12", 0, true},
		{"unknown function", "0D 00 0001", ErrCodeBVLCFunctionUnknown, false},
		{"reserved control flag", "0A 10 0001", errCodeParameterOutOfRange, false},
		{"address on a connection message", "0A 08 0001 020102030405", errCodeParameterOutOfRange, false},
		{"truncated originating address", "01 08 0001 0201", errCodeMessageIncomplete, false},
		{"truncated header option", "01 06 0001 020102030405 3F 0005 00", errCodeMessageIncomplete, false},
		{"payload expected", "01 04 0001 020102030405", errCodePayloadExpected, false},
		{"payload not allowed", "0A 00 0001 00", errCodeUnexpectedData, false},
		{"connect payload too short", "06 00 0001 0102", errCodeMessageIncomplete, false},
		{"connect payload too long", "06 00 0001 " + strings.Repeat("00", 27), errCodeUnexpectedData, false},
		{"data options without an NPDU", "0A 01 0001 01", errCodeParameterOutOfRange, false},
		{"Secure Path with data", "01 05 0001 020102030405 21 0000 01", errCodeHeaderEncodingError, false},
		{"Hello of two octets", "06 02 0001 22 0002 0000", errCodeHeaderEncodingError, false},
	} {
		_, e := DecodeSC(hx(t, v.hex))
		switch {
		case e == nil:
			t.Errorf("%s: accepted", v.name)
		case e.silent != v.silent || (!v.silent && e.code != v.code):
			t.Errorf("%s: got code %d silent %v, want %d silent %v", v.name, e.code, e.silent, v.code, v.silent)
		}
	}
	// A destination option that must be understood and is not (AB.3.1.4).
	m, e := DecodeSC(hx(t, "0A 02 0001 7F 0003 0309 39"))
	if e != nil {
		t.Fatal(e)
	}
	if ne := m.mustUnderstand(); ne == nil || ne.code != ErrCodeHeaderNotUnderstood || ne.marker != 0x7f {
		t.Fatalf("must understand = %+v", ne)
	}
	// Not must-understand: ignored.
	m, _ = DecodeSC(hx(t, "0A 02 0001 3F 0003 0309 39"))
	if m.mustUnderstand() != nil {
		t.Fatal("an option that need not be understood was refused")
	}
}
