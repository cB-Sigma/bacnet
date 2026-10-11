package bacnet

import (
	"testing"
)

func reqSeg(seq, window byte, more bool, data []byte) []byte {
	h := byte(PDUConfirmed<<4 | flagSEG | flagSA)
	if more {
		h |= flagMOR
	}
	return append([]byte{h, 0x05, 0x33, seq, window, SvcConfirmedCOV}, data...)
}

// Covers: SIG-IPE-1995
func TestSegmentedRequestFromDevice(t *testing.T) {
	cov := hx(t, "09 01 1C 02000004 2C 0000000A 39 00 4E 09 55 2E 44 42820000 2F 4F")
	parts := [][]byte{cov[:5], cov[5:10], cov[10:15], cov[15:]}
	setup := func(t *testing.T) (*tsmRig, *[][]byte) {
		r := newTSMRig(t)
		var got [][]byte
		r.x.c.OnConfirmed = func(from Dest, a APDU) []byte {
			got = append(got, a.Data)
			return []byte{PDUSimpleACK << 4, a.InvokeID, a.Service}
		}
		return r, &got
	}
	in := func(r *tsmRig, b []byte) { r.x.c.Receive(r.x.to, NPDU{Data: b}) }
	t.Run("windows acknowledged, reassembled, answered", func(t *testing.T) {
		r, got := setup(t)
		in(r, reqSeg(0, 5, true, parts[0]))
		if a := r.sent(t); a.Typ != PDUSegmentACK || !a.Srv || a.NAK || a.Seq != 0 || a.Window != 5 {
			t.Fatalf("first ack %+v", a)
		}
		in(r, reqSeg(1, 5, true, parts[1]))
		in(r, reqSeg(2, 5, true, parts[2]))
		in(r, reqSeg(3, 5, false, parts[3]))
		if a := r.sent(t); a.Typ != PDUSegmentACK || a.NAK || a.Seq != 3 {
			t.Fatalf("last ack %+v", a)
		}
		if a := r.sent(t); a.Typ != PDUSimpleACK || a.InvokeID != 0x33 {
			t.Fatalf("reply %+v", a)
		}
		if len(*got) != 1 || string((*got)[0]) != string(cov) {
			t.Fatalf("reassembled %X", *got)
		}
	})
	t.Run("full window acknowledged; out of order NAKed", func(t *testing.T) {
		r, _ := setup(t)
		in(r, reqSeg(0, 2, true, parts[0]))
		r.sent(t)
		in(r, reqSeg(1, 2, true, parts[1]))
		in(r, reqSeg(2, 2, true, parts[2])) // 0+2: end of window
		if a := r.sent(t); a.NAK || a.Seq != 2 {
			t.Fatalf("window ack %+v", a)
		}
		in(r, reqSeg(4, 2, false, parts[3])) // 3 missing
		if a := r.sent(t); !a.NAK || a.Seq != 2 || !a.Srv {
			t.Fatalf("NAK %+v", a)
		}
		in(r, reqSeg(3, 2, false, parts[3]))
		if a := r.sent(t); a.NAK || a.Seq != 3 {
			t.Fatalf("final ack %+v", a)
		}
		if a := r.sent(t); a.Typ != PDUSimpleACK {
			t.Fatalf("reply %+v", a)
		}
	})
	t.Run("window size out of range and stray segments aborted", func(t *testing.T) {
		r, _ := setup(t)
		in(r, reqSeg(0, 0, true, parts[0]))
		if a := r.sent(t); a.Typ != PDUAbort || !a.Srv || a.Reason != abortWindowSizeOutOfRange {
			t.Fatalf("sent %+v", a)
		}
		in(r, reqSeg(0, 128, true, parts[0]))
		if a := r.sent(t); a.Typ != PDUAbort || a.Reason != abortWindowSizeOutOfRange {
			t.Fatalf("sent %+v", a)
		}
		in(r, reqSeg(4, 2, true, parts[0]))
		if a := r.sent(t); a.Typ != PDUAbort || !a.Srv {
			t.Fatalf("sent %+v", a)
		}
	})
}
