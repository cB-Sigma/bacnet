package bacnet

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"
)

// tsmRig is a requester transaction whose replies are fed by hand; what
// the requester sends back arrives on a local UDP socket.
type tsmRig struct {
	x   *txn
	dev *net.UDPConn
}

func newTSMRig(t *testing.T) *tsmRig {
	t.Helper()
	dev, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewClient("127.0.0.1:0", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); _ = dev.Close() })
	to := dev.LocalAddr().(*net.UDPAddr)
	return &tsmRig{x: &txn{c: c, to: to, d: Dest{Addr: to}, id: 9, ch: make(chan APDU, 64), timeout: time.Second}, dev: dev}
}

// sent is the next APDU the requester sent.
func (r *tsmRig) sent(t *testing.T) APDU {
	t.Helper()
	buf := make([]byte, 1500)
	_ = r.dev.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := r.dev.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("nothing sent: %v", err)
	}
	a, err := ParseAPDU(mustUnframe(t, buf[:n]))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func mustUnframe(t *testing.T, b []byte) []byte {
	t.Helper()
	a, err := Unframe(b)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func seg(seq, window byte, more bool, data string) APDU {
	return APDU{Typ: PDUComplexACK, InvokeID: 9, Service: SvcReadPropertyMultiple, Seg: true, More: more, Seq: seq, Window: window, Data: []byte(data)}
}

// Covers: SIG-IPE-1973
func TestSegmentedConfClause5(t *testing.T) {
	t.Run("first segment not number 0 is aborted with invalid-apdu-in-this-state", func(t *testing.T) {
		r := newTSMRig(t)
		r.x.ch <- seg(3, 4, true, "x")
		if _, err := r.x.reply(context.Background()); err == nil {
			t.Fatal("accepted")
		}
		if a := r.sent(t); a.Typ != PDUAbort || a.Reason != abortInvalidAPDU || a.Srv {
			t.Fatalf("sent %+v", a)
		}
	})
	t.Run("out of order segments get a negative Segment-ACK each", func(t *testing.T) {
		r := newTSMRig(t)
		done := make(chan APDU, 1)
		go func() { a, _ := r.x.reply(context.Background()); done <- a }()
		r.x.ch <- seg(0, 4, true, "a")
		if a := r.sent(t); a.Typ != PDUSegmentACK || a.NAK || a.Seq != 0 || a.Window != 4 {
			t.Fatalf("first ack %+v", a)
		}
		r.x.ch <- seg(1, 4, true, "b")
		r.x.ch <- seg(3, 4, true, "d") // 2 lost
		if a := r.sent(t); !a.NAK || a.Seq != 1 {
			t.Fatalf("want NAK 1, sent %+v", a)
		}
		r.x.ch <- seg(4, 4, true, "e") // still out of order: another NAK
		if a := r.sent(t); !a.NAK || a.Seq != 1 {
			t.Fatalf("want second NAK 1, sent %+v", a)
		}
		for i, s := range "cde" {
			r.x.ch <- seg(byte(2+i), 4, true, string(s))
		}
		// Window started at 1 after the NAK: segment 5 (1+4) closes it.
		r.x.ch <- seg(5, 4, false, "f")
		if a := r.sent(t); a.NAK || a.Seq != 5 {
			t.Fatalf("final ack %+v", a)
		}
		if a := <-done; string(a.Data) != "abcdef" {
			t.Fatalf("reassembled %q", a.Data)
		}
	})
	t.Run("duplicates in the window are dropped up to Ndup, then NAKed", func(t *testing.T) {
		r := newTSMRig(t)
		done := make(chan APDU, 1)
		go func() { a, _ := r.x.reply(context.Background()); done <- a }()
		r.x.ch <- seg(0, 2, true, "a")
		r.sent(t)
		r.x.ch <- seg(1, 2, true, "b")
		for range 2 { // Ndup = window = 2 duplicates dropped silently
			r.x.ch <- seg(1, 2, true, "b")
		}
		r.x.ch <- seg(1, 2, true, "b") // the third: NAK naming the last good
		if a := r.sent(t); !a.NAK || a.Seq != 1 {
			t.Fatalf("want NAK 1, sent %+v", a)
		}
		r.x.ch <- seg(2, 2, false, "c")
		if a := r.sent(t); a.NAK || a.Seq != 2 {
			t.Fatalf("final ack %+v", a)
		}
		if a := <-done; string(a.Data) != "abc" {
			t.Fatalf("reassembled %q", a.Data)
		}
	})
}
