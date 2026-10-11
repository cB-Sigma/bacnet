package bacnet

// Segmented confirmed requests from a device (the responder's
// SEGMENTED_REQUEST state, clause 5.4.5.1 and 5.4.5.2): the first segment
// is acknowledged with the actual window (at most the proposed one, at
// most 16), each full window and the last segment are acknowledged,
// duplicates in the window are dropped up to Ndup and then negatively
// acknowledged, any other segment out of order gets a negative Segment-ACK
// naming the last good one, and a proposed window outside 1..127 is
// aborted with window-size-out-of-range. The reassembled request goes to
// OnConfirmed like an unsegmented one.

import (
	"net"
	"time"
)

const abortWindowSizeOutOfRange = 7

// segRx is one segmented request being received.
type segRx struct {
	service               byte
	maxResp               int
	sa                    bool
	data                  []byte
	last, initial, window byte
	dups, count           int
	seen                  time.Time
}

// segIn handles one segment; it returns the APDUs to send back (Segment-ACK,
// Abort, and the reply once the request is complete).
func (c *Client) segIn(src net.Addr, d Dest, a APDU) [][]byte {
	now := time.Now()
	key := PendingKey{d.Key() + "/rx", a.InvokeID}
	c.Mu.Lock()
	defer c.Mu.Unlock()
	if c.segRx == nil {
		c.segRx = map[PendingKey]*segRx{}
	}
	for k, r := range c.segRx { // Timeout: Tseg times four
		if now.Sub(r.seen) > 4*SegTimeout {
			delete(c.segRx, k)
		}
	}
	r := c.segRx[key]
	ack := func(seq byte, nak bool) []byte { return SegmentACK(a.InvokeID, seq, r.window, nak, true) }
	if a.Seq == 0 && (r == nil || r.count > 0) {
		if a.Window == 0 || a.Window > 127 {
			delete(c.segRx, key)
			return [][]byte{EncodeAbort(a.InvokeID, abortWindowSizeOutOfRange, true)}
		}
		r = &segRx{service: a.Service, maxResp: a.MaxResp, sa: a.Sa, data: append([]byte(nil), a.Data...),
			window: min(a.Window, MaxWindow), count: 1, seen: now}
		c.segRx[key] = r
		if !a.More {
			delete(c.segRx, key)
			return [][]byte{ack(0, false), c.complete(d, a.InvokeID, r)}
		}
		return [][]byte{ack(0, false)}
	}
	if r == nil {
		return [][]byte{EncodeAbort(a.InvokeID, abortInvalidAPDU, true)}
	}
	r.seen = now
	switch {
	case a.Seq == r.last+1:
		r.data, r.last, r.count = append(r.data, a.Data...), a.Seq, r.count+1
		if r.count > MaxSegments {
			delete(c.segRx, key)
			return [][]byte{EncodeAbort(a.InvokeID, AbortBufferOverflow, true)}
		}
		if !a.More { // LastSegmentOfMessageReceived
			delete(c.segRx, key)
			return [][]byte{ack(r.last, false), c.complete(d, a.InvokeID, r)}
		}
		if a.Seq == r.initial+r.window { // LastSegmentOfGroupReceived
			r.initial, r.dups = r.last, 0
			return [][]byte{ack(r.last, false)}
		}
		return nil
	case duplicateInWindow(a.Seq, r.initial, r.last):
		if r.dups < int(r.window) {
			r.dups++
			return nil
		}
		r.initial, r.dups = r.last, 0 // TooManyDuplicateSegmentsReceived
		return [][]byte{ack(r.last, true)}
	default: // SegmentReceivedOutOfOrder
		r.initial, r.dups = r.last, 0
		return [][]byte{ack(r.last, true)}
	}
}

// SegTimeout is Tseg for received segments.
const SegTimeout = 2 * time.Second

// complete hands the reassembled request to onConfirmed (called with c.mu
// held; onConfirmed does not take it).
func (c *Client) complete(d Dest, id byte, r *segRx) []byte {
	if c.OnConfirmed == nil {
		return []byte{PDUReject << 4, id, RejectUnrecognizedService}
	}
	c.Mu.Unlock()
	defer c.Mu.Lock()
	return c.OnConfirmed(d, APDU{Typ: PDUConfirmed, InvokeID: id, Service: r.service, Data: r.data, MaxResp: r.maxResp, Sa: r.sa})
}
