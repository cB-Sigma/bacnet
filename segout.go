package bacnet

// Segmented Complex-ACKs sent by this node (the responder's
// AWAIT_RESPONSE and SEGMENTED_RESPONSE states, clause 5.4.5.3 and
// 5.4.5.4): a reply longer than the requester's max APDU goes in segments
// when the requester accepts them and states enough segments; the first
// segment alone, then windows of the size its Segment-ACKs grant, going
// back to the segment after the one a Segment-ACK names; retried after
// Tseg up to the retry count, and ended by an Abort from the requester.

import (
	"net"
	"time"
)

// Transmission settings of segmented replies.
var (
	segReplyTimeout = 2 * time.Second // Tseg
	segReplyRetries = 3
)

// ReplyLimit is the longest APDU the requester accepts.
func ReplyLimit(a APDU) int { return min(max(a.MaxResp, 50), 1476) }

// fitReply turns a reply that cannot be sent into the Abort of 5.4.5.3
// (CannotSendSegmentedComplexACK); other replies are returned unchanged.
func (c *Client) fitReply(a APDU, reply []byte) []byte {
	if reply[0]>>4 != PDUComplexACK || len(reply) <= ReplyLimit(a) {
		return reply
	}
	if !a.Sa {
		return EncodeAbort(a.InvokeID, AbortSegNotSupp, true)
	}
	return EncodeAbort(a.InvokeID, AbortBufferOverflow, true)
}

// segmentReply starts a segmented reply when one is needed and allowed;
// it reports whether it did.
func (c *Client) segmentReply(to net.Addr, d Dest, a APDU, reply []byte) bool {
	limit := ReplyLimit(a)
	if reply[0]>>4 != PDUComplexACK || len(reply) <= limit || !a.Sa {
		return false
	}
	size := limit - 5 // segment header: type, invoke ID, sequence, window, service
	body := reply[3:]
	n := (len(body) + size - 1) / size
	if n > a.MaxSegs || n > MaxSegments || n > 255 {
		return false // abort: buffer-overflow (fitReply)
	}
	var parts [][]byte
	for len(body) > 0 {
		k := min(size, len(body))
		parts = append(parts, body[:k])
		body = body[k:]
	}
	key := PendingKey{Dest{Addr: to, Net: d.Net, MAC: d.MAC}.Key() + "/tx", a.InvokeID}
	if d.Net != 0 {
		key = PendingKey{d.Key() + "/tx", a.InvokeID}
	}
	ch := make(chan APDU, 16)
	c.Mu.Lock()
	if c.segTx == nil {
		c.segTx = map[PendingKey]chan APDU{}
	}
	c.segTx[key] = ch
	c.Mu.Unlock()
	go func() {
		defer func() {
			c.Mu.Lock()
			if c.segTx[key] == ch {
				delete(c.segTx, key)
			}
			c.Mu.Unlock()
		}()
		c.sendReplySegments(to, d, a.InvokeID, reply[2], parts, ch)
	}()
	return true
}

func (c *Client) sendReplySegments(to net.Addr, d Dest, id, service byte, parts [][]byte, ch chan APDU) {
	send := func(seq int) {
		_ = c.SendAPDU(to, Dest{Net: d.Net, MAC: d.MAC}, true,
			ComplexACKSegment(id, service, byte(seq), MaxWindow, seq < len(parts)-1, parts[seq]))
	}
	fill := func(initial, window int) {
		for i := initial; i < min(initial+window, len(parts)); i++ {
			send(i)
		}
	}
	initial, window, retries := 0, 1, 0
	send(0)
	t := time.NewTimer(segReplyTimeout)
	defer t.Stop()
	for {
		select {
		case a := <-ch:
			if a.Typ == PDUAbort {
				return
			}
			if !inWindow(a.Seq, byte(initial), byte(window)) {
				t.Reset(segReplyTimeout) // DuplicateACK_Received
				continue
			}
			next := initial + int(a.Seq-byte(initial)) + 1
			if next >= len(parts) {
				return // FinalACK_Received
			}
			initial, window, retries = next, max(1, min(int(a.Window), 127)), 0
			fill(initial, window)
			t.Reset(segReplyTimeout)
		case <-t.C:
			if retries >= segReplyRetries {
				return // FinalTimeout
			}
			retries++
			fill(initial, window)
			t.Reset(segReplyTimeout)
		}
	}
}

func (c *Client) ownMax() byte {
	if c.MaxRespCode == 0 {
		return ownMaxAPDU
	}
	return c.MaxRespCode
}
