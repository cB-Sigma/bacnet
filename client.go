package bacnet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Client is the driver's one UDP socket. Confirmed requests are matched to
// replies by invoke ID and the device's BACnet address (its B/IP address,
// or network number and MAC when routed); unconfirmed requests (COV
// notifications) go to onUnconfirmed. It finds routers with
// Who-Is-Router-To-Network and, with a BBMD configured, registers as a
// foreign device and broadcasts through the BBMD.
type Client struct {
	Conn          *net.UDPConn // BACnet/IP; nil over BACnet/SC
	SC            *SCNode      // BACnet/SC hub connector; nil over BACnet/IP
	IP6           *BIP6        // BACnet/IPv6 port; nil otherwise (bip6.go)
	Log           *slog.Logger
	OnUnconfirmed func(from Dest, a APDU)
	OnConfirmed   func(from Dest, a APDU) []byte // the reply to a device's confirmed request
	IAmLog        iAmLog                         // I-Ams while a discovery round runs
	Broadcast     *net.UDPAddr                   // local B/IP broadcast address; nil for none
	BBMD          *net.UDPAddr                   // BBMD to register with; nil for none
	BBMDRole      *bbmdState                     // this port's BBMD function (bbmd.go); nil for none
	// Fanout, when set, is the local subnet member by member: broadcasts
	// go to each instead of the broadcast address (hosts and tests
	// without IP broadcast).
	Fanout []*net.UDPAddr

	Mu         sync.Mutex
	next       byte
	Pending    map[PendingKey]chan APDU
	Routers    map[uint16]net.Addr // discovered router per network
	RouterSeen chan struct{}       // closed and replaced on each I-Am-Router-To-Network
	Iams       map[uint32]chan IAm
	ihaves     []chan iHave             // Who-Has commands waiting for I-Have
	segRx      map[PendingKey]*segRx    // segmented requests being received (segin.go)
	segTx      map[PendingKey]chan APDU // segmented replies being sent (segout.go)
	// MaxRespCode is the max-APDU-length-accepted code stated in our
	// requests (0: 5, 1476 octets).
	MaxRespCode byte
	Bindings    map[uint32]Dest // device instance to address, from the I-Ams heard
	Results     chan uint16     // BVLC-Result codes from the BBMD
	fdErr       error           // why foreign-device registration or distribution failed
}

// Dest is a device's BACnet address: a B/IP address (*net.UDPAddr) or a
// BACnet/SC VMAC on the local network, or a network number and MAC
// reached through the router at addr (nil until discovered).
type Dest struct {
	Addr net.Addr
	Net  uint16
	MAC  []byte
}

// Key identifies the device whatever path its replies take.
func (d Dest) Key() string {
	if d.Net != 0 {
		return fmt.Sprintf("%d/%x", d.Net, d.MAC)
	}
	if d.Addr == nil {
		return ""
	}
	return d.Addr.String()
}

// Peer is what the device accepts: its largest APDU and whether it takes
// segmented requests.
type Peer struct {
	MaxAPDU int
	RecvSeg bool
}

// Target is everything a confirmed request needs to reach a device.
type Target struct {
	Dest
	Peer
	Timeout time.Duration
	Retries int
}

type PendingKey struct {
	Addr string
	ID   byte
}

func NewClient(local string, log *slog.Logger) (*Client, error) {
	if local == "" {
		local = "0.0.0.0:0"
	}
	la, err := net.ResolveUDPAddr("udp", local)
	if err != nil {
		return nil, fmt.Errorf("local address %q: %w", local, err)
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	return &Client{
		Conn: conn, Log: log, Pending: map[PendingKey]chan APDU{}, Routers: map[uint16]net.Addr{},
		RouterSeen: make(chan struct{}), Iams: map[uint32]chan IAm{}, Results: make(chan uint16, 8),
	}, nil
}

func (c *Client) Close() {
	if c.Conn != nil {
		_ = c.Conn.Close()
	}
	if c.SC != nil {
		c.SC.Close()
	}
	if c.IP6 != nil {
		c.IP6.Close()
	}
}

// NewClient6 is a client on a BACnet/IPv6 port whose VMAC is instance
// (random when nil).
func NewClient6(s *IPv6Settings, instance *uint32, timeout time.Duration, log *slog.Logger) (*Client, error) {
	c := &Client{
		Log: log, Pending: map[PendingKey]chan APDU{}, Routers: map[uint16]net.Addr{},
		RouterSeen: make(chan struct{}), Iams: map[uint32]chan IAm{}, Results: make(chan uint16, 8), BBMD: s.bbmd,
	}
	l, err := openBIP6(s, instance, timeout, log)
	if err != nil {
		return nil, err
	}
	l.Deliver = c.Receive
	l.Result = func(from *net.UDPAddr, code uint16) { c.bvlcResult(from, FromResult6(code)) }
	c.IP6 = l
	return c, nil
}

// NewClientSC is a client on the BACnet/SC network port n: the NPDUs n
// receives (with their data options) go to the client. Start n with
// n.Start after this call; Close closes n. Serve is not needed.
func NewClientSC(n *SCNode, log *slog.Logger) *Client {
	c := &Client{
		SC: n, Log: log, Pending: map[PendingKey]chan APDU{}, Routers: map[uint16]net.Addr{},
		RouterSeen: make(chan struct{}), Iams: map[uint32]chan IAm{}, Results: make(chan uint16, 8),
	}
	n.OnNPDU = func(from VMAC, b []byte, opts []SCOption) {
		f, err := DecodeNPDU(NPDU{Fn: BVLCOriginalUnicast}, b)
		if err != nil {
			log.Debug("BACnet/SC NPDU ignored", "from", from, "error", err)
			return
		}
		f.Opts = opts
		c.Receive(from, f)
	}
	return c
}

// Serve reads frames until the socket closes.
func (c *Client) Serve() {
	if c.IP6 != nil {
		c.IP6.Serve()
		return
	}
	buf := make([]byte, 1500)
	for {
		n, from, err := c.Conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		f, err := DecodeFrame(append([]byte(nil), buf[:n]...))
		if err != nil {
			c.Log.Debug("BACnet frame ignored", "from", from, "error", err)
			continue
		}
		if f.Fn == BVLCResult {
			c.bvlcResult(from, f.Result)
			continue
		}
		if !hasNPDU(f.Fn) {
			c.bvllService(from, f) // BBMD services, or their NAK (J.2.1)
			continue
		}
		np := buf[4:n]
		if f.Fn == BVLCForwardedNPDU {
			np = buf[10:n]
		}
		if !c.forward(from, f, append([]byte(nil), np...)) {
			continue
		}
		var src net.Addr = from
		if f.Origin != nil {
			src = f.Origin // Forwarded-NPDU: the original sender
		}
		c.Receive(src, f)
	}
}

// Receive handles an NPDU from src, whichever data link it came over.
func (c *Client) Receive(src net.Addr, f NPDU) {
	if f.NetMsg {
		c.network(src, f)
		return
	}
	if f.Dnet != 0 && f.Dnet != 0xffff {
		return // no APDU, or not for this network
	}
	a, err := ParseAPDU(f.Data)
	if err != nil {
		c.Log.Debug("BACnet frame ignored", "from", src, "error", err)
		return
	}
	a.Attrs = f.Opts
	d := Dest{Addr: src, Net: f.Snet, MAC: f.SADR}
	switch a.Typ {
	case PDUConfirmed:
		// Only ConfirmedCOVNotification is served (by onConfirmed);
		// anything else is rejected as an unrecognized service.
		var replies [][]byte
		switch {
		case a.Seg:
			replies = c.segIn(src, d, a)
		case c.OnConfirmed != nil:
			replies = [][]byte{c.OnConfirmed(d, a)}
		default:
			replies = [][]byte{{PDUReject << 4, a.InvokeID, RejectUnrecognizedService}}
		}
		for i, reply := range replies {
			if reply == nil {
				continue
			}
			if i == len(replies)-1 && !a.Seg || a.Seg && i > 0 {
				if c.segmentReply(src, Dest{Net: f.Snet, MAC: f.SADR}, a, reply) {
					continue
				}
				reply = c.fitReply(a, reply)
			}
			if err := c.SendAPDU(src, Dest{Net: f.Snet, MAC: f.SADR}, false, reply); err != nil {
				c.Log.Debug("BACnet reply not sent", "to", src, "error", err)
			}
		}
		return
	case PDUUnconfirmed:
		if a.Service == SvcIHave {
			c.gotIHave(a.Data)
		}
		if a.Service == SvcIAm {
			c.gotIAm(a.Data)
			if i, err := DecodeIAm(a.Data); err == nil {
				c.IAmLog.add(d, i)
				c.Mu.Lock()
				if c.Bindings == nil {
					c.Bindings = map[uint32]Dest{}
				}
				c.Bindings[i.Device.Instance] = d
				c.Mu.Unlock()
			}
		}
		if c.OnUnconfirmed != nil {
			c.OnUnconfirmed(d, a)
		}
		return
	}
	if a.Typ == PDUSegmentACK && !a.Srv || a.Typ == PDUAbort && !a.Srv {
		// For a segmented reply this node sends (segout.go).
		c.Mu.Lock()
		ch := c.segTx[PendingKey{d.Key() + "/tx", a.InvokeID}]
		c.Mu.Unlock()
		if ch != nil {
			select {
			case ch <- a:
			default:
			}
		}
		return
	}
	c.Mu.Lock()
	ch := c.Pending[PendingKey{d.Key(), a.InvokeID}]
	c.Mu.Unlock()
	if ch != nil {
		select {
		case ch <- a:
		default: // a full window already queued; a Segment-ACK NAK recovers
		}
	}
}

// ---- network layer and BVLL ----------------------------------------------

// Network handles network layer messages: I-Am-Router-To-Network records
// the router of each network listed, Reject-Message-To-Network forgets it.
func (c *Client) network(from net.Addr, f NPDU) {
	switch f.MsgType {
	case NlIAmRouter:
		c.Mu.Lock()
		for b := f.Data; len(b) >= 2; b = b[2:] {
			c.Routers[binary.BigEndian.Uint16(b)] = from
		}
		close(c.RouterSeen)
		c.RouterSeen = make(chan struct{})
		c.Mu.Unlock()
	case nlRejectMessage:
		if len(f.Data) >= 3 {
			nw := binary.BigEndian.Uint16(f.Data[1:])
			c.Log.Info("BACnet router rejected a message", "router", from, "network", nw, "reason", f.Data[0])
			c.forgetRouter(nw, from)
		}
	}
}

func (c *Client) forgetRouter(nw uint16, r net.Addr) {
	c.Mu.Lock()
	if cur := c.Routers[nw]; cur != nil && cur.String() == r.String() {
		delete(c.Routers, nw)
	}
	c.Mu.Unlock()
}

// BVLCResult takes a BVLC-Result from the BBMD. A refused distribution is
// recorded here; registration results go to registerForeign.
func (c *Client) bvlcResult(from *net.UDPAddr, code uint16) {
	if c.BBMD == nil || from.String() != c.BBMD.String() {
		return
	}
	if code == ResultDistributeNAK {
		c.Log.Warn("the BBMD refused Distribute-Broadcast-To-Network", "bbmd", c.BBMD)
		c.Mu.Lock()
		c.fdErr = fmt.Errorf("BBMD %s refused Distribute-Broadcast-To-Network (not registered as a foreign device)", c.BBMD)
		c.Mu.Unlock()
		return
	}
	select {
	case c.Results <- code:
	default:
	}
}

// ForeignErr is why the IPE is not (yet) a registered foreign device.
func (c *Client) ForeignErr() error {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return c.fdErr
}

// RegisterForeign sends Register-Foreign-Device to the BBMD and waits for
// its BVLC-Result.
func (c *Client) RegisterForeign(ctx context.Context, ttl time.Duration, timeout time.Duration, retries int) error {
	secs := uint16(min(ttl/time.Second, 65535))
	pkt := BVLC(BVLCRegisterFD, []byte{byte(secs >> 8), byte(secs)})
	for len(c.Results) > 0 {
		<-c.Results
	}
	err := fmt.Errorf("no BVLC-Result from BBMD %s after %d attempts", c.BBMD, retries+1)
	for attempt := 0; attempt <= retries && err != nil; attempt++ {
		var werr error
		if c.IP6 != nil {
			werr = c.IP6.Register(secs)
		} else {
			_, werr = c.Conn.WriteToUDP(pkt, c.BBMD)
		}
		if werr != nil {
			err = werr
			break
		}
		t := time.NewTimer(timeout)
	wait:
		for {
			select {
			case <-ctx.Done():
				t.Stop()
				return ctx.Err()
			case code := <-c.Results:
				switch code {
				case ResultOK:
					err = nil
				case ResultRegisterFDNAK:
					err = fmt.Errorf("BBMD %s refused the foreign-device registration: Register-Foreign-Device %w", c.BBMD, errNAK)
				default:
					continue
				}
				break wait
			case <-t.C:
				break wait
			}
		}
		t.Stop()
		if err != nil && errors.Is(err, errNAK) {
			break
		}
	}
	c.Mu.Lock()
	c.fdErr = err
	c.Mu.Unlock()
	return err
}

var errNAK = errors.New("NAK")

// BroadcastNPDU sends an NPDU to every device on the local network:
// through the BBMD when registered as a foreign device, else to the
// Broadcast address.
func (c *Client) BroadcastNPDU(n NPDU) error {
	switch {
	case c.SC != nil:
		return c.SC.Broadcast(NPDUBytes(n))
	case c.IP6 != nil:
		return c.IP6.Broadcast(NPDUBytes(n))
	case c.BBMDRole != nil:
		// A BBMD's own broadcast: on the subnet, and forwarded to the
		// peers and foreign devices (J.4.5).
		np := NPDUBytes(n)
		err := c.localBroadcast(EncodeNPDU(BVLCOriginalBcast, n))
		fwd := encodeForwarded(c.ownBIP(), np)
		c.toPeers(fwd)
		c.toForeign(fwd, nil)
		return err
	case c.BBMD != nil:
		_, err := c.Conn.WriteToUDP(EncodeNPDU(BVLCDistributeBcast, n), c.BBMD)
		return err
	case c.Broadcast != nil || len(c.Fanout) > 0:
		return c.localBroadcast(EncodeNPDU(BVLCOriginalBcast, n))
	}
	return errors.New("no broadcast address or BBMD is configured")
}

// routerFor finds the router to a network with Who-Is-Router-To-Network.
func (c *Client) routerFor(ctx context.Context, nw uint16, timeout time.Duration, retries int) (net.Addr, error) {
	for attempt := 0; attempt <= retries; attempt++ {
		c.Mu.Lock()
		r, seen := c.Routers[nw], c.RouterSeen
		c.Mu.Unlock()
		if r != nil {
			return r, nil
		}
		if err := c.BroadcastNPDU(NPDU{NetMsg: true, MsgType: NlWhoIsRouter, Data: binary.BigEndian.AppendUint16(nil, nw)}); err != nil {
			return nil, fmt.Errorf("looking for the router to network %d: %w", nw, err)
		}
		t := time.NewTimer(timeout)
	wait:
		for {
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-seen:
				c.Mu.Lock()
				r, seen = c.Routers[nw], c.RouterSeen
				c.Mu.Unlock()
				if r != nil {
					t.Stop()
					return r, nil
				}
			case <-t.C:
				break wait
			}
		}
	}
	err := fmt.Errorf("no router to network %d answered Who-Is-Router-To-Network", nw)
	if ferr := c.ForeignErr(); ferr != nil {
		err = fmt.Errorf("%w; %v", err, ferr)
	}
	return nil, err
}

// via is the UDP address a request to d goes to, finding the router of a
// remote network when none is configured.
func (c *Client) via(ctx context.Context, t Target) (net.Addr, bool, error) {
	if t.Addr != nil {
		return t.Addr, false, nil
	}
	if t.Net == 0 {
		return nil, false, errors.New("the device has no address")
	}
	r, err := c.routerFor(ctx, t.Net, t.Timeout, t.Retries)
	return r, true, err
}

// SendAPDU sends an APDU to d through the data link address to (a B/IP
// address or a BACnet/SC VMAC).
func (c *Client) SendAPDU(to net.Addr, d Dest, expectReply bool, a []byte) error {
	n := NPDU{ExpectReply: expectReply, Data: a}
	if d.Net != 0 {
		n.Dnet, n.DADR, n.Hop = d.Net, d.MAC, 255
	}
	switch x := to.(type) {
	case *net.UDPAddr:
		if c.IP6 != nil {
			return c.IP6.Unicast(x, NPDUBytes(n))
		}
		if c.Conn == nil {
			return errors.New("a B/IP address needs the BACnet/IP data link")
		}
		_, err := c.Conn.WriteToUDP(EncodeNPDU(BVLCOriginalUnicast, n), x)
		return err
	case Peer6:
		if c.IP6 == nil {
			return errors.New("a B/IPv6 peer needs the BACnet/IPv6 data link")
		}
		return c.IP6.unicastTo(x, NPDUBytes(n))
	case VMAC:
		if c.SC == nil {
			return errors.New("a VMAC needs the BACnet/SC data link")
		}
		return c.SC.Unicast(x, NPDUBytes(n))
	}
	return fmt.Errorf("no data link for address %v", to)
}

// ---- Who-Is / I-Am ---------------------------------------------------------

func (c *Client) gotIAm(data []byte) {
	i, err := DecodeIAm(data)
	if err != nil {
		return
	}
	c.Mu.Lock()
	ch := c.Iams[i.Device.Instance]
	c.Mu.Unlock()
	if ch != nil {
		select {
		case ch <- i:
		default:
		}
	}
}

// WhoIs asks one device for its I-Am (directed, not broadcast).
func (c *Client) WhoIs(ctx context.Context, t Target, instance uint32) (IAm, error) {
	to, _, err := c.via(ctx, t)
	if err != nil {
		return IAm{}, err
	}
	ch := make(chan IAm, 1)
	c.Mu.Lock()
	c.Iams[instance] = ch
	c.Mu.Unlock()
	defer func() {
		c.Mu.Lock()
		delete(c.Iams, instance)
		c.Mu.Unlock()
	}()
	if err := c.SendAPDU(to, t.Dest, false, append([]byte{PDUUnconfirmed << 4, SvcWhoIs}, EncodeWhoIs(instance)...)); err != nil {
		return IAm{}, err
	}
	tm := time.NewTimer(t.Timeout)
	defer tm.Stop()
	select {
	case <-ctx.Done():
		return IAm{}, ctx.Err()
	case i := <-ch:
		return i, nil
	case <-tm.C:
		return IAm{}, fmt.Errorf("no I-Am from device %d", instance)
	}
}

// ---- confirmed requests ----------------------------------------------------

// errNoAnswer is a transaction that timed out; the request is resent.
var errNoAnswer = errors.New("no answer")

// Request sends a confirmed request and waits for its reply, resending on
// Timeout up to retries more times. A request longer than the device's
// max APDU is segmented when the device accepts that; a segmented reply
// is acknowledged window by window and reassembled.
func (c *Client) Request(ctx context.Context, t Target, service byte, data []byte) (APDU, error) {
	to, discovered, err := c.via(ctx, t)
	if err != nil {
		return APDU{}, err
	}
	segmented := len(data)+4 > t.MaxAPDU
	if segmented && (!t.RecvSeg || t.MaxAPDU <= 6) {
		return APDU{}, fmt.Errorf("a request of %d octets exceeds the device's max APDU of %d and it does not accept segmented requests", len(data)+4, t.MaxAPDU)
	}
	ch := make(chan APDU, 2*MaxWindow+4)
	c.Mu.Lock()
	var key PendingKey
	found := false
	for range 256 {
		c.next++
		key = PendingKey{t.Key(), c.next}
		if c.Pending[key] == nil {
			found = true
			break
		}
	}
	if !found {
		c.Mu.Unlock()
		return APDU{}, errors.New("no free invoke ID for " + t.Key())
	}
	c.Pending[key] = ch
	c.Mu.Unlock()
	defer func() {
		c.Mu.Lock()
		delete(c.Pending, key)
		c.Mu.Unlock()
	}()
	tx := &txn{c: c, to: to, d: t.Dest, id: key.ID, ch: ch, timeout: t.Timeout}
	for attempt := 0; attempt <= t.Retries; attempt++ {
		tx.drain()
		var a APDU
		var early bool
		var err error
		if segmented {
			a, early, err = tx.sendSegmented(ctx, service, data, t.MaxAPDU-6, t.Retries)
		} else {
			err = tx.send(confirmedMax(key.ID, service, c.ownMax(), data))
		}
		if err == nil && !early {
			a, err = tx.reply(ctx)
		}
		if errors.Is(err, errNoAnswer) {
			continue
		}
		if err != nil {
			return a, err
		}
		switch a.Typ {
		case PDUError:
			return a, ErrorFrom(a.Data)
		case PDUReject:
			return a, &RejectPDU{Reason: a.Reason}
		case PDUAbort:
			return a, &AbortPDU{Reason: a.Reason}
		}
		return a, nil
	}
	if discovered {
		c.forgetRouter(t.Net, to) // look for the router again next time
	}
	return APDU{}, fmt.Errorf("no answer from %s after %d attempts", t.Describe(), t.Retries+1)
}

func (d Dest) Describe() string {
	if d.Net != 0 {
		return fmt.Sprintf("network %d MAC %x", d.Net, d.MAC)
	}
	return d.Key()
}

// txn is one confirmed transaction's state as the requester (clause 5.4.4).
type txn struct {
	c       *Client
	to      net.Addr
	d       Dest
	id      byte
	ch      chan APDU
	timeout time.Duration
}

func (x *txn) send(a []byte) error { return x.c.SendAPDU(x.to, x.d, true, a) }

// drain drops what an earlier attempt left queued.
func (x *txn) drain() {
	for {
		select {
		case <-x.ch:
		default:
			return
		}
	}
}

// sendSegmented sends a request in segments of size octets: the first
// alone, then windows of the size the device's Segment-ACK allows, going
// back to the segment after the one a Segment-ACK names. It returns a
// reply that arrives early (such as an Abort) with early set, or nothing
// once every segment is acknowledged.
func (x *txn) sendSegmented(ctx context.Context, service byte, data []byte, size, retries int) (reply APDU, early bool, err error) {
	var parts [][]byte
	for len(data) > 0 {
		n := min(size, len(data))
		parts = append(parts, data[:n])
		data = data[n:]
	}
	if len(parts) > 255 {
		return APDU{}, false, fmt.Errorf("a request of %d segments is too long", len(parts))
	}
	acked, next, window, tries := -1, 0, 1, 0
	for acked < len(parts)-1 {
		for end := min(acked+1+window, len(parts)); next < end; next++ {
			if err := x.send(ConfirmedSegment(x.id, service, byte(next), MaxWindow, next < len(parts)-1, parts[next])); err != nil {
				return APDU{}, false, err
			}
		}
		t := time.NewTimer(x.timeout)
	wait:
		for {
			select {
			case <-ctx.Done():
				t.Stop()
				return APDU{}, false, ctx.Err()
			case a := <-x.ch:
				if a.Typ != PDUSegmentACK {
					t.Stop()
					return a, true, nil
				}
				if !a.Srv {
					continue
				}
				j := -1
				for k := next - 1; k > acked; k-- {
					if byte(k) == a.Seq {
						j = k
						break
					}
				}
				if j < 0 && !(a.NAK && byte(acked) == a.Seq && acked >= 0) {
					continue // stale
				}
				if j >= 0 {
					acked = j
				}
				next, window, tries = acked+1, max(1, min(int(a.Window), 127)), 0
				break wait
			case <-t.C:
				tries++
				if tries > retries {
					_ = x.send(EncodeAbort(x.id, AbortOther, false))
					return APDU{}, false, errNoAnswer
				}
				next = acked + 1 // resend the window
				break wait
			}
		}
		t.Stop()
	}
	return APDU{}, false, nil
}

// inWindow is the InWindow function of clause 5.4.2.1: whether seqA is
// less than window ahead of seqB, modulo 256.
func inWindow(seqA, seqB, window byte) bool { return seqA-seqB < window }

// duplicateInWindow is the DuplicateInWindow function of clause 5.4.2.2:
// whether seqA is a segment of the current, incomplete window already
// received.
func duplicateInWindow(seqA, initial, last byte) bool {
	received := last - initial
	if received == 0 {
		return false
	}
	return seqA-initial <= received
}

// reply waits for the answer to a request, acknowledging and reassembling
// a segmented Complex-ACK as the requester's SEGMENTED_CONF state does
// (clause 5.4.4.4): a Segment-ACK for the first segment, each full window
// and the last; duplicates in the window dropped up to Ndup (the window
// size) and then a negative Segment-ACK; any other segment out of order a
// negative Segment-ACK naming the last good one. A segmented Complex-ACK
// whose first segment is not number 0 is aborted with
// invalid-apdu-in-this-state (clause 5.4.4.3); a stalled reply is aborted
// and the request resent.
func (x *txn) reply(ctx context.Context) (APDU, error) {
	t := time.NewTimer(x.timeout)
	defer t.Stop()
	var (
		got                   []byte
		started               bool
		last, initial, window byte
		service               byte
		count, dups           int
	)
	ack := func(seq byte, nak bool) error { return x.send(SegmentACK(x.id, seq, window, nak, false)) }
	abort := func(reason byte) { _ = x.send(EncodeAbort(x.id, reason, false)) }
	for {
		select {
		case <-ctx.Done():
			return APDU{}, ctx.Err()
		case <-t.C:
			if started {
				abort(AbortOther)
			}
			return APDU{}, errNoAnswer
		case a := <-x.ch:
			if a.Typ == PDUSegmentACK || a.Typ == PDUAbort && !a.Srv {
				continue // left over from sending the request; not from the server
			}
			if a.Typ != PDUComplexACK || !a.Seg {
				return a, nil
			}
			switch {
			case !started:
				if a.Seq != 0 {
					abort(abortInvalidAPDU)
					return APDU{}, fmt.Errorf("the first segment of the reply is number %d, not 0 (aborted: invalid-apdu-in-this-state)", a.Seq)
				}
				// ActualWindowSize: at most the proposed window, 1..127.
				started, service, window = true, a.Service, max(1, min(a.Window, MaxWindow))
				got, last, initial, count = append(got, a.Data...), 0, 0, 1
				if !a.More {
					if err := ack(last, false); err != nil {
						return APDU{}, err
					}
					return APDU{Typ: PDUComplexACK, InvokeID: x.id, Service: service, Data: got}, nil
				}
				if err := ack(0, false); err != nil {
					return APDU{}, err
				}
				t.Reset(x.timeout)
				continue
			case a.Seq == last+1:
				got, last, count = append(got, a.Data...), a.Seq, count+1
			case duplicateInWindow(a.Seq, initial, last):
				dups++
				if dups > int(window) { // TooManyDuplicateSegmentsReceived
					if err := ack(last, true); err != nil {
						return APDU{}, err
					}
					dups = 0
				}
				t.Reset(x.timeout)
				continue
			default: // SegmentReceivedOutOfOrder
				if err := ack(last, true); err != nil {
					return APDU{}, err
				}
				initial, dups = last, 0
				t.Reset(x.timeout)
				continue
			}
			if count > MaxSegments {
				abort(AbortBufferOverflow)
				return APDU{}, fmt.Errorf("the reply has more than %d segments", MaxSegments)
			}
			if !a.More {
				if err := ack(last, false); err != nil {
					return APDU{}, err
				}
				return APDU{Typ: PDUComplexACK, InvokeID: x.id, Service: service, Data: got}, nil
			}
			if a.Seq == initial+window { // LastSegmentOfGroupReceived
				if err := ack(last, false); err != nil {
					return APDU{}, err
				}
				initial, dups = last, 0
			}
			t.Reset(x.timeout)
		}
	}
}

// ReadProperty reads one property.
func (c *Client) ReadProperty(ctx context.Context, t Target, o ObjectID, prop uint32) ([]any, error) {
	a, err := c.Request(ctx, t, SvcReadProperty, EncodeReadProperty(o, prop))
	if err != nil {
		return nil, err
	}
	if a.Typ != PDUComplexACK {
		return nil, errors.New("ReadProperty was not answered with a Complex-ACK")
	}
	r, err := DecodeReadPropertyAck(a.Data)
	return r.Values, err
}

// ReadMultiple reads several properties in one request.
func (c *Client) ReadMultiple(ctx context.Context, t Target, refs []PropRef) ([]PropResult, error) {
	a, err := c.Request(ctx, t, SvcReadPropertyMultiple, EncodeReadPropertyMultiple(refs))
	if err != nil {
		return nil, err
	}
	if a.Typ != PDUComplexACK {
		return nil, errors.New("ReadPropertyMultiple was not answered with a Complex-ACK")
	}
	return DecodeReadPropertyMultipleAck(a.Data)
}

func (c *Client) WriteProperty(ctx context.Context, t Target, o ObjectID, prop uint32, v any, prio int) error {
	data, err := EncodeWriteProperty(o, prop, v, prio)
	if err != nil {
		return err
	}
	a, err := c.Request(ctx, t, SvcWriteProperty, data)
	if err != nil {
		return err
	}
	if a.Typ != PDUSimpleACK {
		return errors.New("WriteProperty was not answered with a Simple-ACK")
	}
	return nil
}

func (c *Client) SubscribeCOV(ctx context.Context, t Target, process uint32, o ObjectID, confirmed bool, lifetime uint32) error {
	a, err := c.Request(ctx, t, SvcSubscribeCOV, encodeSubscribeCOV(process, o, confirmed, lifetime))
	if err != nil {
		return err
	}
	if a.Typ != PDUSimpleACK {
		return errors.New("SubscribeCOV was not answered with a Simple-ACK")
	}
	return nil
}
