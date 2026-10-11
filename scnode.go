package bacnet

// The BACnet/SC node of the IPE (Annex AB.1.1): its BVLL entity and hub
// connector. The connector keeps one hub connection, to the primary hub
// or, when that cannot be reached, to the failover hub while it keeps
// trying the primary (AB.5.2). Connections follow the initiating peer
// State machine of AB.6.2.2 with the heartbeat of AB.6.3. Direct
// Connections (AB.4) are not initiated or accepted: Address-Resolution
// is answered with a NAK (AB.3.3).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/tlsx"
	"github.com/coder/websocket"
)

// Sizes the IPE advertises: an NPDU of the largest APDU plus the longest
// NPDU header, and room for header options (AB.5.1 asks hubs for 1497
// Octets of NPDU and 4192 of options).
const (
	SCMaxNPDU = 1497
	SCMaxBVLC = 1497 + 4192 + 16
)

// SCConn is one BACnet/SC connection over a secure WebSocket.
type SCConn struct {
	WS   *websocket.Conn
	TLS  *tlsx.Conn // for key updates; nil when not known
	peer SCConnect  // what the peer's Connect-Request or Connect-Accept said
	URI  string

	lastRx atomic.Int64 // unix nanoseconds of the last message received
	lastTx atomic.Int64 // unix nanoseconds of the last message sent

	KaHeartbeats atomic.Int64 // Heartbeat-Requests sent before key updates on an idle connection
}

func (c *SCConn) Send(ctx context.Context, m SCMsg) error {
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := c.WS.Write(wctx, websocket.MessageBinary, m.Encode())
	if err == nil {
		c.lastTx.Store(time.Now().UnixNano())
	}
	return err
}

// Read returns the next BVLC message's octets. A non-binary frame closes
// the connection with 1003 (AB.7.5.3).
func (c *SCConn) Read(ctx context.Context) ([]byte, error) {
	for {
		typ, b, err := c.WS.Read(ctx)
		if err != nil {
			return nil, err
		}
		c.lastRx.Store(time.Now().UnixNano())
		if typ != websocket.MessageBinary {
			_ = c.WS.Close(websocket.StatusUnsupportedData, "BVLC messages are binary")
			return nil, errors.New("a WebSocket text frame was received")
		}
		if len(b) > SCMaxBVLC {
			continue // longer than the node's maximum BVLC length: discarded
		}
		return b, nil
	}
}

// SCConnStatus mirrors BACnetSCHubConnection (clause 21): the state of a
// hub connection, when it last connected and disconnected, and the last
// error.
type SCConnStatus struct {
	State        string    `json:"connectionState"`
	Connected    time.Time `json:"connectTimestamp,omitzero"`
	Disconnected time.Time `json:"disconnectTimestamp,omitzero"`
	ErrorCode    uint16    `json:"errorCode,omitempty"`
	Error        string    `json:"errorDetails,omitempty"`
}

// BACnetSCConnectionState names (clause 21).
const (
	SCNotConnected   = "not-connected"
	SCConnected      = "connected"
	SCDisconnectedEr = "disconnected-with-errors"
	SCFailed         = "failed-to-connect"
)

// scErr is a connection failure with its BACnet error code.
type scErr struct {
	code uint16
	err  error
}

func (e *scErr) Error() string { return e.err.Error() }
func (e *scErr) Unwrap() error { return e.err }

// SCNode is the IPE's BACnet/SC network port.
type SCNode struct {
	Log            *slog.Logger
	Creds          *SCTLS
	Primary        string
	Failover       string
	UUID           [16]byte
	MinReconnect   time.Duration
	MaxReconnect   time.Duration
	ConnectWait    time.Duration
	DisconnectWait time.Duration
	Heartbeat      time.Duration
	KeyUpdate      time.Duration
	OnNPDU         func(from VMAC, npdu []byte, dataOpts []SCOption)
	OnChange       func()      // hub connector state changed
	Dc             *NodeSwitch // direct connections (scdirect.go); nil for none
	// DataOpts are the data options sent with every NPDU this node
	// originates (AB.2.3: Secure Path, Identity, proprietary).
	DataOpts []SCOption
	// NoHello leaves the Hello header option out of this node's
	// Connect-Request, for hubs and nodes written to an edition of the
	// standard before 2024 that do not skip it (bacnet-stack 1.6.1's hub
	// crashed on it).
	NoHello bool

	Mu       sync.Mutex
	VMAC     VMAC
	Conn     *SCConn
	which    byte // hub connector state: 0 none, 1 primary, 2 failover
	status   [3]SCConnStatus
	nextID   uint16
	cancel   context.CancelFunc
	done     chan struct{}
	RxResult []scResultInfo // BVLC-Results received, newest last (bounded)
}

// SCStatus is the hub connector's state as the Network Port object
// States it (12.56: SC_Hub_Connector_State, SC_Primary_Hub_Connection_Status,
// SC_Failover_Hub_Connection_Status) with the node's VMAC and UUID.
type SCStatus struct {
	HubConnectorState string        `json:"hubConnectorState"`
	Primary           SCConnStatus  `json:"primaryHubConnectionStatus"`
	Failover          *SCConnStatus `json:"failoverHubConnectionStatus,omitempty"`
	VMAC              string        `json:"vmac"`
	UUID              string        `json:"deviceUuid"`
}

var HubConnectorStates = [...]string{"no-hub-connection", "connected-to-primary", "connected-to-failover"}

func (n *SCNode) State() SCStatus {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	s := SCStatus{HubConnectorState: HubConnectorStates[n.which], Primary: n.status[1], VMAC: n.VMAC.String(), UUID: UUIDString(n.UUID)}
	if n.Failover != "" {
		f := n.status[2]
		s.Failover = &f
	}
	return s
}

func (n *SCNode) id() uint16 {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	n.nextID++
	return n.nextID
}

func (n *SCNode) MyVMAC() VMAC {
	n.Mu.Lock()
	defer n.Mu.Unlock()
	return n.VMAC
}

// Start runs the hub connector until close.
func (n *SCNode) Start(ctx context.Context) {
	ctx, n.cancel = context.WithCancel(ctx)
	n.done = make(chan struct{})
	if n.Dc != nil {
		n.Dc.start(ctx)
	}
	for i := range n.status {
		n.status[i].State = SCNotConnected
	}
	go func() {
		defer close(n.done)
		n.run(ctx)
	}()
}

func (n *SCNode) Close() {
	if n.Dc != nil {
		n.Dc.close()
	}
	if n.cancel != nil {
		n.cancel()
		<-n.done
	}
}

// Unicast sends an NPDU to a node through the hub (AB.3.4).
func (n *SCNode) Unicast(to VMAC, npdu []byte) error {
	if n.Dc != nil {
		if sent, err := n.Dc.send(to, npdu, n.DataOpts); sent {
			return err
		}
	}
	return n.sendNPDU(to, npdu)
}

// Broadcast sends an NPDU to every node of the network through the hub.
func (n *SCNode) Broadcast(npdu []byte) error { return n.sendNPDU(broadcastVMAC, npdu) }

func (n *SCNode) sendNPDU(to VMAC, npdu []byte) error {
	n.Mu.Lock()
	c := n.Conn
	n.Mu.Unlock()
	if c == nil {
		return errors.New("no BACnet/SC hub connection")
	}
	d := to
	return c.Send(context.Background(), SCMsg{Fn: scEncapsulated, ID: n.id(), dest: &d, dataOpts: n.DataOpts, Payload: npdu})
}

// run is the hub connector (AB.5.2): primary first; the failover while
// the primary cannot be reached, trying the primary again every
// Reconnect time; the wait between failed rounds grows from the minimum
// to the maximum reconnect time (AB.6.1).
func (n *SCNode) run(ctx context.Context) {
	delay := n.MinReconnect
	for ctx.Err() == nil {
		if c, err := n.connect(ctx, 1); err == nil {
			delay = n.MinReconnect
			n.serve(ctx, c, 1, nil)
			continue // a lost primary connection is re-established first
		}
		if n.Failover != "" {
			if c, err := n.connect(ctx, 2); err == nil {
				delay = n.MinReconnect
				n.onFailover(ctx, c)
				continue
			}
		}
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		delay = min(2*delay, n.MaxReconnect)
	}
}

// onFailover serves the failover connection while trying the primary;
// when the primary answers, the failover connection is closed (AB.5.2).
func (n *SCNode) onFailover(ctx context.Context, c *SCConn) {
	lost := make(chan struct{})
	fctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		defer close(lost)
		n.serve(fctx, c, 2, nil)
	}()
	delay := n.MinReconnect
	for {
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			<-lost
			return
		case <-lost:
			t.Stop()
			return
		case <-t.C:
		}
		p, err := n.connect(ctx, 1)
		if err != nil {
			delay = min(2*delay, n.MaxReconnect)
			continue
		}
		stop() // local disconnection of the failover connection
		<-lost
		n.serve(ctx, p, 1, nil)
		return
	}
}

func (n *SCNode) uri(which byte) string {
	if which == 2 {
		return n.Failover
	}
	return n.Primary
}

func (n *SCNode) setStatus(which byte, f func(s *SCConnStatus)) {
	n.Mu.Lock()
	f(&n.status[which])
	n.Mu.Unlock()
}

// connect establishes a hub connection as the initiating peer: a secure
// WebSocket with the hub subprotocol, then Connect-Request and
// Connect-Accept within the connect wait time (AB.6.2.2).
func (n *SCNode) connect(ctx context.Context, which byte) (*SCConn, error) {
	c, err := n.dial(ctx, which)
	if err != nil {
		code := uint16(errCodeWebsocketError)
		var se *scErr
		if errors.As(err, &se) {
			code = se.code
		}
		n.setStatus(which, func(s *SCConnStatus) {
			s.State, s.ErrorCode, s.Error = SCFailed, code, err.Error()
		})
		n.Log.Debug("BACnet/SC hub connection failed", "hub", n.uri(which), "error", err)
		return nil, err
	}
	n.setStatus(which, func(s *SCConnStatus) {
		s.State, s.Connected, s.ErrorCode, s.Error = SCConnected, time.Now(), 0, ""
	})
	n.Mu.Lock()
	n.Conn, n.which = c, which
	n.Mu.Unlock()
	n.Log.Info("BACnet/SC hub connected", "hub", c.URI, "vmac", n.MyVMAC())
	if n.OnChange != nil {
		n.OnChange()
	}
	return c, nil
}

func (n *SCNode) dial(ctx context.Context, which byte) (*SCConn, error) {
	return n.dialPeer(ctx, n.uri(which), SCHubProtocol, nil)
}

// dialPeer establishes a BACnet/SC connection as the initiating peer
// (AB.6.2.2) with subprotocol proto; want, when set, is the VMAC the
// accepting peer must have (a direct connection).
func (n *SCNode) dialPeer(ctx context.Context, uri, proto string, want *VMAC) (*SCConn, error) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "wss" || u.Host == "" {
		return nil, &scErr{ErrCodeWebsocketSchemeNotSupp, fmt.Errorf("hub URI %q is not a wss URI", uri)}
	}
	var tconn *tlsx.Conn
	cfg := n.Creds.Config(false, u.Hostname())
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, &scErr{errCodeTCPError, err}
			}
			tc := tlsx.Client(raw, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, &scErr{ErrCodeTLSError, err}
			}
			tconn = tc
			return tc, nil
		},
		ForceAttemptHTTP2: false,
	}
	dctx, cancel := context.WithTimeout(ctx, n.ConnectWait)
	defer cancel()
	ws, resp, err := websocket.Dial(dctx, uri, &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr}, Subprotocols: []string{proto}})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		var se *scErr
		if errors.As(err, &se) {
			return nil, err
		}
		return nil, &scErr{errCodeHTTPError, err}
	}
	if ws.Subprotocol() != proto {
		_ = ws.Close(websocket.StatusProtocolError, "subprotocol "+proto+" required")
		return nil, &scErr{errCodeWebsocketProtocolError, fmt.Errorf("%s did not accept subprotocol %s", uri, proto)}
	}
	ws.SetReadLimit(1 << 16)
	c := &SCConn{WS: ws, TLS: tconn, URI: uri}
	c.lastRx.Store(time.Now().UnixNano())
	// AWAITING_ACCEPT
	n.Mu.Lock()
	me := SCConnect{VMAC: n.VMAC, UUID: n.UUID, MaxBVLC: SCMaxBVLC, MaxNPDU: SCMaxNPDU}
	noHello := n.NoHello
	n.Mu.Unlock()
	id := n.id()
	var opts []SCOption
	if !noHello {
		opts = []SCOption{{Typ: SCOptHello, HasData: true, Data: []byte{0}}} // capabilities: no identity relay
	}
	if err := c.Send(ctx, SCMsg{Fn: SCConnectRequest, ID: id, DestOpts: opts, Payload: me.Bytes()}); err != nil {
		_ = ws.CloseNow()
		return nil, &scErr{errCodeWebsocketError, err}
	}
	wctx, wcancel := context.WithTimeout(ctx, n.ConnectWait)
	defer wcancel()
	for {
		b, err := c.Read(wctx)
		if err != nil {
			_ = ws.CloseNow()
			if wctx.Err() != nil && ctx.Err() == nil {
				return nil, &scErr{errCodeWebsocketError, errors.New("no Connect-Accept within the connect wait time")}
			}
			return nil, &scErr{websocketCloseCode(int(websocket.CloseStatus(err))), err}
		}
		m, e := DecodeSC(b)
		if e != nil {
			continue
		}
		switch {
		case m.Fn == SCConnectAccept && m.ID == id:
			c.peer, _ = DecodeConnect(m.Payload)
			if want != nil && c.peer.VMAC != *want {
				_ = c.Send(ctx, SCMsg{Fn: SCDisconnectReq, ID: n.id()})
				_ = ws.Close(websocket.StatusNormalClosure, "")
				return nil, &scErr{errCodeInconsistentParameters, fmt.Errorf("%s is node %s, not %s", uri, c.peer.VMAC, *want)}
			}
			return c, nil
		case m.Fn == SCResult && m.Payload[0] == SCConnectRequest:
			r := DecodeResult(m.Payload)
			_ = ws.Close(websocket.StatusNormalClosure, "")
			if r.NAK && r.Code == ErrCodeNodeDuplicateVMAC {
				n.Mu.Lock()
				old := n.VMAC
				n.VMAC = RandomVMAC() // AB.6.2.2: a new Random-48 VMAC before reconnecting
				n.Log.Warn("BACnet/SC hub reports a duplicate VMAC; choosing a new one", "old", old, "new", n.VMAC)
				n.Mu.Unlock()
			}
			return nil, &scErr{r.Code, fmt.Errorf("the hub refused Connect-Request: error code %d %s", r.Code, r.details)}
		}
	}
}

// Serve runs an established hub connection until it is lost or ctx ends
// (then the local disconnection of AB.6.2.2 is made).
func (n *SCNode) serve(ctx context.Context, c *SCConn, which byte, _ chan struct{}) {
	rx := make(chan []byte, 16)
	rerr := make(chan error, 1)
	rctx, stopRead := context.WithCancel(context.Background())
	defer func() { _ = c.WS.CloseNow() }()
	defer stopRead()
	go func() {
		for {
			b, err := c.Read(rctx)
			if err != nil {
				rerr <- err
				return
			}
			select {
			case rx <- b:
			case <-rctx.Done():
				return
			}
		}
	}()
	var lostErr error
	defer func() {
		n.Mu.Lock()
		if n.Conn == c {
			n.Conn, n.which = nil, 0
		}
		s := &n.status[which]
		s.Disconnected = time.Now()
		if lostErr != nil {
			s.State, s.Error = SCDisconnectedEr, lostErr.Error()
			s.ErrorCode = websocketCloseCode(int(websocket.CloseStatus(lostErr)))
		} else {
			s.State = SCNotConnected
		}
		n.Mu.Unlock()
		if n.OnChange != nil {
			n.OnChange()
		}
	}()
	hb := time.NewTicker(max(min(n.Heartbeat, n.DisconnectWait)/4, 10*time.Millisecond))
	defer hb.Stop()
	var ku <-chan time.Time
	if n.KeyUpdate > 0 && c.TLS != nil {
		t := time.NewTicker(n.KeyUpdate)
		defer t.Stop()
		ku = t.C
	}
	var hbSent time.Time // Heartbeat-Request outstanding since
	var hbID uint16
	lastKU := time.Now() // the previous key update (or the connection)
	var discID uint16
	var discSent time.Time
	for {
		select {
		case <-ctx.Done():
			if discSent.IsZero() {
				discID, discSent = n.id(), time.Now()
				_ = c.Send(context.Background(), SCMsg{Fn: SCDisconnectReq, ID: discID})
			}
			ctx = context.Background() // DISCONNECTING: wait for the ACK
			continue
		case err := <-rerr:
			if !discSent.IsZero() {
				return
			}
			lostErr = err
			n.Log.Info("BACnet/SC hub connection lost", "hub", c.URI, "error", err)
			return
		case now := <-ku:
			// Go's crypto/tls and tlsx (a Go-based hub) end a connection
			// after more than 16 KeyUpdates with no application data
			// between them. When the connection carried no message one
			// way or the other since the previous update, a
			// Heartbeat-Request goes first (AB.6.3; its Heartbeat-ACK is
			// awaited as for an idle connection), unless one is
			// outstanding.
			last := time.Unix(0, c.lastRx.Load())
			if !hbSent.IsZero() && last.After(hbSent) {
				hbSent = time.Time{} // answered, as the heartbeat tick sees it
			}
			idle := last.Before(lastKU) || time.Unix(0, c.lastTx.Load()).Before(lastKU)
			if idle && hbSent.IsZero() && discSent.IsZero() {
				hbID, hbSent = n.id(), now
				if c.Send(context.Background(), SCMsg{Fn: SCHeartbeatReq, ID: hbID}) == nil {
					c.KaHeartbeats.Add(1)
				}
			}
			lastKU = now
			if err := c.TLS.SendKeyUpdate(true); err != nil {
				n.Log.Debug("BACnet/SC key update failed", "error", err)
			}
		case now := <-hb.C:
			if !discSent.IsZero() {
				if now.Sub(discSent) > n.DisconnectWait {
					_ = c.WS.Close(websocket.StatusNormalClosure, "")
					return
				}
				continue
			}
			last := time.Unix(0, c.lastRx.Load())
			switch {
			case !hbSent.IsZero() && last.After(hbSent):
				hbSent = time.Time{}
			case !hbSent.IsZero() && now.Sub(hbSent) > n.Heartbeat:
				// No Heartbeat-ACK: local disconnection (AB.6.3).
				n.Log.Warn("BACnet/SC hub did not answer Heartbeat-Request", "hub", c.URI)
				lostErr = errors.New("no Heartbeat-ACK from the hub")
				discID, discSent = n.id(), now
				_ = c.Send(context.Background(), SCMsg{Fn: SCDisconnectReq, ID: discID})
			case hbSent.IsZero() && now.Sub(last) >= n.Heartbeat:
				hbID, hbSent = n.id(), now
				_ = c.Send(context.Background(), SCMsg{Fn: SCHeartbeatReq, ID: hbID})
			}
		case b := <-rx:
			m, e := DecodeSC(b)
			if e != nil {
				n.refuse(c, m, e)
				continue
			}
			if !discSent.IsZero() {
				if (m.Fn == SCDisconnectACK && m.ID == discID) || (m.Fn == SCResult && m.Payload[0] == SCDisconnectReq) {
					_ = c.WS.Close(websocket.StatusNormalClosure, "")
					return
				}
				continue
			}
			if m.Fn == SCDisconnectReq {
				_ = c.Send(context.Background(), SCMsg{Fn: SCDisconnectACK, ID: m.ID})
				_ = c.WS.Close(websocket.StatusNormalClosure, "")
				lostErr = errors.New("the hub disconnected")
				return
			}
			n.handle(c, m)
		}
	}
}

// refuse answers a malformed message with a BVLC-Result NAK when it was
// Unicast and not a response (AB.3.1.4, AB.3.1.5).
func (n *SCNode) refuse(c *SCConn, m SCMsg, e *scNAK) {
	n.Log.Debug("BACnet/SC message refused", "function", m.Fn, "error", e)
	if e.silent || m.broadcast() || isResponse(m.Fn) {
		return
	}
	r := SCMsg{Fn: SCResult, ID: m.ID, dest: m.orig, Payload: resultPayload(m.Fn, e, e.why)}
	_ = c.Send(context.Background(), r)
}

// Handle is the BVLL entity's reception (AB.3, AB.3.4, AB.5.4).
func (n *SCNode) handle(c *SCConn, m SCMsg) {
	if m.dest != nil && !m.broadcast() {
		return // a hub connector drops unicast messages that name a destination (AB.5.4)
	}
	if e := m.mustUnderstand(); e != nil {
		if !m.broadcast() && !isResponse(m.Fn) {
			n.refuse(c, m, e)
		}
		return
	}
	reply := func(r SCMsg) {
		r.dest = m.orig
		_ = c.Send(context.Background(), r)
	}
	switch m.Fn {
	case scEncapsulated:
		if m.orig == nil || n.OnNPDU == nil {
			return // the hub function originates no NPDUs
		}
		n.OnNPDU(*m.orig, m.Payload, m.dataOpts)
	case SCResult:
		r := DecodeResult(m.Payload)
		n.Mu.Lock()
		n.RxResult = append(n.RxResult, r)
		if len(n.RxResult) > 16 {
			n.RxResult = n.RxResult[1:]
		}
		n.Mu.Unlock()
		if r.NAK {
			n.Log.Info("BACnet/SC NAK received", "function", r.Fn, "class", r.Class, "code", r.Code, "details", r.details)
		}
	case SCHeartbeatReq:
		reply(SCMsg{Fn: SCHeartbeatACK, ID: m.ID})
	case scAdvSolicitation:
		n.Mu.Lock()
		adv := scAdvert{hubStatus: n.which, acceptsDirect: n.Dc != nil && n.Dc.Listen != "", maxBVLC: SCMaxBVLC, maxNPDU: SCMaxNPDU}
		n.Mu.Unlock()
		// Not a response: a new message ID (AB.3.2).
		reply(SCMsg{Fn: scAdvertisement, ID: n.id(), Payload: adv.bytes()})
	case SCAddrResolution:
		if m.broadcast() {
			return
		}
		if n.Dc == nil || n.Dc.Listen == "" {
			reply(SCMsg{Fn: SCResult, ID: m.ID, Payload: resultPayload(m.Fn, nak(ErrCodeOptionalNotSupported, "direct connections are not accepted"), "")})
			return
		}
		reply(SCMsg{Fn: scAddrResACK, ID: m.ID, Payload: []byte(strings.Join(n.Dc.AcceptURIs(), " "))})
	case scAddrResACK:
		if n.Dc != nil && m.orig != nil {
			go n.Dc.resolved(*m.orig, strings.Fields(string(m.Payload)))
		}
	case scProprietary:
		if m.broadcast() {
			return
		}
		reply(SCMsg{Fn: SCResult, ID: m.ID, Payload: resultPayload(m.Fn, nak(errCodeBVLCProprietaryUnknown, "no proprietary functions"), "")})
	}
}
