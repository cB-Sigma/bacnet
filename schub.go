package bacnet

// The BACnet/SC hub function (Annex AB.5.3): it accepts hub connections
// over secure WebSockets with the hub subprotocol only, establishes them
// as the accepting peer of AB.6.2.3 (duplicate device UUIDs replace the
// old connection, VMAC collisions are refused with NODE_DUPLICATE_VMAC),
// forwards unicast messages to the connection whose peer has the
// Destination VMAC (adding the originating VMAC and removing the
// destination) and copies broadcasts to every other connection (adding
// the originating VMAC, keeping the destination). It answers
// Heartbeat-Request and Disconnect-Request addressed to it.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cB-Sigma/tlsx"
	"github.com/coder/websocket"
)

// SCHub is a hub function.
type SCHub struct {
	log         *slog.Logger
	creds       *SCTLS
	VMAC        VMAC     // of the network port holding the hub (sent in Connect-Accept)
	UUID        [16]byte // of the device holding the hub
	connectWait time.Duration

	Mu     sync.Mutex
	peers  map[VMAC]*hubPeer
	Failed []SCFailedRequest // SC_Failed_Connection_Requests (12.56.99), newest last
	srv    *http.Server
	ln     net.Listener

	Forwarded atomic.Int64 // messages forwarded
}

type hubPeer struct {
	c         *SCConn
	peer      SCConnect
	remote    string
	connected time.Time
	gone      chan struct{}
}

// SCFailedRequest mirrors BACnetSCFailedConnectionRequest (clause 21).
type SCFailedRequest struct {
	Time      time.Time `json:"timestamp"`
	Peer      string    `json:"peerAddress"`
	VMAC      string    `json:"peerVmac,omitempty"`
	UUID      string    `json:"peerUuid,omitempty"`
	ErrorCode uint16    `json:"errorCode"`
	Error     string    `json:"errorDetails,omitempty"`
}

// SCHubConn mirrors BACnetSCHubFunctionConnection (clause 21).
type SCHubConn struct {
	State     string    `json:"connectionState"`
	Connected time.Time `json:"connectTimestamp"`
	Peer      string    `json:"peerAddress"`
	VMAC      string    `json:"peerVmac"`
	UUID      string    `json:"peerUuid"`
}

func NewHub(log *slog.Logger, creds *SCTLS, vmac VMAC, uuid [16]byte, connectWait time.Duration) *SCHub {
	return &SCHub{log: log, creds: creds, VMAC: vmac, UUID: uuid, connectWait: connectWait, peers: map[VMAC]*hubPeer{}}
}

// Listen serves the hub function on addr (TLS 1.3 with mutual
// authentication) until close.
func (h *SCHub) Listen(addr string) (net.Addr, error) {
	raw, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	type tlsKey struct{}
	h.ln = tlsx.NewListener(raw, h.creds.Config(true, ""))
	h.srv = &http.Server{
		Handler:           h,
		ReadHeaderTimeout: h.connectWait,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, tlsKey{}, c)
		},
		ErrorLog: slog.NewLogLogger(h.log.Handler(), slog.LevelDebug),
	}
	go func() { _ = h.srv.Serve(h.ln) }()
	return raw.Addr(), nil
}

func (h *SCHub) Close() {
	if h.srv != nil {
		_ = h.srv.Close()
	}
	h.Mu.Lock()
	peers := make([]*hubPeer, 0, len(h.peers))
	for _, p := range h.peers {
		peers = append(peers, p)
	}
	h.Mu.Unlock()
	for _, p := range peers {
		_ = p.c.WS.CloseNow()
	}
}

// Connections is SC_Hub_Function_Connection_Status (12.56).
func (h *SCHub) Connections() []SCHubConn {
	h.Mu.Lock()
	defer h.Mu.Unlock()
	var out []SCHubConn
	for _, p := range h.peers {
		out = append(out, SCHubConn{State: SCConnected, Connected: p.connected, Peer: p.remote, VMAC: p.peer.VMAC.String(), UUID: UUIDString(p.peer.UUID)})
	}
	return out
}

func (h *SCHub) fail(remote string, c *SCConnect, code uint16, why string) {
	f := SCFailedRequest{Time: time.Now(), Peer: remote, ErrorCode: code, Error: why}
	if c != nil {
		f.VMAC, f.UUID = c.VMAC.String(), UUIDString(c.UUID)
	}
	h.Mu.Lock()
	h.Failed = append(h.Failed, f)
	if len(h.Failed) > 32 {
		h.Failed = h.Failed[1:]
	}
	h.Mu.Unlock()
}

// ServeHTTP accepts one hub connection.
func (h *SCHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{SCHubProtocol}, InsecureSkipVerify: true})
	if err != nil {
		h.log.Debug("BACnet/SC hub: WebSocket upgrade refused", "peer", r.RemoteAddr, "error", err)
		return
	}
	if ws.Subprotocol() != SCHubProtocol {
		// Only the hub subprotocol is accepted (AB.5.3.1).
		h.fail(r.RemoteAddr, nil, errCodeWebsocketProtocolError, "no hub subprotocol")
		_ = ws.Close(websocket.StatusProtocolError, "subprotocol "+SCHubProtocol+" required")
		return
	}
	ws.SetReadLimit(1 << 16)
	c := &SCConn{WS: ws}
	c.lastRx.Store(time.Now().UnixNano())
	ctx := r.Context()
	// AWAITING_REQUEST
	wctx, cancel := context.WithTimeout(ctx, h.connectWait)
	var req SCMsg
	for {
		b, err := c.Read(wctx)
		if err != nil {
			h.log.Debug("BACnet/SC hub: no Connect-Request", "peer", r.RemoteAddr, "error", err)
			cancel()
			_ = ws.CloseNow()
			return
		}
		m, e := DecodeSC(b)
		if e != nil {
			if !e.silent && !isResponse(m.Fn) {
				_ = c.Send(ctx, SCMsg{Fn: SCResult, ID: m.ID, Payload: resultPayload(m.Fn, e, e.why)})
			}
			continue
		}
		if m.Fn == SCConnectRequest {
			req = m
			break
		}
	}
	cancel()
	cr, _ := DecodeConnect(req.Payload)
	p := &hubPeer{c: c, peer: cr, remote: r.RemoteAddr, connected: time.Now(), gone: make(chan struct{})}
	h.Mu.Lock()
	var replaced *hubPeer
	for _, q := range h.peers {
		if q.peer.UUID == cr.UUID {
			replaced = q // a known device reconnecting: the old connection goes
		}
	}
	if old := h.peers[cr.VMAC]; old != nil && old != replaced {
		h.Mu.Unlock()
		// VMAC collision with a different device (AB.6.2.3).
		h.fail(r.RemoteAddr, &cr, ErrCodeNodeDuplicateVMAC, "VMAC in use by another device")
		_ = c.Send(ctx, SCMsg{Fn: SCResult, ID: req.ID, Payload: resultPayload(SCConnectRequest, nak(ErrCodeNodeDuplicateVMAC, "duplicate VMAC"), "")})
		_ = ws.Close(websocket.StatusNormalClosure, "")
		return
	}
	if replaced != nil {
		delete(h.peers, replaced.peer.VMAC)
	}
	h.peers[cr.VMAC] = p
	h.Mu.Unlock()
	if replaced != nil {
		go h.disconnect(replaced)
	}
	hello := SCOption{Typ: SCOptHello, HasData: true, Data: []byte{0}}
	acc := SCConnect{VMAC: h.VMAC, UUID: h.UUID, MaxBVLC: SCMaxBVLC, MaxNPDU: SCMaxNPDU}
	if err := c.Send(ctx, SCMsg{Fn: SCConnectAccept, ID: req.ID, DestOpts: []SCOption{hello}, Payload: acc.Bytes()}); err != nil {
		h.drop(p)
		return
	}
	h.log.Debug("BACnet/SC hub connection accepted", "vmac", cr.VMAC, "peer", r.RemoteAddr)
	h.serve(p)
}

func (h *SCHub) drop(p *hubPeer) {
	h.Mu.Lock()
	if h.peers[p.peer.VMAC] == p {
		delete(h.peers, p.peer.VMAC)
	}
	h.Mu.Unlock()
	_ = p.c.WS.CloseNow()
}

// disconnect is a local disconnection of a peer's connection.
func (h *SCHub) disconnect(p *hubPeer) {
	_ = p.c.Send(context.Background(), SCMsg{Fn: SCDisconnectReq, ID: 1})
	select {
	case <-p.gone:
	case <-time.After(h.connectWait):
		_ = p.c.WS.CloseNow()
	}
}

// Serve relays one connection's messages (CONNECTED).
func (h *SCHub) serve(p *hubPeer) {
	defer close(p.gone)
	defer h.drop(p)
	ctx := context.Background()
	for {
		b, err := p.c.Read(ctx)
		if err != nil {
			return
		}
		m, e := DecodeSC(b)
		if e != nil {
			if !e.silent && !m.broadcast() && !isResponse(m.Fn) {
				_ = p.c.Send(ctx, SCMsg{Fn: SCResult, ID: m.ID, dest: m.orig, Payload: resultPayload(m.Fn, e, e.why)})
			}
			continue
		}
		if m.dest != nil {
			h.forward(p, m)
			continue
		}
		// For the hub itself.
		if e := m.mustUnderstand(); e != nil {
			if !isResponse(m.Fn) {
				_ = p.c.Send(ctx, SCMsg{Fn: SCResult, ID: m.ID, Payload: resultPayload(m.Fn, e, e.why)})
			}
			continue
		}
		switch m.Fn {
		case SCHeartbeatReq:
			_ = p.c.Send(ctx, SCMsg{Fn: SCHeartbeatACK, ID: m.ID})
		case SCDisconnectReq:
			_ = p.c.Send(ctx, SCMsg{Fn: SCDisconnectACK, ID: m.ID})
			_ = p.c.WS.Close(websocket.StatusNormalClosure, "")
			return
		case SCDisconnectACK:
			_ = p.c.WS.Close(websocket.StatusNormalClosure, "")
			return
		}
	}
}

// Forward relays a message naming a destination VMAC (AB.5.3.2, AB.5.3.3);
// the message ID and options are unchanged.
func (h *SCHub) forward(from *hubPeer, m SCMsg) {
	orig := from.peer.VMAC
	m.orig = &orig
	h.Mu.Lock()
	var to []*hubPeer
	if m.broadcast() {
		for _, q := range h.peers {
			if q != from {
				to = append(to, q)
			}
		}
	} else if q := h.peers[*m.dest]; q != nil && q != from {
		to = append(to, q)
		m.dest = nil
	}
	h.Mu.Unlock()
	b := m.Encode()
	h.Forwarded.Add(int64(len(to)))
	for _, q := range to {
		if err := q.c.WS.Write(context.Background(), websocket.MessageBinary, b); err != nil && !errors.Is(err, net.ErrClosed) {
			h.log.Debug("BACnet/SC hub could not forward", "to", q.peer.VMAC, "error", err)
		}
	}
}
