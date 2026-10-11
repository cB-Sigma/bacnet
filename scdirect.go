package bacnet

// The BACnet/SC node switch and direct connections (Annex AB.4): with
// directConnect.listen the node accepts direct connections (subprotocol
// Dc.bsc.bacnet.org only) as the accepting peer of AB.6.2.3 and answers
// Address-Resolution with its accept URIs; with directConnect.initiate it
// resolves a node's URIs through the hub the first time it sends to it
// and opens a direct connection, used from then on for unicasts to that
// node (broadcasts always go to the hub). Messages on a direct connection
// carry no VMACs (AB.4.2.1); received ones are from the connection peer
// (AB.4.2.2). Only one direct connection exists per peer.

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/cB-Sigma/tlsx"
	"github.com/coder/websocket"
)

// NodeSwitch keeps a node's direct connections.
type NodeSwitch struct {
	N        *SCNode
	Listen   string   // accept direct connections here ("" for no)
	URIs     []string // URIs advertised in Address-Resolution-ACK; default from the listener
	Initiate bool
	// Reconnect is the wait before trying a peer again after a failure
	// (the minimum reconnect time, AB.4).
	Reconnect time.Duration

	Mu      sync.Mutex
	ctx     context.Context
	Conns   map[VMAC]*dcConn
	pending map[VMAC]time.Time // Address-Resolution sent or last failure, per peer
	srv     *http.Server
	addr    net.Addr
	wg      sync.WaitGroup
}

type dcConn struct {
	C         *SCConn
	Peer      SCConnect
	initiated bool
	stop      context.CancelFunc
	done      chan struct{}
}

// DirectConnect settings (12.56: SC_Direct_Connect_Initiate_Enable,
// SC_Direct_Connect_Accept_Enable, SC_Direct_Connect_Accept_URIs,
// SC_Direct_Connect_Binding).
type DirectConnect struct {
	Listen     string   `json:"listen,omitempty"`
	AcceptURIs []string `json:"acceptUris,omitempty"`
	Initiate   bool     `json:"initiate,omitempty"`
}

func (s *NodeSwitch) start(ctx context.Context) {
	s.Mu.Lock()
	s.ctx = ctx
	if s.Conns == nil {
		s.Conns, s.pending = map[VMAC]*dcConn{}, map[VMAC]time.Time{}
	}
	s.Mu.Unlock()
	if s.Listen != "" && s.srv == nil {
		if err := s.serve(); err != nil {
			s.N.Log.Warn("BACnet/SC direct connections not accepted", "listen", s.Listen, "error", err)
		}
	}
}

func (s *NodeSwitch) serve() error {
	raw, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return err
	}
	s.addr = raw.Addr()
	s.srv = &http.Server{Handler: http.HandlerFunc(s.accept), ReadHeaderTimeout: s.N.ConnectWait,
		ErrorLog: slog.NewLogLogger(s.N.Log.Handler(), slog.LevelDebug)}
	go func() { _ = s.srv.Serve(tlsx.NewListener(raw, s.N.Creds.Config(true, ""))) }()
	return nil
}

// AcceptURIs are the URIs sent in Address-Resolution-ACK.
func (s *NodeSwitch) AcceptURIs() []string {
	if len(s.URIs) > 0 || s.addr == nil {
		return s.URIs
	}
	return []string{"wss://" + s.addr.String() + "/"}
}

func (s *NodeSwitch) close() {
	if s.srv != nil {
		_ = s.srv.Close()
	}
	s.Mu.Lock()
	var all []*dcConn
	for _, c := range s.Conns {
		all = append(all, c)
	}
	s.Mu.Unlock()
	for _, c := range all {
		c.stop()
		<-c.done
	}
	s.wg.Wait()
}

// Connected reports whether a direct connection to v is established.
func (s *NodeSwitch) Connected(v VMAC) bool {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Conns[v] != nil
}

// Send sends an NPDU to v over its direct connection; sent is false when
// there is none (the caller uses the hub). The first time, with initiate
// Set, it asks v for its URIs through the hub.
func (s *NodeSwitch) send(v VMAC, npdu []byte, opts []SCOption) (bool, error) {
	s.Mu.Lock()
	c := s.Conns[v]
	ask := false
	if c == nil && s.Initiate {
		if last, ok := s.pending[v]; !ok || time.Since(last) > s.Reconnect {
			s.pending[v], ask = time.Now(), true
		}
	}
	s.Mu.Unlock()
	if ask {
		d := v
		_ = s.N.sendHub(SCMsg{Fn: SCAddrResolution, ID: s.N.id(), dest: &d})
	}
	if c == nil {
		return false, nil
	}
	return true, c.C.Send(context.Background(), SCMsg{Fn: scEncapsulated, ID: s.N.id(), dataOpts: opts, Payload: npdu})
}

// resolved dials the first URI of an Address-Resolution-ACK that
// connects (AB.4.1).
func (s *NodeSwitch) resolved(v VMAC, uris []string) {
	s.Mu.Lock()
	ctx := s.ctx
	have := s.Conns[v] != nil
	s.Mu.Unlock()
	if have || ctx == nil || ctx.Err() != nil {
		return
	}
	for _, u := range uris {
		c, err := s.N.dialPeer(ctx, u, SCDirectProtocol, &v)
		if err != nil {
			s.N.Log.Debug("BACnet/SC direct connection failed", "peer", v, "uri", u, "error", err)
			continue
		}
		s.add(c, true)
		return
	}
	s.Mu.Lock()
	s.pending[v] = time.Now()
	s.Mu.Unlock()
}

// Add registers an established connection, replacing an older one to the
// same peer, and serves it.
func (s *NodeSwitch) add(c *SCConn, initiated bool) {
	s.Mu.Lock()
	old := s.Conns[c.peer.VMAC]
	cctx, stop := context.WithCancel(s.ctx)
	dc := &dcConn{C: c, Peer: c.peer, initiated: initiated, stop: stop, done: make(chan struct{})}
	s.Conns[c.peer.VMAC] = dc
	delete(s.pending, c.peer.VMAC)
	s.Mu.Unlock()
	if old != nil {
		old.stop()
	}
	s.N.Log.Info("BACnet/SC direct connection established", "peer", c.peer.VMAC, "initiated", initiated)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer close(dc.done)
		s.run(cctx, dc)
		s.Mu.Lock()
		if s.Conns[dc.Peer.VMAC] == dc {
			delete(s.Conns, dc.Peer.VMAC)
		}
		s.Mu.Unlock()
	}()
}

// run serves one direct connection until it ends: NPDUs to the BVLL
// entity as from the peer, Heartbeat-Request answered, and (initiating
// peer) a heartbeat when idle; ctx ending is a local disconnection.
func (s *NodeSwitch) run(ctx context.Context, dc *dcConn) {
	c := dc.C
	defer func() { _ = c.WS.CloseNow() }()
	rx := make(chan []byte, 16)
	rerr := make(chan error, 1)
	rctx, stopRead := context.WithCancel(context.Background())
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
	hb := time.NewTicker(max(min(s.N.Heartbeat, s.N.DisconnectWait)/4, 10*time.Millisecond))
	defer hb.Stop()
	var hbSent, discSent time.Time
	for {
		select {
		case <-ctx.Done():
			if discSent.IsZero() {
				discSent = time.Now()
				_ = c.Send(context.Background(), SCMsg{Fn: SCDisconnectReq, ID: s.N.id()})
			}
			ctx = context.Background()
		case <-rerr:
			return
		case now := <-hb.C:
			if !discSent.IsZero() {
				if now.Sub(discSent) > s.N.DisconnectWait {
					return
				}
				continue
			}
			if !dc.initiated {
				continue
			}
			last := time.Unix(0, c.lastRx.Load())
			switch {
			case !hbSent.IsZero() && last.After(hbSent):
				hbSent = time.Time{}
			case !hbSent.IsZero() && now.Sub(hbSent) > s.N.Heartbeat:
				discSent = now
				_ = c.Send(context.Background(), SCMsg{Fn: SCDisconnectReq, ID: s.N.id()})
			case hbSent.IsZero() && now.Sub(last) >= s.N.Heartbeat:
				hbSent = now
				_ = c.Send(context.Background(), SCMsg{Fn: SCHeartbeatReq, ID: s.N.id()})
			}
		case b := <-rx:
			m, e := DecodeSC(b)
			if e != nil {
				if !e.silent && !m.broadcast() && !isResponse(m.Fn) {
					_ = c.Send(context.Background(), SCMsg{Fn: SCResult, ID: m.ID, Payload: resultPayload(m.Fn, e, e.why)})
				}
				continue
			}
			if !discSent.IsZero() {
				if m.Fn == SCDisconnectACK || m.Fn == SCResult {
					_ = c.WS.Close(websocket.StatusNormalClosure, "")
					return
				}
				continue
			}
			if m.broadcast() || m.dest != nil && *m.dest != s.N.MyVMAC() {
				continue // broadcasts never come over a direct connection (AB.4.2.2)
			}
			if e := m.mustUnderstand(); e != nil {
				if !isResponse(m.Fn) {
					_ = c.Send(context.Background(), SCMsg{Fn: SCResult, ID: m.ID, Payload: resultPayload(m.Fn, e, e.why)})
				}
				continue
			}
			switch m.Fn {
			case scEncapsulated:
				from := dc.Peer.VMAC
				if m.orig != nil {
					from = *m.orig
				}
				if s.N.OnNPDU != nil {
					s.N.OnNPDU(from, m.Payload, m.dataOpts)
				}
			case SCHeartbeatReq:
				_ = c.Send(context.Background(), SCMsg{Fn: SCHeartbeatACK, ID: m.ID})
			case SCDisconnectReq:
				_ = c.Send(context.Background(), SCMsg{Fn: SCDisconnectACK, ID: m.ID})
				_ = c.WS.Close(websocket.StatusNormalClosure, "")
				return
			}
		}
	}
}

// accept takes one direct connection as the accepting peer (AB.6.2.3).
func (s *NodeSwitch) accept(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{SCDirectProtocol}, InsecureSkipVerify: true})
	if err != nil {
		return
	}
	if ws.Subprotocol() != SCDirectProtocol {
		_ = ws.Close(websocket.StatusProtocolError, "subprotocol "+SCDirectProtocol+" required")
		return
	}
	ws.SetReadLimit(1 << 16)
	c := &SCConn{WS: ws}
	c.lastRx.Store(time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(r.Context(), s.N.ConnectWait)
	defer cancel()
	var req SCMsg
	for {
		b, err := c.Read(ctx)
		if err != nil {
			_ = ws.CloseNow()
			return
		}
		m, e := DecodeSC(b)
		if e == nil && m.Fn == SCConnectRequest {
			req = m
			break
		}
	}
	cr, _ := DecodeConnect(req.Payload)
	me := s.N.MyVMAC()
	s.Mu.Lock()
	collision := cr.VMAC == me && cr.UUID != s.N.UUID
	for v, x := range s.Conns {
		if v == cr.VMAC && x.Peer.UUID != cr.UUID {
			collision = true
		}
	}
	started := s.ctx != nil
	s.Mu.Unlock()
	if collision || !started {
		_ = c.Send(r.Context(), SCMsg{Fn: SCResult, ID: req.ID, Payload: resultPayload(SCConnectRequest, nak(ErrCodeNodeDuplicateVMAC, "duplicate VMAC"), "")})
		_ = ws.Close(websocket.StatusNormalClosure, "")
		return
	}
	acc := SCConnect{VMAC: me, UUID: s.N.UUID, MaxBVLC: SCMaxBVLC, MaxNPDU: SCMaxNPDU}
	hello := SCOption{Typ: SCOptHello, HasData: true, Data: []byte{0}}
	if err := c.Send(r.Context(), SCMsg{Fn: SCConnectAccept, ID: req.ID, DestOpts: []SCOption{hello}, Payload: acc.Bytes()}); err != nil {
		_ = ws.CloseNow()
		return
	}
	c.peer = cr
	s.add(c, false)
	// Keep the handler until the connection ends (the HTTP server owns it).
	s.Mu.Lock()
	dc := s.Conns[cr.VMAC]
	s.Mu.Unlock()
	if dc != nil {
		<-dc.done
	}
}

// sendHub sends a message through the hub connection.
func (n *SCNode) sendHub(m SCMsg) error {
	n.Mu.Lock()
	c := n.Conn
	n.Mu.Unlock()
	if c == nil {
		return errors.New("no BACnet/SC hub connection")
	}
	return c.Send(context.Background(), m)
}
