package bacnet

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// Timed TLS 1.3 key updates on an idle hub connection: Go's crypto/tls
// and tlsx (our hub) end a connection after more than 16 KeyUpdates with
// no application data between them, so the hub connector sends a
// Heartbeat-Request (AB.6.3) before an update when the connection carried
// nothing one way or the other since the previous one.

const (
	scKARekey     = 20 * time.Millisecond
	scKAIntervals = 50
)

// stdHub is a minimal hub function on Go's crypto/tls (standard library):
// it accepts the connection and answers Heartbeat-Request, counting them.
func stdHub(t *testing.T, p *testPKI) (string, *atomic.Int64) {
	t.Helper()
	c := p.ca.leaf(t, "stdhub", time.Now().Add(-time.Hour))
	pair, err := tls.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	var heartbeats atomic.Int64
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{SCHubProtocol}})
		if err != nil {
			return
		}
		c := &SCConn{WS: ws}
		b, err := c.Read(r.Context())
		if err != nil {
			return
		}
		m, _ := DecodeSC(b)
		_ = c.Send(r.Context(), SCMsg{Fn: SCConnectAccept, ID: m.ID, Payload: SCConnect{MaxBVLC: 1600, MaxNPDU: 1497}.Bytes()})
		for {
			b, err := c.Read(r.Context())
			if err != nil {
				return
			}
			m, e := DecodeSC(b)
			if e == nil && m.Fn == SCHeartbeatReq {
				heartbeats.Add(1)
				_ = c.Send(r.Context(), SCMsg{Fn: SCHeartbeatACK, ID: m.ID})
			}
		}
	})}
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{pair}, ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	go func() { _ = srv.Serve(tls.NewListener(raw, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "wss://" + raw.Addr().String() + "/", &heartbeats
}

// Covers: SIG-TLSKA-007
func TestSCIdleConnectionKeyUpdates(t *testing.T) {
	p := newTestPKI(t)
	run := func(t *testing.T, uri string) *SCConn {
		t.Helper()
		n, _ := testNode(t, p.creds(t, "n"), uri, "", RandomVMAC())
		n.KeyUpdate = scKARekey // heartbeat stays 5 s: longer than the test
		n.Start(context.Background())
		t.Cleanup(n.Close)
		waitState(t, n, "connected-to-primary")
		n.Mu.Lock()
		c := n.Conn
		n.Mu.Unlock()
		time.Sleep(scKAIntervals * scKARekey)
		n.Mu.Lock()
		same := n.Conn == c
		n.Mu.Unlock()
		if s := n.State(); !same || s.Primary.State != SCConnected {
			t.Fatalf("the hub connection did not last: same %v, status %+v", same, s)
		}
		if k := c.TLS.ConnectionState().Ext.KeyUpdatesSent; k < scKAIntervals/2 {
			t.Fatalf("%d key updates", k)
		}
		if h := c.KaHeartbeats.Load(); h < scKAIntervals/4 {
			t.Fatalf("%d heartbeats before key updates", h)
		}
		return c
	}
	t.Run("sigmam2m hub", func(t *testing.T) {
		h, uri := startHub(t, p, "127.0.0.1:0")
		run(t, uri)
		if len(h.Connections()) != 1 {
			t.Fatalf("%d hub connections", len(h.Connections()))
		}
	})
	t.Run("crypto/tls hub", func(t *testing.T) {
		uri, heartbeats := stdHub(t, p)
		run(t, uri)
		// Observed on the wire at the hub.
		if n := heartbeats.Load(); n < scKAIntervals/4 {
			t.Fatalf("the hub saw %d Heartbeat-Requests", n)
		}
	})
}
