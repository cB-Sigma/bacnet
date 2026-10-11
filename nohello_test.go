// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package bacnet

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/cB-Sigma/tlsx"
	"github.com/coder/websocket"
)

// connectRequestOf runs a hub that records the Connect-Request a node
// sends and accepts it.
func connectRequestOf(t *testing.T, p *testPKI, noHello bool) SCMsg {
	t.Helper()
	got := make(chan SCMsg, 1)
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
		got <- m
		_ = c.Send(r.Context(), SCMsg{Fn: SCConnectAccept, ID: m.ID, Payload: SCConnect{MaxBVLC: 1600, MaxNPDU: 1497}.Bytes()})
		for {
			if _, err := c.Read(r.Context()); err != nil {
				return
			}
		}
	})}
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg := p.creds(t, "capture").Config(true, "")
	go func() { _ = srv.Serve(tlsx.NewListener(raw, cfg)) }()
	t.Cleanup(func() { _ = srv.Close() })
	n, _ := testNode(t, p.creds(t, "n"), "wss://"+raw.Addr().String()+"/", "", RandomVMAC())
	n.NoHello = noHello
	n.Start(context.Background())
	defer n.Close()
	select {
	case m := <-got:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no Connect-Request")
	}
	return SCMsg{}
}

// bacnet-stack 1.6.1's hub crashed on the Hello header option of a
// Connect-Request; with NoHello the node sends none, and by default it
// still sends Hello.
func TestSCNoHello(t *testing.T) {
	p := newTestPKI(t)
	m := connectRequestOf(t, p, false)
	if len(m.DestOpts) != 1 || m.DestOpts[0].Typ != SCOptHello {
		t.Errorf("default Connect-Request options %+v, want Hello", m.DestOpts)
	}
	m = connectRequestOf(t, p, true)
	if m.Fn != SCConnectRequest || len(m.DestOpts) != 0 {
		t.Errorf("NoHello Connect-Request %+v, want no header options", m)
	}
}
