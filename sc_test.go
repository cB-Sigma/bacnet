// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package bacnet

// BACnet/SC end to end over real TLS 1.3 WebSockets on localhost: a hub
// function (schub.go) and hub connectors (scnode.go).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/tlsx"
	"github.com/coder/websocket"
)

// ---- test PKI ---------------------------------------------------------------

// testCreds are PEM credentials of a test node.
type testCreds struct {
	Certificate, PrivateKey, Issuers string
}

// loadTestTLS is the TLS profile of c, with no hooks.
func loadTestTLS(t *testing.T, c testCreds) *SCTLS {
	t.Helper()
	cert, err := tlsx.X509KeyPair([]byte(c.Certificate), []byte(c.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	var issuers []*x509.Certificate
	for rest := []byte(c.Issuers); ; {
		var blk *pem.Block
		if blk, rest = pem.Decode(rest); blk == nil {
			break
		}
		ic, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		issuers = append(issuers, ic)
	}
	return &SCTLS{Certificate: cert, Issuers: issuers}
}

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

var serial int64 = 100

func newTestCA(t *testing.T, name string, parent *testCA) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// leaf is an operational certificate and key signed by ca, valid from
// notBefore for a day; with a ServerAuth-only EKU on purpose (AB.7.4
// forbids checking it by default).
func (ca *testCA) leaf(t *testing.T, name string, notBefore time.Time) testCreds {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: notBefore, NotAfter: notBefore.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kd, _ := x509.MarshalECPrivateKey(key)
	return testCreds{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		PrivateKey:  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})),
	}
}

type testPKI struct {
	ca, other, inter *testCA
}

func newTestPKI(t *testing.T) *testPKI {
	ca := newTestCA(t, "site CA", nil)
	return &testPKI{ca: ca, other: newTestCA(t, "other CA", nil), inter: newTestCA(t, "intermediate", ca)}
}

// Creds are credentials for name signed by the site CA, trusting it.
func (p *testPKI) creds(t *testing.T, name string) *SCTLS {
	t.Helper()
	c := p.ca.leaf(t, name, time.Now().Add(-time.Hour))
	c.Issuers = p.ca.pem
	return loadTestTLS(t, c)
}

// ---- hub and nodes ----------------------------------------------------------

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func startHub(t *testing.T, p *testPKI, addr string) (*SCHub, string) {
	t.Helper()
	h := NewHub(quiet(), p.creds(t, "hub"), VMAC{0x02, 0xee, 0, 0, 0, 1}, NewUUID(), 2*time.Second)
	a, err := h.Listen(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return h, "wss://" + a.String() + "/"
}

type rxNPDU struct {
	from VMAC
	b    []byte
	opts []SCOption
}

func testNode(t *testing.T, creds *SCTLS, primary, failover string, vmac VMAC) (*SCNode, chan rxNPDU) {
	t.Helper()
	rx := make(chan rxNPDU, 32)
	n := &SCNode{
		Log: quiet(), Creds: creds, Primary: primary, Failover: failover, UUID: NewUUID(), VMAC: vmac,
		MinReconnect: 50 * time.Millisecond, MaxReconnect: 200 * time.Millisecond, ConnectWait: 2 * time.Second,
		DisconnectWait: time.Second, Heartbeat: 5 * time.Second,
		OnNPDU: func(from VMAC, b []byte, opts []SCOption) {
			rx <- rxNPDU{from, append([]byte(nil), b...), opts}
		},
	}
	return n, rx
}

func waitState(t *testing.T, n *SCNode, want string) SCStatus {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s := n.State()
		if s.HubConnectorState == want {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("hub connector state %s, want %s (%+v)", s.HubConnectorState, want, s)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func recv(t *testing.T, rx chan rxNPDU) rxNPDU {
	t.Helper()
	select {
	case r := <-rx:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("no NPDU received")
	}
	return rxNPDU{}
}

func none(t *testing.T, rx chan rxNPDU) {
	t.Helper()
	select {
	case r := <-rx:
		t.Fatalf("unexpected NPDU from %s", r.from)
	case <-time.After(150 * time.Millisecond):
	}
}

// Covers: SIG-IPE-1977
func TestSCHubForwarding(t *testing.T) {
	p := newTestPKI(t)
	h, uri := startHub(t, p, "127.0.0.1:0")
	va, vb, vc := VMAC{0x02, 0, 0, 0, 0, 0xa}, VMAC{0x02, 0, 0, 0, 0, 0xb}, VMAC{0x02, 0, 0, 0, 0, 0xc}
	a, rxa := testNode(t, p.creds(t, "a"), uri, "", va)
	b, rxb := testNode(t, p.creds(t, "b"), uri, "", vb)
	c, rxc := testNode(t, p.creds(t, "c"), uri, "", vc)
	for _, n := range []*SCNode{a, b, c} {
		n.Start(context.Background())
		defer n.Close()
		waitState(t, n, "connected-to-primary")
	}
	if n := len(h.Connections()); n != 3 {
		t.Fatalf("%d hub connections", n)
	}
	if err := a.Unicast(vb, []byte{1, 0, 0x10, 0x08}); err != nil {
		t.Fatal(err)
	}
	if r := recv(t, rxb); r.from != va || string(r.b) != "\x01\x00\x10\x08" {
		t.Fatalf("b got %+v", r)
	}
	none(t, rxc)
	none(t, rxa)
	if err := b.Broadcast([]byte{1, 0, 0x10, 0x08}); err != nil {
		t.Fatal(err)
	}
	if r := recv(t, rxa); r.from != vb {
		t.Fatalf("a got %+v", r)
	}
	if r := recv(t, rxc); r.from != vb {
		t.Fatalf("c got %+v", r)
	}
	none(t, rxb) // never back to the sender (AB.5.1)
	// Unknown destination: discarded.
	if err := a.Unicast(VMAC{0x02, 9, 9, 9, 9, 9}, []byte{1, 0}); err != nil {
		t.Fatal(err)
	}
	none(t, rxb)
	none(t, rxc)
}

// rawNode is a hand-driven hub connection for checking the hub's
// replies octet by octet.

type rawNode struct {
	ws *websocket.Conn
}

func dialRaw(t *testing.T, p *testPKI, uri, proto string) (*rawNode, error) {
	t.Helper()
	cfg := p.creds(t, "raw").Config(false, "")
	tr := &http.Transport{DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tc := tlsx.Client(raw, cfg)
		return tc, tc.HandshakeContext(ctx)
	}}
	ws, _, err := websocket.Dial(context.Background(), uri, &websocket.DialOptions{HTTPClient: &http.Client{Transport: tr}, Subprotocols: []string{proto}})
	if err != nil {
		return nil, err
	}
	return &rawNode{ws: ws}, nil
}

func (r *rawNode) send(t *testing.T, b []byte) {
	t.Helper()
	if err := r.ws.Write(context.Background(), websocket.MessageBinary, b); err != nil {
		t.Fatal(err)
	}
}

func (r *rawNode) read(t *testing.T) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, b, err := r.ws.Read(ctx)
	return b, err
}

func connectReq(v VMAC, u [16]byte, id uint16) []byte {
	return SCMsg{Fn: SCConnectRequest, ID: id, Payload: SCConnect{VMAC: v, UUID: u, MaxBVLC: 1600, MaxNPDU: 1497}.Bytes()}.Encode()
}

// Covers: SIG-IPE-1978
func TestSCConnectionEstablishment(t *testing.T) {
	p := newTestPKI(t)
	h, uri := startHub(t, p, "127.0.0.1:0")
	v := VMAC{0x02, 1, 1, 1, 1, 1}
	u1, u2 := NewUUID(), NewUUID()
	r1, err := dialRaw(t, p, uri, SCHubProtocol)
	if err != nil {
		t.Fatal(err)
	}
	r1.send(t, connectReq(v, u1, 0x0101))
	b, err := r1.read(t)
	if err != nil {
		t.Fatal(err)
	}
	m, e := DecodeSC(b)
	if e != nil || m.Fn != SCConnectAccept || m.ID != 0x0101 || len(m.DestOpts) != 1 || m.DestOpts[0].Typ != SCOptHello {
		t.Fatalf("Connect-Accept = %+v %v", m, e)
	}
	if acc, _ := DecodeConnect(m.Payload); acc.VMAC != h.VMAC || acc.UUID != h.UUID {
		t.Fatalf("accept payload %+v", acc)
	}
	t.Run("VMAC collision from another device is refused", func(t *testing.T) {
		r2, err := dialRaw(t, p, uri, SCHubProtocol)
		if err != nil {
			t.Fatal(err)
		}
		r2.send(t, connectReq(v, u2, 0x0202))
		b, err := r2.read(t)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := DecodeSC(b)
		if r := DecodeResult(m.Payload); m.Fn != SCResult || m.ID != 0x0202 || !r.NAK || r.Fn != SCConnectRequest || r.Class != 7 || r.Code != ErrCodeNodeDuplicateVMAC {
			t.Fatalf("result %+v %+v", m, r)
		}
		if _, err := r2.read(t); err == nil {
			t.Fatal("the refused connection stayed open")
		}
	})
	t.Run("the same device reconnecting replaces its old connection", func(t *testing.T) {
		r3, err := dialRaw(t, p, uri, SCHubProtocol)
		if err != nil {
			t.Fatal(err)
		}
		r3.send(t, connectReq(v, u1, 0x0303))
		if b, _ := r3.read(t); b == nil || b[0] != SCConnectAccept {
			t.Fatalf("got %X", b)
		}
		// The old connection gets a Disconnect-Request.
		b, err = r1.read(t)
		if err != nil || b[0] != SCDisconnectReq {
			t.Fatalf("old connection got %X, %v", b, err)
		}
		r1.send(t, SCMsg{Fn: SCDisconnectACK, ID: uint16(b[2])<<8 | uint16(b[3])}.Encode())
	})
	t.Run("a node told of a duplicate VMAC picks a new Random-48 VMAC", func(t *testing.T) {
		n, _ := testNode(t, p.creds(t, "n"), uri, "", v) // v is taken by u1
		n.Start(context.Background())
		defer n.Close()
		s := waitState(t, n, "connected-to-primary")
		if s.VMAC == v.String() || s.VMAC[1] != '2' {
			t.Fatalf("node VMAC %s", s.VMAC)
		}
	})
	t.Run("hub answers heartbeat and malformed messages", func(t *testing.T) {
		r4, err := dialRaw(t, p, uri, SCHubProtocol)
		if err != nil {
			t.Fatal(err)
		}
		r4.send(t, connectReq(VMAC{0x02, 4, 4, 4, 4, 4}, NewUUID(), 1))
		_, _ = r4.read(t)
		r4.send(t, hx(t, "0A 00 BEEF"))
		if b, _ := r4.read(t); string(b) != string(hx(t, "0B 00 BEEF")) {
			t.Fatalf("heartbeat answer %X", b)
		}
		r4.send(t, hx(t, "0D 00 0042"))
		b, _ := r4.read(t)
		if m, _ := DecodeSC(b); m.Fn != SCResult || m.ID != 0x42 || DecodeResult(m.Payload).Code != ErrCodeBVLCFunctionUnknown {
			t.Fatalf("unknown function answer %X", b)
		}
		r4.send(t, hx(t, "0A 02 0043 7F 0003 0309 39"))
		b, _ = r4.read(t)
		if m, _ := DecodeSC(b); m.Fn != SCResult || DecodeResult(m.Payload).Code != ErrCodeHeaderNotUnderstood || DecodeResult(m.Payload).Marker != 0x7f {
			t.Fatalf("must-understand answer %X", b)
		}
		r4.send(t, SCMsg{Fn: SCDisconnectReq, ID: 9}.Encode())
		if b, _ := r4.read(t); string(b) != string(hx(t, "09 00 0009")) {
			t.Fatalf("disconnect answer %X", b)
		}
	})
}

// Covers: SIG-IPE-1979
func TestSCFailover(t *testing.T) {
	p := newTestPKI(t)
	// Reserve an address for the primary, which starts later.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	primaryAddr := ln.Addr().String()
	_ = ln.Close()
	fh, furi := startHub(t, p, "127.0.0.1:0")
	n, _ := testNode(t, p.creds(t, "n"), "wss://"+primaryAddr+"/", furi, RandomVMAC())
	n.Start(context.Background())
	defer n.Close()
	s := waitState(t, n, "connected-to-failover")
	if s.Primary.State != SCFailed || s.Failover == nil || s.Failover.State != SCConnected {
		t.Fatalf("status %+v", s)
	}
	ph, _ := startHub(t, p, primaryAddr)
	waitState(t, n, "connected-to-primary")
	// The failover connection is closed once the primary is back.
	deadline := time.Now().Add(3 * time.Second)
	for len(fh.Connections()) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if len(fh.Connections()) != 0 || len(ph.Connections()) != 1 {
		t.Fatalf("failover %d, primary %d connections", len(fh.Connections()), len(ph.Connections()))
	}
	// Losing the primary goes back to the failover.
	ph.Close()
	waitState(t, n, "connected-to-failover")
}

// silentHub accepts a hub connection and then answers nothing, so the
// node's heartbeat goes unanswered.
func silentHub(t *testing.T, p *testPKI) (string, *sync.WaitGroup, *[]byte) {
	t.Helper()
	creds := p.creds(t, "silent")
	var mu sync.Mutex
	var got []byte
	var wg sync.WaitGroup
	wg.Add(1)
	var once sync.Once
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
			mu.Lock()
			got = append(got, b[0])
			mu.Unlock()
			if b[0] == SCDisconnectReq {
				once.Do(wg.Done)
			}
		}
	})}
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() { _ = srv.Serve(tlsx.NewListener(raw, creds.Config(true, ""))) }()
	t.Cleanup(func() { _ = srv.Close() })
	return "wss://" + raw.Addr().String() + "/", &wg, &got
}

// Covers: SIG-IPE-1980
func TestSCHeartbeatAndDisconnect(t *testing.T) {
	p := newTestPKI(t)
	t.Run("idle connection kept alive by Heartbeat-Request", func(t *testing.T) {
		h, uri := startHub(t, p, "127.0.0.1:0")
		n, _ := testNode(t, p.creds(t, "n"), uri, "", RandomVMAC())
		n.Heartbeat = 100 * time.Millisecond
		n.Start(context.Background())
		waitState(t, n, "connected-to-primary")
		time.Sleep(600 * time.Millisecond) // several heartbeat periods, all answered
		if s := n.State(); s.HubConnectorState != "connected-to-primary" || s.Primary.State != SCConnected {
			t.Fatalf("status %+v", s)
		}
		n.Close() // local disconnection: Disconnect-Request, the hub ACKs
		if s := n.State(); s.Primary.State != SCNotConnected {
			t.Fatalf("after close %+v", s)
		}
		deadline := time.Now().Add(2 * time.Second)
		for len(h.Connections()) != 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if len(h.Connections()) != 0 {
			t.Fatal("the hub kept the connection after Disconnect-Request")
		}
	})
	t.Run("no Heartbeat-ACK leads to a local disconnection", func(t *testing.T) {
		uri, wg, got := silentHub(t, p)
		n, _ := testNode(t, p.creds(t, "n"), uri, "", RandomVMAC())
		n.Heartbeat = 100 * time.Millisecond
		n.Start(context.Background())
		defer n.Close()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("no Disconnect-Request after an unanswered heartbeat")
		}
		if (*got)[0] != SCHeartbeatReq {
			t.Fatalf("messages %X", *got)
		}
	})
}

// Covers: SIG-IPE-1983
func TestSCKeyUpdate(t *testing.T) {
	p := newTestPKI(t)
	_, uri := startHub(t, p, "127.0.0.1:0")
	a, _ := testNode(t, p.creds(t, "a"), uri, "", VMAC{0x02, 0, 0, 0, 0, 1})
	b, rxb := testNode(t, p.creds(t, "b"), uri, "", VMAC{0x02, 0, 0, 0, 0, 2})
	a.KeyUpdate = 50 * time.Millisecond
	for _, n := range []*SCNode{a, b} {
		n.Start(context.Background())
		defer n.Close()
		waitState(t, n, "connected-to-primary")
	}
	time.Sleep(300 * time.Millisecond)
	a.Mu.Lock()
	cs := a.Conn.TLS.ConnectionState()
	a.Mu.Unlock()
	if cs.Ext.KeyUpdatesSent == 0 {
		t.Fatal("no TLS KeyUpdate sent")
	}
	if err := a.Unicast(b.MyVMAC(), []byte{1, 0}); err != nil {
		t.Fatal(err)
	}
	recv(t, rxb) // traffic continues under the new keys
}

// ---- the IPE over BACnet/SC -------------------------------------------------

// scDevice is the simulator's object table behind a BACnet/SC node.
