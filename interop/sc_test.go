// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/bacnet"
	"github.com/cB-Sigma/tlsx"
)

// pki is a test CA with operational certificates for each node, written
// as PEM files into dir (mounted into the containers as /opt/bacnet/sc).
type pki struct {
	dir    string
	ca     *x509.Certificate
	caKey  *rsa.PrivateKey
	serial int64
}

// newPKI takes the test CA that comes with bacnet-stack (bin/certs, a
// published test key) and issues our certificates from it: bacnet-stack
// 1.6.1's hub crashed (SIGSEGV) with a CA made here by crypto/x509.
func newPKI(t *testing.T) *pki {
	t.Helper()
	caPEM := run(t, image, "cat", "/opt/bacnet/bsc/certs/ca_cert.pem")
	blk, _ := pem.Decode([]byte(caPEM))
	if blk == nil {
		t.Fatal("bacnet-stack's test CA certificate not found")
	}
	der := blk.Bytes
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := pem.Decode([]byte(run(t, image, "cat", "/opt/bacnet/bsc/certs/ca_key.pem")))
	if kb == nil {
		t.Fatal("bacnet-stack's test CA key not found")
	}
	key, err := x509.ParsePKCS1PrivateKey(kb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// The real path: on macOS the temporary directory is reached through
	// the /var symbolic link, which a bind mount does not follow well.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := &pki{dir: dir, ca: ca, caKey: key, serial: 1}
	if err := os.WriteFile(filepath.Join(dir, "ca_cert.pem"), []byte(caPEM), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// sample writes bacnet-stack's own sample server certificate and key as
// name.pem and name.key.
func (p *pki) sample(t *testing.T, name string) {
	t.Helper()
	for src, dst := range map[string]string{"server_cert.pem": name + "_cert.pem", "server_key.pem": name + "_key.pem"} {
		b := run(t, image, "cat", "/opt/bacnet/bsc/certs/"+src)
		if err := os.WriteFile(filepath.Join(p.dir, dst), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (p *pki) write(t *testing.T, name, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(p.dir, name), pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// leaf issues name.pem and name.key and returns them as SCTLS
// credentials. The certificate has a full subject and no extensions, like
// bacnet-stack's own sample certificates: bacnet-stack 1.6.1's hub
// (bacschub) crashed (SIGSEGV) on certificates with a common name only
// and subjectAltName, key usage and extended key usage extensions.
func (p *pki) leaf(t *testing.T, name string) *bacnet.SCTLS {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p.serial++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(p.serial),
		Subject:      pkix.Name{Country: []string{"IN"}, Province: []string{"Test"}, Organization: []string{"Sigma interop"}, CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca, &key.PublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	kd := x509.MarshalPKCS1PrivateKey(key)
	p.write(t, name+"_cert.pem", "CERTIFICATE", der)
	p.write(t, name+"_key.pem", "RSA PRIVATE KEY", kd)
	cert, err := tlsx.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: kd}))
	if err != nil {
		t.Fatal(err)
	}
	return &bacnet.SCTLS{Certificate: cert, Issuers: []*x509.Certificate{p.ca}}
}

// testLog logs to standard error at debug level when
// SIGMA_BACNET_INTEROP_LOG=1, and nowhere otherwise.
func testLog() *slog.Logger {
	if os.Getenv(envVar+"_LOG") != "1" {
		return slog.New(slog.DiscardHandler)
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// scEnv are the environment variables of a bacnet-stack BACnet/SC node
// whose credentials are sc/<name>.pem and .key (bacnet-stack takes relative paths only), connecting to hub.
func scEnv(name, hub string) []string {
	return []string{
		"-e", "BACNET_SC_PRIMARY_HUB_URI=" + hub, "-e", "BACNET_SC_DEBUG=1",
		// Without it libwebsockets checks the peer's host name, which
		// AB.7.4 leaves out (this module does not check it by default
		// either); it also lets self-signed certificates through.
		"-e", "BACNET_SC_SELFSIGNED_ENABLED=1",
		"-e", "BACNET_SC_ISSUER_1_CERTIFICATE_FILE=sc/ca_cert.pem",
		"-e", "BACNET_SC_OPERATIONAL_CERTIFICATE_FILE=sc/" + name + "_cert.pem",
		"-e", "BACNET_SC_OPERATIONAL_CERTIFICATE_PRIVATE_KEY_FILE=sc/" + name + "_key.pem",
	}
}

// scClient is this module's client on a BACnet/SC node connected to hub.
func scClient(t *testing.T, creds *bacnet.SCTLS, hub string, noHello bool) *bacnet.Client {
	t.Helper()
	n := &bacnet.SCNode{
		Log: testLog(), Creds: creds, Primary: hub, UUID: bacnet.NewUUID(), VMAC: bacnet.RandomVMAC(),
		MinReconnect: 200 * time.Millisecond, MaxReconnect: 2 * time.Second, ConnectWait: 5 * time.Second,
		DisconnectWait: 2 * time.Second, Heartbeat: 30 * time.Second, NoHello: noHello,
	}
	c := bacnet.NewClientSC(n, n.Log)
	n.Start(context.Background())
	t.Cleanup(c.Close)
	deadline := time.Now().Add(20 * time.Second)
	for n.State().HubConnectorState != "connected-to-primary" {
		if time.Now().After(deadline) {
			t.Fatalf("not connected to the hub %s: %+v", hub, n.State())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return c
}

// discoverSC broadcasts Who-Is for instance over the hub and returns the
// device's VMAC from its I-Am.
func discoverSC(t *testing.T, c *bacnet.Client, instance uint32) bacnet.Dest {
	t.Helper()
	whoIs := bacnet.NPDU{Data: append([]byte{bacnet.PDUUnconfirmed << 4, bacnet.SvcWhoIs}, bacnet.EncodeWhoIs(instance)...)}
	var d bacnet.Dest
	deadline := time.Now().Add(30 * time.Second)
	for next := time.Now(); ; time.Sleep(50 * time.Millisecond) {
		c.Mu.Lock()
		got, ok := c.Bindings[instance]
		c.Mu.Unlock()
		if ok {
			d = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no I-Am from device %d over BACnet/SC", instance)
		}
		if time.Now().After(next) {
			if err := c.BroadcastNPDU(whoIs); err != nil {
				t.Fatal(err)
			}
			next = time.Now().Add(2 * time.Second)
		}
	}
	if _, ok := d.Addr.(bacnet.VMAC); !ok {
		t.Fatalf("I-Am source %v is not a VMAC", d.Addr)
	}
	return d
}

func readOverSC(t *testing.T, c *bacnet.Client, d bacnet.Dest, name string) {
	t.Helper()
	ctx := context.Background()
	tg := bacnet.Target{Dest: d, Peer: bacnet.Peer{MaxAPDU: 1476}, Timeout: 3 * time.Second, Retries: 2}
	v, err := c.ReadProperty(ctx, tg, device, propObjName)
	if err != nil || len(v) != 1 || v[0] != name {
		t.Fatalf("object-name over BACnet/SC = %v, %v", v, err)
	}
	av1 := bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 1}
	if err := c.WriteProperty(ctx, tg, av1, bacnet.PropPresentValue, float32(3.5), 8); err != nil {
		t.Fatalf("WriteProperty over BACnet/SC: %v", err)
	}
	res, err := c.ReadMultiple(ctx, tg, []bacnet.PropRef{{Object: av1, Prop: bacnet.PropPresentValue}, {Object: device, Prop: propVendorID}})
	if err != nil || len(res) != 2 || res[0].Err != nil || res[0].Values[0] != float32(3.5) {
		t.Errorf("ReadPropertyMultiple over BACnet/SC = %+v, %v", res, err)
	}
}

// This module's hub connector and client through bacnet-stack's hub
// (bacschub) to bacnet-stack's server on BACnet/SC.
func TestSCThroughBacnetStackHub(t *testing.T) {
	needDocker(t)
	p := newPKI(t)
	p.leaf(t, "hub")
	p.leaf(t, "server")
	mine := p.leaf(t, "sigma")
	port := freeTCPPort(t)
	hub := startPeer(t, append(append([]string{"-p", fmt.Sprintf("127.0.0.1:%d:50050", port), "-v", p.dir + ":/opt/bacnet/sc",
		"-e", "BACNET_SC_HUB_FUNCTION_BINDING=50050"}, scEnv("hub", "wss://127.0.0.1:50050")...),
		image, "stdbuf", "-oL", "/opt/bacnet/bsc/bacschub", "4321", "Sigma Hub")...)
	hub.expect(60*time.Second, "Connected to a BACnet/SC hub")
	srv := startPeer(t, append(append([]string{"--network", "container:" + hub.name, "-v", p.dir + ":/opt/bacnet/sc"},
		scEnv("server", "wss://127.0.0.1:50050")...), image, "stdbuf", "-oL", "/opt/bacnet/bsc/bacserv", fmt.Sprint(devInstance), "Sigma SC")...)
	srv.expect(60*time.Second, "Connected to a BACnet/SC hub")

	c := scClient(t, mine, fmt.Sprintf("wss://127.0.0.1:%d", port), true)
	d := discoverSC(t, c, devInstance)
	readOverSC(t, c, d, "Sigma SC")
}

// bacnet-stack's server connects to this module's hub function, and this
// module's client reaches it through that hub.
//
// Not run by default: on Docker Desktop for macOS (2026-10-11) bacnet-stack's
// node never opened a TCP connection to a hub outside its container (none
// seen with ss in the container), so this direction is unverified. Set
// SIGMA_BACNET_INTEROP_OURHUB=1 to try it on another Docker host.
func TestSCBacnetStackNodeOnOurHub(t *testing.T) {
	needDocker(t)
	if os.Getenv(envVar+"_OURHUB") != "1" {
		t.Skip("set " + envVar + "_OURHUB=1: bacnet-stack's node did not reach a hub on the host under Docker Desktop")
	}
	// The host's IPv4 address as containers see it (the name resolves to
	// an IPv6 address first, which Docker Desktop does not forward).
	out := run(t, image, "getent", "ahostsv4", "host.docker.internal")
	fields := strings.Fields(out)
	if len(fields) == 0 || net.ParseIP(fields[0]) == nil {
		t.Fatalf("host address: %q", out)
	}
	hostIP := net.ParseIP(fields[0])
	p := newPKI(t)
	hubCreds := p.leaf(t, "hub")
	p.leaf(t, "server")
	mine := p.leaf(t, "sigma")
	h := bacnet.NewHub(testLog(), hubCreds, bacnet.RandomVMAC(), bacnet.NewUUID(), 5*time.Second)
	addr, err := h.Listen(":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	port := addr.(*net.TCPAddr).Port
	startPeer(t, append(append([]string{"-v", p.dir + ":/opt/bacnet/sc"},
		scEnv("server", fmt.Sprintf("wss://%s:%d", hostIP, port))...), image, "stdbuf", "-oL", "/opt/bacnet/bsc/bacserv", fmt.Sprint(devInstance), "Sigma SC")...)

	c := scClient(t, mine, fmt.Sprintf("wss://127.0.0.1:%d", port), false)
	d := discoverSC(t, c, devInstance)
	readOverSC(t, c, d, "Sigma SC")
	if n := len(h.Connections()); n != 2 {
		t.Errorf("hub connections %d, want 2 (bacserv and this client)", n)
	}
}
