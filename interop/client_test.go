// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package interop runs this module's client against bacnet-stack's demo
// server (bacserv, built in a container from peer/Dockerfile) over
// BACnet/IP: ReadProperty, ReadPropertyMultiple, WriteProperty,
// SubscribeCOV, ReadRange, segmentation both ways, foreign-device
// registration with bacserv's BBMD function and Who-Is through it; and
// over BACnet/SC against bacnet-stack's hub (bacschub) and a bacserv node.
// The tests need Docker and are skipped unless SIGMA_BACNET_INTEROP=1.
package interop

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cB-Sigma/bacnet"
)

const (
	devInstance   = 1234
	propObjName   = 77
	propObjList   = 76
	propVendorID  = 120
	propLocation  = 58
	propDesc      = 28
	objDevice     = 8
	vendorBACnetS = 260 // bacnet-stack's vendor identifier
)

var device = bacnet.ObjectID{Type: objDevice, Instance: devInstance}

// bacserv starts bacnet-stack's demo server as device 1234 with its port
// published on 127.0.0.1 and returns that address.
func bacserv(t *testing.T) *net.UDPAddr {
	t.Helper()
	port := freeUDPPort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:47808/udp", port), image, "stdbuf", "-oL", "/opt/bacnet/bip/bacserv", fmt.Sprint(devInstance), "Sigma Interop")
	p.expect(60*time.Second, "BACnet Device ID")
	time.Sleep(300 * time.Millisecond)
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
}

// client opens a B/IP client on the loopback interface.
func client(t *testing.T) *bacnet.Client {
	t.Helper()
	c, err := bacnet.NewClient("127.0.0.1:0", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	go c.Serve()
	t.Cleanup(c.Close)
	return c
}

func target(a *net.UDPAddr) bacnet.Target {
	return bacnet.Target{Dest: bacnet.Dest{Addr: a}, Peer: bacnet.Peer{MaxAPDU: 1476, RecvSeg: true}, Timeout: 2 * time.Second, Retries: 2}
}

func TestClientAgainstBacserv(t *testing.T) {
	needDocker(t)
	srv := bacserv(t)
	c := client(t)
	ctx := context.Background()
	tg := target(srv)

	var objects []any
	t.Run("ReadProperty", func(t *testing.T) {
		v, err := c.ReadProperty(ctx, tg, device, propObjName)
		if err != nil || len(v) != 1 || v[0] != "Sigma Interop" {
			t.Fatalf("object-name = %v, %v", v, err)
		}
		v, err = c.ReadProperty(ctx, tg, device, propVendorID)
		if err != nil || len(v) != 1 || fmt.Sprint(v[0]) != fmt.Sprint(vendorBACnetS) {
			t.Errorf("vendor-identifier = %#v, %v", v, err)
		}
		objects, err = c.ReadProperty(ctx, tg, device, propObjList)
		if err != nil || len(objects) < 10 {
			t.Fatalf("object-list = %v, %v", objects, err)
		}
		if objects[0] != device {
			t.Errorf("object-list starts with %v", objects[0])
		}
		v, err = c.ReadProperty(ctx, tg, bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 1}, bacnet.PropPresentValue)
		if err != nil || len(v) != 1 {
			t.Errorf("AI 0 present-value = %v, %v", v, err)
		} else if _, ok := v[0].(float32); !ok {
			t.Errorf("AI 0 present-value is %T, want REAL", v[0])
		}
		// An unknown object is an Error PDU with object / unknown-object.
		_, err = c.ReadProperty(ctx, tg, bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 4000}, bacnet.PropPresentValue)
		if err == nil || !strings.Contains(err.Error(), "31") && !strings.Contains(strings.ToLower(err.Error()), "unknown") {
			t.Errorf("unknown object: %v", err)
		}
	})

	t.Run("ReadPropertyMultiple", func(t *testing.T) {
		ai0 := bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 1}
		res, err := c.ReadMultiple(ctx, tg, []bacnet.PropRef{
			{Object: device, Prop: propObjName}, {Object: device, Prop: propVendorID},
			{Object: ai0, Prop: bacnet.PropPresentValue}, {Object: ai0, Prop: bacnet.PropUnits},
			{Object: ai0, Prop: 9999},
		})
		if err != nil || len(res) != 5 {
			t.Fatalf("RPM = %v, %v", res, err)
		}
		if res[0].Err != nil || res[0].Values[0] != "Sigma Interop" {
			t.Errorf("RPM object-name = %+v", res[0])
		}
		if res[2].Err != nil || len(res[2].Values) != 1 {
			t.Errorf("RPM AI 0 present-value = %+v", res[2])
		}
		if res[3].Err != nil || len(res[3].Values) != 1 {
			t.Errorf("RPM AI 0 units = %+v", res[3])
		}
		if res[4].Err == nil {
			t.Errorf("RPM unknown property = %+v, want an error", res[4])
		}
	})

	t.Run("WriteProperty", func(t *testing.T) {
		av0 := bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 1}
		if err := c.WriteProperty(ctx, tg, av0, bacnet.PropPresentValue, float32(42.25), 8); err != nil {
			t.Fatal(err)
		}
		v, err := c.ReadProperty(ctx, tg, av0, bacnet.PropPresentValue)
		if err != nil || len(v) != 1 || v[0] != float32(42.25) {
			t.Errorf("AV 0 after the write = %v, %v", v, err)
		}
		// Relinquish priority 8 again (NULL).
		if err := c.WriteProperty(ctx, tg, av0, bacnet.PropPresentValue, nil, 8); err != nil {
			t.Errorf("relinquish: %v", err)
		}
		// A wrong datatype is refused with an Error PDU.
		if err := c.WriteProperty(ctx, tg, av0, bacnet.PropPresentValue, "text", 8); err == nil {
			t.Error("a character string written to an analog value was accepted")
		}
	})

	t.Run("Segmentation", func(t *testing.T) {
		// bacnet-stack 1.6.1 has no segmentation state machine, so this
		// checks the refusals only: the client reads bacserv's
		// segmentation-supported (none) and turns its aborts into errors.
		seg, err := c.ReadProperty(ctx, tg, device, 107) // segmentation-supported
		if err != nil || len(seg) != 1 || fmt.Sprint(seg[0]) != fmt.Sprint(bacnet.Enumerated(bacnet.SegNone)) {
			t.Errorf("segmentation-supported = %v, %v", seg, err)
		}
		// A reply longer than the 50 octets the client accepts.
		c2 := client(t)
		c2.MaxRespCode = 0
		if v, err := c2.ReadProperty(ctx, tg, device, propObjList); err == nil {
			t.Logf("bacserv answered the object-list (%d entries) unsegmented to a client accepting 50 octets", len(v))
		} else if !strings.Contains(err.Error(), "abort") {
			t.Errorf("object-list to a 50-octet client: %v", err)
		}
		// A request sent in segments: bacserv aborts it.
		small := tg
		small.Peer = bacnet.Peer{MaxAPDU: 50, RecvSeg: true}
		text := strings.Repeat("Sigma segmented request ", 4)[:90]
		err = c.WriteProperty(ctx, small, device, propLocation, text, -1)
		if err == nil || !strings.Contains(err.Error(), "abort") {
			t.Errorf("segmented request: %v, want bacserv's abort", err)
		}
	})

	t.Run("SubscribeCOV", func(t *testing.T) {
		c3 := client(t)
		var mu sync.Mutex
		var notes []bacnet.COVNotification
		got := make(chan struct{}, 8)
		c3.OnUnconfirmed = func(from bacnet.Dest, a bacnet.APDU) {
			if a.Service != bacnet.SvcUnconfirmedCOV {
				return
			}
			n, err := bacnet.DecodeCOVNotification(a.Data)
			if err != nil {
				t.Errorf("COV notification: %v", err)
				return
			}
			mu.Lock()
			notes = append(notes, n)
			mu.Unlock()
			got <- struct{}{}
		}
		av1 := bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 1}
		if err := c3.SubscribeCOV(ctx, tg, 77, av1, false, 120); err != nil {
			t.Fatal(err)
		}
		wait := func(what string) bacnet.COVNotification {
			t.Helper()
			select {
			case <-got:
			case <-time.After(10 * time.Second):
				t.Fatalf("no COV notification (%s)", what)
			}
			mu.Lock()
			defer mu.Unlock()
			return notes[len(notes)-1]
		}
		first := wait("initial")
		if first.Process != 77 || first.Object != av1 || first.Device != device {
			t.Errorf("initial notification %+v", first)
		}
		if err := c.WriteProperty(ctx, tg, av1, bacnet.PropPresentValue, float32(7.5), 8); err != nil {
			t.Fatal(err)
		}
		n := wait("after a write")
		if pv := n.Values[bacnet.PropPresentValue]; len(pv) != 1 || pv[0] != float32(7.5) {
			t.Errorf("notification after the write: %+v", n)
		}
		if _, ok := n.Values[bacnet.PropStatusFlags]; !ok {
			t.Errorf("notification without status-flags: %+v", n)
		}
		_ = c.WriteProperty(ctx, tg, av1, bacnet.PropPresentValue, nil, 8)
	})

	t.Run("ReadRange", func(t *testing.T) {
		tl := bacnet.ObjectID{Type: bacnet.TrendLog, Instance: 0}
		res, err := c.ReadRange(ctx, tg, tl, bacnet.PropLogBuffer, bacnet.ReadRange{Kind: bacnet.RangeByPosition, Ref: 1, Count: 5})
		if err != nil {
			t.Fatalf("ReadRange by position: %v", err)
		}
		t.Logf("ReadRange by position: count %d, first %v last %v more %v, records %d", res.Count, res.FirstItem, res.LastItem, res.MoreItems, len(res.Records))
		if int(res.Count) != len(res.Records) || res.Count == 0 || res.Count > 5 {
			t.Errorf("ReadRange by position: %+v", res)
		}
		for _, r := range res.Records {
			if r.At.IsZero() {
				t.Errorf("a record without its time: %+v", r)
			}
		}
		// All of it, without a range.
		all, err := c.ReadRange(ctx, tg, tl, bacnet.PropLogBuffer, bacnet.ReadRange{})
		if err != nil {
			t.Fatalf("ReadRange without a range: %v", err)
		}
		t.Logf("ReadRange without a range: %d records, first %v last %v more %v", len(all.Records), all.FirstItem, all.LastItem, all.MoreItems)
		if len(all.Records) < len(res.Records) {
			t.Errorf("whole buffer %d records, fewer than the range's %d", len(all.Records), len(res.Records))
		}
	})
}

// The client registers as a foreign device with bacserv's BBMD function,
// broadcasts Who-Is through it and hears the I-Am bacserv broadcasts,
// forwarded by the BBMD. Unregistered, the distribution is refused.
func TestForeignDeviceWithBacservBBMD(t *testing.T) {
	needDocker(t)
	srv := bacserv(t)
	ctx := context.Background()

	c := client(t)
	c.BBMD = srv
	whoIs := bacnet.NPDU{Data: append([]byte{bacnet.PDUUnconfirmed << 4, bacnet.SvcWhoIs}, bacnet.EncodeWhoIs(devInstance)...)}

	// bacnet-stack 1.6.1 distributes a broadcast from a device that is not
	// registered too (its BBMD does not look it up in the FDT), so the
	// NAK path is checked only against bacnet-sim.
	if err := c.RegisterForeign(ctx, 60*time.Second, 2*time.Second, 2); err != nil {
		t.Fatalf("Register-Foreign-Device: %v", err)
	}
	if err := c.BroadcastNPDU(whoIs); err != nil {
		t.Fatal(err)
	}
	var d bacnet.Dest
	eventually(t, 10*time.Second, "the forwarded I-Am", func() bool {
		c.Mu.Lock()
		defer c.Mu.Unlock()
		var ok bool
		d, ok = c.Bindings[devInstance]
		return ok
	})
	t.Logf("I-Am of device %d heard from %v", devInstance, d.Addr)
	// A directed Who-Is: bacserv broadcasts its I-Am, which reaches the
	// client through the BBMD.
	i, err := c.WhoIs(ctx, target(srv), devInstance)
	if err != nil {
		t.Fatalf("Who-Is: %v", err)
	}
	if i.Device != device || i.MaxAPDU != 1476 || i.Segmentation != bacnet.SegNone || i.Vendor != vendorBACnetS {
		t.Errorf("I-Am %+v", i)
	}
	// Registering again (as the client does before the time-to-live
	// runs out) is accepted too.
	if err := c.RegisterForeign(ctx, 30*time.Second, 2*time.Second, 2); err != nil {
		t.Errorf("re-registration: %v", err)
	}
}

// eventually polls cond until it holds or the wait runs out.
func eventually(t *testing.T, wait time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
