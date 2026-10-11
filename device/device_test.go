// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package device_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/bacnet"
	"github.com/cB-Sigma/bacnet/device"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func newDevice(t *testing.T, cfg device.Config, extra int) (*device.Device, *net.UDPAddr) {
	t.Helper()
	cfg.Logger = quiet
	d := device.New(cfg)
	d.AddObject(&device.Object{ID: bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 1}, Name: "Zone Temp",
		Props: map[uint32]any{bacnet.PropPresentValue: float32(21.5), bacnet.PropUnits: bacnet.Enumerated(62), bacnet.PropOutOfService: false}})
	d.AddObject(&device.Object{ID: bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 2}, Name: "Setpoint", Commandable: true,
		Props: map[uint32]any{bacnet.PropPresentValue: float32(20), bacnet.PropUnits: bacnet.Enumerated(62)}})
	d.AddObject(&device.Object{ID: bacnet.ObjectID{Type: bacnet.BinaryValue, Instance: 3}, Name: "Occupied",
		Props: map[uint32]any{bacnet.PropPresentValue: bacnet.Enumerated(0), device.PropDescription: "lobby"}, Writable: map[uint32]bool{device.PropDescription: true}})
	for i := 0; i < extra; i++ {
		d.AddObject(&device.Object{ID: bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: uint32(100 + i)}, Name: fmt.Sprintf("Point %d with a long name", i),
			Props: map[uint32]any{bacnet.PropPresentValue: float32(i)}})
	}
	addr, err := d.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d, addr
}

func newClient(t *testing.T, setup ...func(*bacnet.Client)) *bacnet.Client {
	t.Helper()
	c, err := bacnet.NewClient("127.0.0.1:0", quiet)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range setup {
		f(c) // hooks are set before Serve
	}
	go c.Serve()
	t.Cleanup(c.Close)
	return c
}

func target(addr *net.UDPAddr) bacnet.Target {
	return bacnet.Target{Dest: bacnet.Dest{Addr: addr}, Peer: bacnet.Peer{MaxAPDU: 1476, RecvSeg: true}, Timeout: 2 * time.Second, Retries: 2}
}

var (
	ai1 = bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 1}
	av2 = bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 2}
	bv3 = bacnet.ObjectID{Type: bacnet.BinaryValue, Instance: 3}
)

// The device role answers this module's client: Who-Is, ReadProperty
// with and without an array index, ReadPropertyMultiple with ALL, errors.
func TestDeviceReads(t *testing.T) {
	_, addr := newDevice(t, device.Config{Instance: 4001, Name: "Lib Device", VendorID: 999, VendorName: "cB-Sigma demo", ModelName: "device test"}, 0)
	c := newClient(t)
	tg := target(addr)
	iam, err := c.WhoIs(ctx(t), tg, 4001)
	if err != nil || iam.Device.Instance != 4001 || iam.Vendor != 999 || iam.MaxAPDU != 1476 {
		t.Fatalf("I-Am %+v %v", iam, err)
	}
	dev := bacnet.ObjectID{Type: bacnet.ObjDevice, Instance: 4001}
	if v, err := c.ReadProperty(ctx(t), tg, dev, device.PropObjectName); err != nil || v[0] != "Lib Device" {
		t.Errorf("object-name %v %v", v, err)
	}
	list, err := c.ReadProperty(ctx(t), tg, dev, device.PropObjectList)
	if err != nil || len(list) != 4 || list[0] != dev || list[1] != ai1 {
		t.Errorf("object-list %v %v", list, err)
	}
	if v, err := c.ReadProperty(ctx(t), tg, ai1, bacnet.PropPresentValue); err != nil || v[0] != float32(21.5) {
		t.Errorf("present-value %v %v", v, err)
	}
	res, err := c.ReadMultiple(ctx(t), tg, []bacnet.PropRef{{Object: ai1, Prop: 8}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint32]any{}
	for _, r := range res {
		if r.Err == nil && len(r.Values) == 1 {
			got[r.Prop] = r.Values[0]
		}
	}
	if got[device.PropObjectName] != "Zone Temp" || got[bacnet.PropUnits] != bacnet.Enumerated(62) || got[device.PropObjectType] != bacnet.Enumerated(0) {
		t.Errorf("ALL of AI 1: %v", got)
	}
	res, err = c.ReadMultiple(ctx(t), tg, []bacnet.PropRef{{Object: ai1, Prop: bacnet.PropPresentValue}, {Object: ai1, Prop: 9999}})
	if err != nil || len(res) != 2 || res[0].Err != nil || res[1].Err == nil {
		t.Errorf("RPM with an unknown property: %+v %v", res, err)
	}
	if _, err := c.ReadProperty(ctx(t), tg, bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 77}, bacnet.PropPresentValue); err == nil || !strings.Contains(err.Error(), "31") && !strings.Contains(strings.ToLower(err.Error()), "unknown") {
		t.Errorf("an unknown object: %v", err)
	}
}

// Writes: a commandable value at a priority, relinquished with NULL; a
// property the object does not let others write; a wrong datatype; a
// WritePropertyMultiple; OnWrite refusing one.
func TestDeviceWrites(t *testing.T) {
	refuse := errors.New("refused")
	d, addr := newDevice(t, device.Config{Instance: 4002, OnWrite: func(o bacnet.ObjectID, p uint32, _ int, v any, _ int) error {
		if v == "forbidden" {
			return refuse
		}
		return nil
	}}, 0)
	c := newClient(t)
	tg := target(addr)
	if err := c.WriteProperty(ctx(t), tg, av2, bacnet.PropPresentValue, float32(23), 8); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.Get(av2, bacnet.PropPresentValue); v != float32(23) {
		t.Errorf("after the write at 8: %v", v)
	}
	if v, err := c.ReadProperty(ctx(t), tg, av2, device.PropPriorityArray); err != nil || len(v) != 16 || v[7] != float32(23) || v[0] != nil {
		t.Errorf("priority-array %v %v", v, err)
	}
	if err := c.WriteProperty(ctx(t), tg, av2, bacnet.PropPresentValue, nil, 8); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.Get(av2, bacnet.PropPresentValue); v != float32(20) {
		t.Errorf("after relinquishing: %v", v)
	}
	if err := c.WriteProperty(ctx(t), tg, ai1, bacnet.PropPresentValue, float32(1), 0); err == nil {
		t.Error("an input's present-value was written")
	}
	if err := c.WriteProperty(ctx(t), tg, av2, bacnet.PropPresentValue, "text", 8); err == nil {
		t.Error("a string was written to a REAL")
	}
	if err := c.WriteMultiple(ctx(t), tg, []bacnet.PropWrite{{Object: av2, Prop: bacnet.PropPresentValue, Value: float32(19), Priority: 10},
		{Object: bv3, Prop: device.PropDescription, Value: "atrium"}}); err != nil {
		t.Fatal(err)
	}
	if v, _ := d.Get(bv3, device.PropDescription); v != "atrium" {
		t.Errorf("WPM description: %v", v)
	}
	err := c.WriteMultiple(ctx(t), tg, []bacnet.PropWrite{{Object: bv3, Prop: device.PropDescription, Value: "forbidden"}})
	if err == nil {
		t.Error("OnWrite did not refuse")
	}
	if v, _ := d.Get(bv3, device.PropDescription); v != "atrium" {
		t.Errorf("a refused write changed the value: %v", v)
	}
}

// SubscribeCOV: an initial notification, one on every change of the
// present value, confirmed notifications acknowledged, and none after
// cancellation.
func TestDeviceCOV(t *testing.T) {
	d, addr := newDevice(t, device.Config{Instance: 4003}, 0)
	notes := make(chan bacnet.COVNotification, 16)
	c := newClient(t, func(c *bacnet.Client) { hooks(c, notes) })
	tg := target(addr)
	next := func() bacnet.COVNotification {
		t.Helper()
		select {
		case n := <-notes:
			return n
		case <-time.After(5 * time.Second):
			t.Fatal("no COV notification")
		}
		return bacnet.COVNotification{}
	}
	covSteps(t, d, c, tg, notes, next)
}

func hooks(c *bacnet.Client, notes chan bacnet.COVNotification) {
	c.OnUnconfirmed = func(_ bacnet.Dest, a bacnet.APDU) {
		if a.Service == bacnet.SvcUnconfirmedCOV {
			if n, err := bacnet.DecodeCOVNotification(a.Data); err == nil {
				notes <- n
			}
		}
	}
	c.OnConfirmed = func(_ bacnet.Dest, a bacnet.APDU) []byte {
		if a.Service == bacnet.SvcConfirmedCOV {
			if n, err := bacnet.DecodeCOVNotification(a.Data); err == nil {
				notes <- n
			}
		}
		return []byte{bacnet.PDUSimpleACK << 4, a.InvokeID, a.Service}
	}
}

func covSteps(t *testing.T, d *device.Device, c *bacnet.Client, tg bacnet.Target, notes chan bacnet.COVNotification, next func() bacnet.COVNotification) {
	t.Helper()
	if err := c.SubscribeCOV(ctx(t), tg, 7, ai1, false, 300); err != nil {
		t.Fatal(err)
	}
	if n := next(); n.Process != 7 || n.Object != ai1 || n.Values[bacnet.PropPresentValue][0] != float32(21.5) {
		t.Errorf("initial %+v", n)
	}
	_ = d.Set(ai1, bacnet.PropPresentValue, float32(22))
	if n := next(); n.Values[bacnet.PropPresentValue][0] != float32(22) {
		t.Errorf("after Set %+v", n)
	}
	if err := c.SubscribeCOV(ctx(t), tg, 8, av2, true, 0); err != nil {
		t.Fatal(err)
	}
	next()
	if err := c.WriteProperty(ctx(t), tg, av2, bacnet.PropPresentValue, float32(25), 9); err != nil {
		t.Fatal(err)
	}
	if n := next(); n.Object != av2 || n.Values[bacnet.PropPresentValue][0] != float32(25) {
		t.Errorf("confirmed after write %+v", n)
	}
	// Cancel: SubscribeCOV without confirmation and lifetime.
	if _, err := c.Request(ctx(t), tg, bacnet.SvcSubscribeCOV, cancelBody(7, ai1)); err != nil {
		t.Fatal(err)
	}
	_ = d.Set(ai1, bacnet.PropPresentValue, float32(30))
	select {
	case n := <-notes:
		t.Errorf("a notification after cancellation: %+v", n)
	case <-time.After(300 * time.Millisecond):
	}
}

func cancelBody(process uint32, o bacnet.ObjectID) []byte {
	var e bacnet.Enc
	e.CtxUnsigned(0, uint64(process))
	e.CtxObjectID(1, o)
	return e.B
}

// Segmentation both ways: a long object-list goes out in segments to a
// client that takes 128-octet APDUs, and a WritePropertyMultiple sent in
// segments to a device stated to take 128 octets is reassembled.
func TestDeviceSegmentation(t *testing.T) {
	d, addr := newDevice(t, device.Config{Instance: 4004, Window: 3}, 120)
	c := newClient(t)
	c.MaxRespCode = 1 // 128 octets
	tg := target(addr)
	dev := bacnet.ObjectID{Type: bacnet.ObjDevice, Instance: 4004}
	list, err := c.ReadProperty(ctx(t), tg, dev, device.PropObjectList)
	if err != nil || len(list) != 124 {
		t.Fatalf("segmented object-list: %d entries, %v", len(list), err)
	}
	refs := []bacnet.PropRef{}
	for i := 0; i < 60; i++ {
		refs = append(refs, bacnet.PropRef{Object: bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: uint32(100 + i)}, Prop: device.PropObjectName})
	}
	res, err := c.ReadMultiple(ctx(t), tg, refs)
	if err != nil || len(res) != 60 || res[59].Values[0] != "Point 59 with a long name" {
		t.Fatalf("segmented RPM: %d %v", len(res), err)
	}
	var ws []bacnet.PropWrite
	for i := 0; i < 30; i++ {
		ws = append(ws, bacnet.PropWrite{Object: av2, Prop: bacnet.PropPresentValue, Value: float32(i), Priority: 1 + i%5})
	}
	tg.Peer = bacnet.Peer{MaxAPDU: 128, RecvSeg: true}
	if err := c.WriteMultiple(ctx(t), tg, ws); err != nil {
		t.Fatalf("segmented WPM: %v", err)
	}
	if v, _ := d.Get(av2, bacnet.PropPresentValue); v != float32(25) {
		t.Errorf("after the segmented WPM: %v", v)
	}
	// A client that takes no segments gets an abort for a long answer.
	tg.Peer = bacnet.Peer{MaxAPDU: 1476, RecvSeg: true}
	raw := bacnet.Confirmed(1, bacnet.SvcReadProperty, bacnet.EncodeReadProperty(dev, device.PropObjectList))
	raw[0] &^= 0x02 // segmented-response-accepted off
	raw[1] = 0x00   // 50 octets
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write(bacnet.Frame(raw, true))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	ap, err := bacnet.Unframe(buf[:n])
	if err != nil || ap[0]>>4 != bacnet.PDUAbort || ap[2] != bacnet.AbortSegNotSupp {
		t.Errorf("no segments accepted: %x %v", ap, err)
	}
}

// The device on a client's port (Attach): the same port answers as a
// device and reads as a client.
func TestDeviceAttach(t *testing.T) {
	d := device.New(device.Config{Instance: 4005, Name: "attached", Logger: quiet})
	d.AddObject(&device.Object{ID: ai1, Name: "t", Props: map[uint32]any{bacnet.PropPresentValue: float32(5)}})
	host := newClient(t, d.Attach)
	c := newClient(t)
	tg := target(host.Conn.LocalAddr().(*net.UDPAddr))
	if v, err := c.ReadProperty(ctx(t), tg, ai1, bacnet.PropPresentValue); err != nil || v[0] != float32(5) {
		t.Errorf("read through Attach: %v %v", v, err)
	}
	if iam, err := c.WhoIs(ctx(t), tg, 4005); err != nil || iam.Device.Instance != 4005 {
		t.Errorf("Who-Is through Attach: %+v %v", iam, err)
	}
}
