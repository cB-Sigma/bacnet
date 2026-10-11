// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package interop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/bacnet"
	bacdevice "github.com/cB-Sigma/bacnet/device"
)

// bp3Image is BACpypes3 0.0.110 with our peer scripts, built from
// ./bacpypes3.
const bp3Image = "sigma-bacnet-interop:bacpypes3-0.0.110"

func needBACpypes3(t *testing.T) {
	t.Helper()
	needDocker(t)
	out, err := exec.Command("docker", "build", "-q", "-t", bp3Image, "bacpypes3").CombinedOutput()
	if err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
}

func peerEvent(t *testing.T, line string) map[string]any {
	t.Helper()
	i := strings.Index(line, "PEER ")
	var m map[string]any
	if i < 0 || json.Unmarshal([]byte(line[i+5:]), &m) != nil {
		t.Fatalf("not a peer event: %q", line)
	}
	return m
}

// BACpypes3's client against this module's device role: a 404-entry
// object-list that needs a segmented answer, ReadPropertyMultiple, a
// write at priority 8 read back with the priority array, and COV
// notifications after the device's values change.
func TestBACpypes3ClientAgainstDeviceRole(t *testing.T) {
	needBACpypes3(t)
	d := bacdevice.New(bacdevice.Config{Instance: 4010, Name: "Sigma Device Role", VendorID: 999, VendorName: "cB-Sigma demo",
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	ai1 := bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 1}
	av2 := bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 2}
	d.AddObject(&bacdevice.Object{ID: ai1, Name: "Zone Temp", Props: map[uint32]any{bacnet.PropPresentValue: float32(21.5), bacnet.PropUnits: bacnet.Enumerated(62)}})
	d.AddObject(&bacdevice.Object{ID: av2, Name: "Setpoint", Commandable: true, Props: map[uint32]any{bacnet.PropPresentValue: float32(20), bacnet.PropUnits: bacnet.Enumerated(62)}})
	for i := 0; i < 402; i++ {
		d.AddObject(&bacdevice.Object{ID: bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: uint32(100 + i)}, Name: fmt.Sprintf("Point %d", i),
			Props: map[uint32]any{bacnet.PropPresentValue: float32(i)}})
	}
	addr, err := d.Listen("0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	p := startPeer(t, "--add-host=host.docker.internal:host-gateway", bp3Image, "python", "-u", "client.py",
		"--instance", "599", fmt.Sprintf("host.docker.internal:%d", addr.Port), "4010")
	ol := peerEvent(t, p.expect(60*time.Second, `"object-list"`))
	if ol["n"] != float64(405) {
		t.Errorf("object-list as BACpypes3 read it: %v", ol)
	}
	if nm := peerEvent(t, p.expect(15*time.Second, `"object-name"`)); nm["value"] != "Sigma Device Role" {
		t.Errorf("object-name %v", nm)
	}
	rpm := peerEvent(t, p.expect(15*time.Second, `"rpm"`))
	if s := fmt.Sprint(rpm["values"]); !strings.Contains(s, "Zone Temp") || !strings.Contains(s, "21.5") || !strings.Contains(s, "20.0") {
		t.Errorf("rpm %v", rpm)
	}
	if w := peerEvent(t, p.expect(15*time.Second, `"write"`)); w["value"] != 23.5 {
		t.Errorf("write read back %v", w)
	}
	if v, _ := d.Get(av2, bacnet.PropPresentValue); v != float32(23.5) {
		t.Errorf("the device holds %v", v)
	}
	if pa := peerEvent(t, p.expect(15*time.Second, `"priority-array"`)); pa["n"] != float64(16) {
		t.Errorf("priority-array %v", pa)
	}
	p.expect(15*time.Second, `"subscribed"`)
	time.Sleep(300 * time.Millisecond)
	_ = d.Set(ai1, bacnet.PropPresentValue, float32(24))
	time.Sleep(300 * time.Millisecond)
	_ = d.Set(ai1, bacnet.PropPresentValue, float32(26))
	var covs []any
	for len(covs) < 2 {
		e := peerEvent(t, p.expect(20*time.Second, `"cov"`))
		covs = append(covs, e["value"])
	}
	t.Logf("BACpypes3 COV values: %v", covs)
	if fmt.Sprint(covs) != "[24 26]" && fmt.Sprint(covs) != "[21.5 24]" {
		t.Errorf("COV values %v", covs)
	}
	if e := peerEvent(t, p.expect(20*time.Second, `"done"`)); e["event"] != "done" {
		t.Error(e)
	}
	if strings.Contains(p.output(), `"error"`) {
		t.Errorf("BACpypes3 reported an error:\n%s", p.output())
	}
}

// This module's client against a BACpypes3 device: a segmented
// object-list and ReadPropertyMultiple answer, and a segmented request.
func TestClientSegmentationAgainstBACpypes3(t *testing.T) {
	needBACpypes3(t)
	port := freeUDPPort(t)
	p := startPeer(t, "-p", fmt.Sprintf("127.0.0.1:%d:47808/udp", port), bp3Image, "python", "-u", "device.py", "--instance", "777", "300")
	p.expect(60*time.Second, "PEER ready")
	time.Sleep(time.Second)
	c, err := bacnet.NewClient("127.0.0.1:0", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	go c.Serve()
	ra, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", port))
	tg := bacnet.Target{Dest: bacnet.Dest{Addr: ra}, Peer: bacnet.Peer{MaxAPDU: 1024, RecvSeg: true}, Timeout: 3 * time.Second, Retries: 2}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dev := bacnet.ObjectID{Type: bacnet.ObjDevice, Instance: 777}
	list, err := c.ReadProperty(ctx, tg, dev, bacdevice.PropObjectList)
	if err != nil {
		t.Fatalf("segmented object-list: %v", err)
	}
	t.Logf("object-list of %d entries (%d octets or more, BACpypes3 takes 1024)", len(list), len(list)*5)
	if len(list) < 301 {
		t.Errorf("object-list has %d entries", len(list))
	}
	var refs []bacnet.PropRef
	for i := 0; i < 300; i++ {
		refs = append(refs, bacnet.PropRef{Object: bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: uint32(100 + i)}, Prop: bacdevice.PropObjectName})
	}
	res, err := c.ReadMultiple(ctx, tg, refs)
	if err != nil || len(res) != 300 || res[299].Err != nil || res[299].Values[0] != "Peer point 299 with a rather long name" {
		t.Fatalf("segmented RPM answer: %d results, %v", len(res), err)
	}
	// A request longer than the 128 octets we state the peer takes goes
	// out in segments.
	tg.Peer = bacnet.Peer{MaxAPDU: 128, RecvSeg: true}
	res, err = c.ReadMultiple(ctx, tg, refs[:80])
	if err != nil || len(res) != 80 || res[79].Values[0] != "Peer point 79 with a rather long name" {
		t.Fatalf("segmented RPM request: %d results, %v", len(res), err)
	}
	ws := []bacnet.PropWrite{}
	for i := 0; i < 40; i++ {
		ws = append(ws, bacnet.PropWrite{Object: bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: uint32(100 + i)}, Prop: bacnet.PropPresentValue, Value: float32(i * 2)})
	}
	if err := c.WriteMultiple(ctx, tg, ws); err != nil {
		t.Logf("segmented WPM to BACpypes3: %v", err)
	} else if v, err := c.ReadProperty(ctx, tg, bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 139}, bacnet.PropPresentValue); err != nil || v[0] != float32(78) {
		t.Errorf("after the segmented WPM: %v %v", v, err)
	}
}
