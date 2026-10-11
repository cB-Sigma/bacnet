// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package device is the BACnet device (server) role over BACnet/IP: a
// Device object and an object table served to other BACnet clients with
// Who-Is and Who-Has, ReadProperty and ReadPropertyMultiple (array
// indexes, ALL, REQUIRED and OPTIONAL), WriteProperty and
// WritePropertyMultiple (priority arrays of commandable objects),
// SubscribeCOV with confirmed and unconfirmed notifications and
// lifetimes, and segmentation of answers and of requests (clause 5.4).
// Clauses cited are of ANSI/ASHRAE 135-2024.
package device

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/cB-Sigma/bacnet"
)

// Property identifiers the device serves itself (clause 12, 21).
const (
	PropAPDUTimeout          = 11
	PropAppSoftwareVersion   = 12
	PropDeviceAddressBinding = 30
	PropFirmwareRevision     = 44
	PropMaxAPDU              = 62
	PropModelName            = 70
	PropNumberOfAPDURetries  = 73
	PropObjectIdentifier     = 75
	PropObjectList           = 76
	PropObjectName           = 77
	PropObjectType           = 79
	PropPriorityArray        = 87
	PropProtocolObjectTypes  = 96
	PropProtocolServices     = 97
	PropProtocolVersion      = 98
	PropRelinquishDefault    = 104
	PropSegmentation         = 107
	PropSystemStatus         = 112
	PropVendorIdentifier     = 120
	PropVendorName           = 121
	PropProtocolRevision     = 139
	PropDatabaseRevision     = 155
	PropDescription          = 28
	PropEventState           = 36

	propAll      = 8
	propOptional = 80
	propRequired = 105
)

// Error classes and codes (clause 18) the device answers with.
const (
	ClassObject       = 1
	ClassProperty     = 2
	ClassServices     = 5
	CodeUnknownObject = 31
	CodeUnknownProp   = 32
	CodeWriteDenied   = 40
	CodeInvalidIndex  = 42
	CodeTypeMismatch  = 9 // invalid-data-type
	CodeValueRange    = 37
	CodeNotArray      = 50 // property-is-not-an-array
	CodeOther         = 0
)

// Object is one object the device serves. Present-value, priority-array
// and relinquish-default are kept for a Commandable object; every other
// property is in Props. Object-identifier, object-name and object-type
// are answered from ID and Name.
type Object struct {
	ID   bacnet.ObjectID
	Name string
	// Props are the object's other properties: values Enc.App encodes, or
	// []any for arrays and lists.
	Props map[uint32]any
	// Writable are the properties other devices may write (present-value
	// of a Commandable object always is).
	Writable map[uint32]bool
	// Commandable objects take writes of present-value at a priority
	// (clause 19.2): the present value is the first non-NULL slot of the
	// priority array, or the relinquish default.
	Commandable bool

	prio [16]any
}

// Error is a BACnet error class and code returned by an OnWrite hook.
type Error struct{ Class, Code uint32 }

func (e *Error) Error() string { return "BACnet error" }

// Config sets up a Device.
type Config struct {
	Instance   uint32 // device instance, 0 to 4194302
	Name       string
	VendorID   uint16
	VendorName string
	ModelName  string
	Firmware   string
	Software   string
	// MaxAPDU is the largest APDU the device accepts and sends (50 to
	// 1476; default 1476).
	MaxAPDU int
	// Window is the window the device proposes for segmented answers
	// (default 4); MaxSegments the most segments it sends (default 64).
	Window      byte
	MaxSegments int
	// SegmentTimeout and SegmentRetries govern segmented transfers
	// (default 2 s, 3).
	SegmentTimeout time.Duration
	SegmentRetries int
	// OnWrite, when set, sees every accepted write before it is stored; a
	// non-nil error (an *Error for a chosen class and code) refuses it.
	OnWrite func(o bacnet.ObjectID, prop uint32, index int, value any, priority int) error
	Logger  *slog.Logger
}

// Device is a BACnet/IP device. Its methods are safe for concurrent use.
type Device struct {
	cfg Config
	log *slog.Logger

	mu      sync.Mutex
	conn    *net.UDPConn
	objs    map[bacnet.ObjectID]*Object
	order   []bacnet.ObjectID
	subs    map[subKey]*sub
	rx      map[bacnet.PendingKey]*rxState
	tx      map[bacnet.PendingKey]chan bacnet.APDU
	invoke  byte
	dbRev   uint64
	done    chan struct{}
	started bool
}

type subKey struct {
	addr    string
	process uint32
	obj     bacnet.ObjectID
}

// Out sends an APDU back to a requester over whatever data link it came
// by; expectReply marks a confirmed request.
type Out func(apdu []byte, expectReply bool) error

type sub struct {
	out       Out
	confirmed bool
	expires   time.Time // zero: indefinite
}

type rxState struct {
	data          []byte
	next, initial byte
	window        byte
	at            time.Time
}

// New makes a Device with its Device object; AddObject adds the others.
func New(cfg Config) *Device {
	if cfg.MaxAPDU <= 0 || cfg.MaxAPDU > 1476 {
		cfg.MaxAPDU = 1476
	}
	if cfg.Window == 0 {
		cfg.Window = 4
	}
	if cfg.MaxSegments <= 0 {
		cfg.MaxSegments = 64
	}
	if cfg.SegmentTimeout <= 0 {
		cfg.SegmentTimeout = 2 * time.Second
	}
	if cfg.SegmentRetries <= 0 {
		cfg.SegmentRetries = 3
	}
	if cfg.Name == "" {
		cfg.Name = "device"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	d := &Device{cfg: cfg, log: cfg.Logger, objs: map[bacnet.ObjectID]*Object{}, subs: map[subKey]*sub{},
		rx: map[bacnet.PendingKey]*rxState{}, tx: map[bacnet.PendingKey]chan bacnet.APDU{}, dbRev: 1}
	dev := &Object{ID: d.ID(), Name: cfg.Name, Props: map[uint32]any{}, Writable: map[uint32]bool{PropDescription: true}}
	d.objs[dev.ID] = dev
	d.order = append(d.order, dev.ID)
	return d
}

// ID is the Device object's identifier.
func (d *Device) ID() bacnet.ObjectID {
	return bacnet.ObjectID{Type: bacnet.ObjDevice, Instance: d.cfg.Instance}
}

// AddObject adds (or replaces) an object; a Commandable object's
// relinquish default is its Props[PropRelinquishDefault], or its
// Props[PropPresentValue] when that is set instead.
func (d *Device) AddObject(o *Object) {
	if o.Props == nil {
		o.Props = map[uint32]any{}
	}
	if o.Commandable {
		if _, ok := o.Props[PropRelinquishDefault]; !ok {
			o.Props[PropRelinquishDefault] = o.Props[bacnet.PropPresentValue]
		}
		delete(o.Props, bacnet.PropPresentValue)
	}
	if _, ok := o.Props[bacnet.PropStatusFlags]; !ok {
		o.Props[bacnet.PropStatusFlags] = bacnet.BitString{Len: 4, Bits: make([]bool, 4)}
	}
	d.mu.Lock()
	if _, ok := d.objs[o.ID]; !ok {
		d.order = append(d.order, o.ID)
	}
	d.objs[o.ID] = o
	d.dbRev++
	d.mu.Unlock()
}

// Set changes a property (present-value of a Commandable object: its
// relinquish default) and sends COV notifications when it is
// present-value or status-flags.
func (d *Device) Set(id bacnet.ObjectID, prop uint32, v any) error {
	d.mu.Lock()
	o := d.objs[id]
	if o == nil {
		d.mu.Unlock()
		return errors.New("bacnet device: no such object")
	}
	if o.Commandable && prop == bacnet.PropPresentValue {
		o.Props[PropRelinquishDefault] = v
	} else {
		o.Props[prop] = v
	}
	d.mu.Unlock()
	if prop == bacnet.PropPresentValue || prop == bacnet.PropStatusFlags {
		d.notify(id)
	}
	return nil
}

// Get returns a property's value as a client reads it.
func (d *Device) Get(id bacnet.ObjectID, prop uint32) (any, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	v, cls, _ := d.prop(id, prop)
	return v, cls == 0
}

// Listen serves BACnet/IP on a UDP address ("0.0.0.0:47808") in the
// background and returns the bound address.
func (d *Device) Listen(addr string) (*net.UDPAddr, error) {
	la, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", la)
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.conn = conn
	d.done = make(chan struct{})
	done := d.done
	d.mu.Unlock()
	go func() {
		defer close(done)
		d.serve(conn)
	}()
	go d.expireLoop(done)
	return conn.LocalAddr().(*net.UDPAddr), nil
}

// Close stops serving.
func (d *Device) Close() {
	d.mu.Lock()
	conn, done := d.conn, d.done
	d.conn = nil
	d.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
		<-done
	}
}

// IAm announces the device by a local broadcast to port 47808 of
// broadcast (for example 255.255.255.255 or a subnet's address).
func (d *Device) IAm(broadcast *net.UDPAddr) error {
	d.mu.Lock()
	conn := d.conn
	d.mu.Unlock()
	if conn == nil {
		return errors.New("bacnet device: not listening")
	}
	_, err := conn.WriteToUDP(bacnet.EncodeNPDU(bacnet.BVLCOriginalBcast, bacnet.NPDU{Data: d.iAm()}), broadcast)
	return err
}

func (d *Device) iAm() []byte {
	seg := bacnet.Enumerated(bacnet.SegBoth)
	return append([]byte{bacnet.PDUUnconfirmed << 4, bacnet.SvcIAm},
		bacnet.EncodeIAm(bacnet.IAm{Device: d.ID(), MaxAPDU: uint64(d.cfg.MaxAPDU), Segmentation: seg, Vendor: uint64(d.cfg.VendorID)})...)
}

func (d *Device) serve(conn *net.UDPConn) {
	buf := make([]byte, 1600)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f, err := bacnet.DecodeFrame(append([]byte(nil), buf[:n]...))
		if err != nil {
			continue
		}
		d.frameIn(conn, from, f)
	}
}

// replyRoute is the NPDU routing back to the source of f (through a
// router when f came from a remote network).
func replyRoute(f bacnet.NPDU) bacnet.NPDU {
	if f.Snet != 0 {
		return bacnet.NPDU{Dnet: f.Snet, DADR: f.SADR, Hop: 255}
	}
	return bacnet.NPDU{}
}

func (d *Device) frameIn(conn *net.UDPConn, from *net.UDPAddr, f bacnet.NPDU) {
	switch f.Fn {
	case bacnet.BVLCOriginalUnicast, bacnet.BVLCOriginalBcast:
	case bacnet.BVLCForwardedNPDU:
		if f.Origin != nil {
			from = f.Origin
		}
	default:
		return
	}
	if f.NetMsg || (f.Dnet != 0 && f.Dnet != 0xffff) {
		return
	}
	a, err := bacnet.ParseAPDU(f.Data)
	if err != nil {
		return
	}
	route := replyRoute(f)
	out := func(b []byte, expectReply bool) error {
		n := route
		n.Data, n.ExpectReply = b, expectReply
		_, err := conn.WriteToUDP(bacnet.EncodeNPDU(bacnet.BVLCOriginalUnicast, n), from)
		return err
	}
	send := func(b []byte) { _ = out(b, false) }
	src := from.String()
	if f.Snet != 0 {
		src = fmt.Sprintf("%s/%d/%x", from, f.Snet, f.SADR)
	}
	key := bacnet.PendingKey{Addr: src, ID: a.InvokeID}
	switch a.Typ {
	case bacnet.PDUUnconfirmed:
		d.unconfirmed(a, send)
	case bacnet.PDUSegmentACK, bacnet.PDUAbort:
		d.mu.Lock()
		ch := d.tx[key]
		d.mu.Unlock()
		if ch != nil {
			select {
			case ch <- a:
			default:
			}
		}
	case bacnet.PDUConfirmed:
		if a.Seg {
			d.segmentIn(a, key, out)
			return
		}
		d.respond(a, key, out)
	}
}

func (d *Device) unconfirmed(a bacnet.APDU, send func([]byte)) {
	switch a.Service {
	case bacnet.SvcWhoIs:
		if inRange(a.Data, d.cfg.Instance) {
			send(d.iAm())
		}
	case bacnet.SvcWhoHas:
		if b := d.whoHas(a.Data); b != nil {
			send(b)
		}
	}
}

// inRange reads a Who-Is or Who-Has instance range (context 0 and 1);
// none means every device.
func inRange(b []byte, inst uint32) bool {
	if len(b) == 0 {
		return true
	}
	t0, rest, err := bacnet.ReadTag(b)
	if err != nil || !t0.Context || t0.Num != 0 {
		return true
	}
	t1, _, err := bacnet.ReadTag(rest)
	if err != nil || !t1.Context || t1.Num != 1 {
		return false
	}
	lo, _ := bacnet.BeUnsigned(t0.Data)
	hi, _ := bacnet.BeUnsigned(t1.Data)
	return uint64(inst) >= lo && uint64(inst) <= hi
}

// whoHas answers a Who-Has (clause 16.9) with an I-Have, or nil.
func (d *Device) whoHas(b []byte) []byte {
	rest := b
	if t, r, err := bacnet.ReadTag(b); err == nil && t.Context && t.Num == 0 {
		if !inRange(b, d.cfg.Instance) {
			return nil
		}
		_, r, _ = bacnet.ReadTag(r)
		rest = r
	}
	t, _, err := bacnet.ReadTag(rest)
	if err != nil || !t.Context {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var found *Object
	switch t.Num {
	case 2:
		if len(t.Data) == 4 {
			found = d.objs[bacnet.ObjectIDFrom(binary.BigEndian.Uint32(t.Data))]
		}
	case 3:
		if len(t.Data) > 0 && t.Data[0] == 0 {
			name := string(t.Data[1:])
			for _, id := range d.order {
				if d.objs[id].Name == name {
					found = d.objs[id]
					break
				}
			}
		}
	}
	if found == nil {
		return nil
	}
	var e bacnet.Enc
	_ = e.App(d.ID())
	_ = e.App(found.ID)
	_ = e.App(found.Name)
	return append([]byte{bacnet.PDUUnconfirmed << 4, bacnet.SvcIHave}, e.B...)
}

// segmentIn reassembles a segmented request (clause 5.4.5), answering
// with Segment-ACKs at the first segment, each full window and the last.
func (d *Device) segmentIn(a bacnet.APDU, key bacnet.PendingKey, out Out) {
	send := func(b []byte) { _ = out(b, false) }
	d.mu.Lock()
	rx := d.rx[key]
	if a.Seq == 0 {
		w := min(max(a.Window, 1), bacnet.MaxWindow)
		rx = &rxState{window: byte(w), at: time.Now()}
		d.rx[key] = rx
	}
	d.mu.Unlock()
	if rx == nil {
		send(bacnet.EncodeAbort(a.InvokeID, 2, true)) // invalid-apdu-in-this-state
		return
	}
	if a.Seq != rx.next {
		send(bacnet.SegmentACK(a.InvokeID, rx.next-1, rx.window, true, true))
		rx.initial = rx.next - 1
		return
	}
	rx.data = append(rx.data, a.Data...)
	rx.next++
	if a.Seq == 0 || !a.More || a.Seq-rx.initial == rx.window {
		send(bacnet.SegmentACK(a.InvokeID, a.Seq, rx.window, false, true))
		rx.initial = a.Seq
	}
	if a.More {
		return
	}
	d.mu.Lock()
	delete(d.rx, key)
	d.mu.Unlock()
	full := a
	full.Seg, full.Data = false, rx.data
	d.respond(full, key, out)
}

// respond answers a confirmed request, segmenting a Complex-ACK longer
// than both sides take when the requester accepts segments.
func (d *Device) respond(a bacnet.APDU, key bacnet.PendingKey, out Out) {
	send := func(b []byte) { _ = out(b, false) }
	reply := d.Handle(a, key.Addr, out)
	if reply == nil {
		return
	}
	limit := min(d.cfg.MaxAPDU, bacnet.ReplyLimit(a))
	if len(reply) <= limit || reply[0]>>4 != bacnet.PDUComplexACK {
		send(reply)
		return
	}
	if !a.Sa {
		send(bacnet.EncodeAbort(a.InvokeID, bacnet.AbortSegNotSupp, true))
		return
	}
	size := limit - 5
	n := (len(reply) - 3 + size - 1) / size
	maxSegs := d.cfg.MaxSegments
	if a.MaxSegs > 0 && a.MaxSegs < 255 {
		maxSegs = min(maxSegs, a.MaxSegs)
	}
	if n > maxSegs || n > 255 {
		send(bacnet.EncodeAbort(a.InvokeID, 11, true)) // apdu-too-long
		return
	}

	ch := make(chan bacnet.APDU, 64)
	d.mu.Lock()
	d.tx[key] = ch
	d.mu.Unlock()
	go d.sendSegments(key, ch, a.InvokeID, reply[2], reply[3:], size, send)
}

// sendSegments sends a segmented Complex-ACK (clause 5.4.4): the first
// segment alone, then windows of the size the requester grants,
// resending a window that is not acknowledged in time.
func (d *Device) sendSegments(key bacnet.PendingKey, ch chan bacnet.APDU, id, svc byte, body []byte, size int, send func([]byte)) {
	defer func() {
		d.mu.Lock()
		delete(d.tx, key)
		d.mu.Unlock()
	}()
	var parts [][]byte
	for len(body) > 0 {
		n := min(size, len(body))
		parts = append(parts, body[:n])
		body = body[n:]
	}
	acked, next, actual, tries := -1, 0, 1, 0
	for acked < len(parts)-1 {
		for end := min(acked+1+actual, len(parts)); next < end; next++ {
			send(bacnet.ComplexACKSegment(id, svc, byte(next), d.cfg.Window, next < len(parts)-1, parts[next]))
		}
		select {
		case a := <-ch:
			if a.Typ == bacnet.PDUAbort {
				return
			}
			j := -1
			for k := next - 1; k > acked; k-- {
				if byte(k) == a.Seq {
					j = k
					break
				}
			}
			if j < 0 && a.NAK && acked >= 0 && byte(acked) == a.Seq {
				j = acked
			}
			if j < 0 {
				continue
			}
			acked, next, actual, tries = j, j+1, max(int(a.Window), 1), 0
		case <-time.After(d.cfg.SegmentTimeout):
			if tries++; tries > d.cfg.SegmentRetries {
				send(bacnet.EncodeAbort(id, bacnet.AbortOther, true))
				return
			}
			next = acked + 1 // resend the window
		}
	}
}

func (d *Device) expireLoop(done chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case now := <-t.C:
			d.mu.Lock()
			for k, s := range d.subs {
				if !s.expires.IsZero() && now.After(s.expires) {
					delete(d.subs, k)
				}
			}
			for k, r := range d.rx {
				if now.Sub(r.at) > time.Minute {
					delete(d.rx, k)
				}
			}
			d.mu.Unlock()
		}
	}
}

// objectList is the object-list, the Device object first.
func (d *Device) objectList() []any {
	out := make([]any, 0, len(d.order))
	for _, id := range d.order {
		out = append(out, id)
	}
	return out
}

// deviceProps are the Device object's own properties (clause 12.11).
func (d *Device) deviceProps() map[uint32]any {
	services := bacnet.BitString{Len: 49, Bits: make([]bool, 49)}
	// BACnetServicesSupported bits (clause 21): confirmedCOVNotification 1,
	// subscribeCOV 5, readProperty 12, readPropertyMultiple 14,
	// writeProperty 15, writePropertyMultiple 16, i-Am 26, i-Have 27,
	// unconfirmedCOVNotification 28, who-Has 33, who-Is 34.
	for _, bit := range []int{1, 5, 12, 14, 15, 16, 26, 27, 28, 33, 34} {
		services.Bits[bit] = true
	}
	types := bacnet.BitString{Len: 64, Bits: make([]bool, 64)}
	for _, id := range d.order {
		if int(id.Type) < len(types.Bits) {
			types.Bits[id.Type] = true
		}
	}
	return map[uint32]any{
		PropSystemStatus: bacnet.Enumerated(0), PropVendorName: d.cfg.VendorName, PropVendorIdentifier: uint64(d.cfg.VendorID),
		PropModelName: d.cfg.ModelName, PropFirmwareRevision: d.cfg.Firmware, PropAppSoftwareVersion: d.cfg.Software,
		PropProtocolVersion: uint64(1), PropProtocolRevision: uint64(24), PropProtocolServices: services,
		PropProtocolObjectTypes: types, PropObjectList: d.objectList(), PropMaxAPDU: uint64(d.cfg.MaxAPDU),
		PropSegmentation: bacnet.Enumerated(bacnet.SegBoth), PropAPDUTimeout: uint64(3000), PropNumberOfAPDURetries: uint64(3),
		PropDeviceAddressBinding: []any{}, PropDatabaseRevision: d.dbRev,
	}
}

// prop returns a property value, or an error class and code. d.mu is
// held.
func (d *Device) prop(id bacnet.ObjectID, p uint32) (any, uint32, uint32) {
	o := d.objs[id]
	if o == nil {
		return nil, ClassObject, CodeUnknownObject
	}
	switch p {
	case PropObjectIdentifier:
		return o.ID, 0, 0
	case PropObjectName:
		return o.Name, 0, 0
	case PropObjectType:
		return bacnet.Enumerated(o.ID.Type), 0, 0
	}
	if o.Commandable {
		switch p {
		case bacnet.PropPresentValue:
			for _, v := range o.prio {
				if v != nil {
					return v, 0, 0
				}
			}
			return o.Props[PropRelinquishDefault], 0, 0
		case PropPriorityArray:
			arr := make([]any, 16)
			copy(arr, o.prio[:])
			return arr, 0, 0
		}
	}
	if id == d.ID() {
		if v, ok := o.Props[p]; ok {
			return v, 0, 0
		}
		if v, ok := d.deviceProps()[p]; ok {
			return v, 0, 0
		}
		return nil, ClassProperty, CodeUnknownProp
	}
	if v, ok := o.Props[p]; ok {
		return v, 0, 0
	}
	return nil, ClassProperty, CodeUnknownProp
}

// propList is every property of an object, sorted.
func (d *Device) propList(id bacnet.ObjectID) []uint32 {
	o := d.objs[id]
	set := map[uint32]bool{PropObjectIdentifier: true, PropObjectName: true, PropObjectType: true}
	for p := range o.Props {
		set[p] = true
	}
	if o.Commandable {
		set[bacnet.PropPresentValue], set[PropPriorityArray], set[PropRelinquishDefault] = true, true, true
	}
	if id == d.ID() {
		for p := range d.deviceProps() {
			set[p] = true
		}
	}
	out := make([]uint32, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// encodeValue writes a value: arrays and lists element by element.
func encodeValue(e *bacnet.Enc, v any) error {
	switch x := v.(type) {
	case []any:
		for _, el := range x {
			if err := e.App(el); err != nil {
				return err
			}
		}
		return nil
	case []string:
		for _, el := range x {
			_ = e.App(el)
		}
		return nil
	case bacnet.ContextValue:
		e.Header(x.Num, true, len(x.Data))
		e.B = append(e.B, x.Data...)
		return nil
	}
	return e.App(v)
}

// indexed applies an array index (-1: none) to v.
func indexed(v any, idx int) (any, uint32, uint32) {
	if idx < 0 {
		return v, 0, 0
	}
	var n int
	switch x := v.(type) {
	case []any:
		n = len(x)
		if idx == 0 {
			return uint64(n), 0, 0
		}
		if idx > n {
			return nil, ClassProperty, CodeInvalidIndex
		}
		return x[idx-1], 0, 0
	case []string:
		n = len(x)
		if idx == 0 {
			return uint64(n), 0, 0
		}
		if idx > n {
			return nil, ClassProperty, CodeInvalidIndex
		}
		return x[idx-1], 0, 0
	}
	return nil, ClassProperty, CodeNotArray
}

func reject(id, reason byte) []byte { return []byte{bacnet.PDUReject << 4, id, reason} }

// Handle answers one unsegmented confirmed request: the APDU to send
// back (a Complex-ACK the caller may segment), or nil.
func (d *Device) Handle(a bacnet.APDU, src string, out Out) []byte {
	id, svc := a.InvokeID, a.Service
	switch svc {
	case bacnet.SvcReadProperty:
		return d.readProperty(id, a.Data)
	case bacnet.SvcReadPropertyMultiple:
		return d.readMultiple(id, a.Data)
	case bacnet.SvcWriteProperty:
		return d.writeProperty(id, a.Data)
	case bacnet.SvcWritePropertyMulti:
		return d.writeMultiple(id, a.Data)
	case bacnet.SvcSubscribeCOV:
		return d.subscribeCOV(id, a.Data, src, out)
	}
	return reject(id, bacnet.RejectUnrecognizedService)
}

// readRef reads ctx0 object, ctx1 property, optional ctx2 index.
func readRef(b []byte) (o bacnet.ObjectID, p uint32, idx int, rest []byte, err error) {
	t, rest, err := bacnet.ReadTag(b)
	if err != nil || !t.Context || t.Num != 0 || len(t.Data) != 4 {
		return o, 0, 0, nil, errors.New("object identifier expected")
	}
	o = bacnet.ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
	t, rest, err = bacnet.ReadTag(rest)
	if err != nil || !t.Context || t.Num != 1 {
		return o, 0, 0, nil, errors.New("property identifier expected")
	}
	pv, _ := bacnet.BeUnsigned(t.Data)
	p, idx = uint32(pv), -1
	if t2, r2, err := bacnet.ReadTag(rest); err == nil && t2.Context && t2.Num == 2 && !t2.Open {
		iv, _ := bacnet.BeUnsigned(t2.Data)
		idx, rest = int(iv), r2
	}
	return o, p, idx, rest, nil
}

func (d *Device) readProperty(id byte, b []byte) []byte {
	o, p, idx, rest, err := readRef(b)
	if err != nil || len(rest) != 0 {
		return reject(id, 0)
	}
	d.mu.Lock()
	v, cls, code := d.prop(o, p)
	d.mu.Unlock()
	if cls == 0 {
		v, cls, code = indexed(v, idx)
	}
	if cls != 0 {
		return bacnet.ErrorAPDU(id, bacnet.SvcReadProperty, cls, code)
	}
	var e bacnet.Enc
	e.CtxObjectID(0, o)
	e.CtxUnsigned(1, uint64(p))
	if idx >= 0 {
		e.CtxUnsigned(2, uint64(idx))
	}
	e.Open(3)
	if err := encodeValue(&e, v); err != nil {
		return bacnet.ErrorAPDU(id, bacnet.SvcReadProperty, ClassProperty, CodeOther)
	}
	e.Close(3)
	return append([]byte{bacnet.PDUComplexACK << 4, id, bacnet.SvcReadProperty}, e.B...)
}

// readMultiple answers ReadPropertyMultiple (clause 15.7), errors in
// place of the values that cannot be read.
func (d *Device) readMultiple(id byte, b []byte) []byte {
	var e bacnet.Enc
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(b) > 0 {
		t, rest, err := bacnet.ReadTag(b)
		if err != nil || !t.Context || t.Num != 0 || len(t.Data) != 4 {
			return reject(id, 0)
		}
		o := bacnet.ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
		t, rest, err = bacnet.ReadTag(rest)
		if err != nil || !t.Open || t.Num != 1 {
			return reject(id, 0)
		}
		type ref struct {
			p   uint32
			idx int
		}
		var refs []ref
		for {
			t, r, err := bacnet.ReadTag(rest)
			if err != nil {
				return reject(id, 0)
			}
			if t.Close && t.Num == 1 {
				rest = r
				break
			}
			if !t.Context || t.Num != 0 {
				return reject(id, 0)
			}
			pv, _ := bacnet.BeUnsigned(t.Data)
			rf := ref{uint32(pv), -1}
			if t2, r2, err := bacnet.ReadTag(r); err == nil && t2.Context && t2.Num == 1 && !t2.Open && !t2.Close {
				iv, _ := bacnet.BeUnsigned(t2.Data)
				rf.idx, r = int(iv), r2
			}
			rest = r
			if (rf.p == propAll || rf.p == propRequired || rf.p == propOptional) && d.objs[o] != nil {
				for _, p := range d.propList(o) {
					refs = append(refs, ref{p, -1})
				}
				continue
			}
			refs = append(refs, rf)
		}
		b = rest
		e.CtxObjectID(0, o)
		e.Open(1)
		for _, rf := range refs {
			e.CtxUnsigned(2, uint64(rf.p))
			if rf.idx >= 0 {
				e.CtxUnsigned(3, uint64(rf.idx))
			}
			v, cls, code := d.prop(o, rf.p)
			if cls == 0 {
				v, cls, code = indexed(v, rf.idx)
			}
			if cls == 0 {
				e.Open(4)
				if encodeValue(&e, v) == nil {
					e.Close(4)
					continue
				}
				// cannot happen for values set through the API
				e.Close(4)
				continue
			}
			e.Open(5)
			_ = e.App(bacnet.Enumerated(cls))
			_ = e.App(bacnet.Enumerated(code))
			e.Close(5)
		}
		e.Close(1)
	}
	return append([]byte{bacnet.PDUComplexACK << 4, id, bacnet.SvcReadPropertyMultiple}, e.B...)
}

// write stores one property write; d.mu is held.
func (d *Device) write(o bacnet.ObjectID, p uint32, idx int, vals []any, prio int) (cls, code uint32) {
	obj := d.objs[o]
	if obj == nil {
		return ClassObject, CodeUnknownObject
	}
	if len(vals) != 1 {
		return ClassProperty, CodeTypeMismatch
	}
	v := vals[0]
	commanded := obj.Commandable && p == bacnet.PropPresentValue
	if !commanded && !obj.Writable[p] {
		if _, _, c := d.prop(o, p); c == CodeUnknownProp {
			return ClassProperty, CodeUnknownProp
		}
		return ClassProperty, CodeWriteDenied
	}
	if prio == 0 {
		prio = 16
	}
	if prio < 1 || prio > 16 || prio == 6 {
		return ClassProperty, CodeValueRange
	}
	if !commanded && v == nil {
		return ClassProperty, CodeTypeMismatch
	}
	if cur, _, _ := d.prop(o, p); v != nil && cur != nil && !sameKind(cur, v) {
		return ClassProperty, CodeTypeMismatch
	}
	if d.cfg.OnWrite != nil {
		d.mu.Unlock()
		err := d.cfg.OnWrite(o, p, idx, v, prio)
		d.mu.Lock()
		if err != nil {
			var be *Error
			if errors.As(err, &be) {
				return be.Class, be.Code
			}
			return ClassProperty, CodeWriteDenied
		}
	}
	if commanded {
		obj.prio[prio-1] = v
	} else {
		obj.Props[p] = v
	}
	return 0, 0
}

// sameKind reports whether v may replace cur (the same Go type; any
// number for a number).
func sameKind(cur, v any) bool {
	return reflectKind(cur) == reflectKind(v)
}

func reflectKind(v any) string {
	switch v.(type) {
	case float32, float64:
		return "real"
	case uint64, uint32, uint:
		return "unsigned"
	case int64, int:
		return "signed"
	case bool:
		return "bool"
	case string:
		return "string"
	case bacnet.Enumerated:
		return "enum"
	case bacnet.BitString:
		return "bits"
	case bacnet.ObjectID:
		return "oid"
	}
	return "other"
}

func (d *Device) writeProperty(id byte, b []byte) []byte {
	o, p, idx, rest, err := readRef(b)
	if err != nil {
		return reject(id, 0)
	}
	t, rest, err := bacnet.ReadTag(rest)
	if err != nil || !t.Open || t.Num != 3 {
		return reject(id, 0)
	}
	vals, rest, err := bacnet.ValuesUntilClose(rest, 3)
	if err != nil {
		return reject(id, 0)
	}
	prio := 0
	if t, _, err := bacnet.ReadTag(rest); err == nil && t.Context && t.Num == 4 {
		pv, _ := bacnet.BeUnsigned(t.Data)
		prio = int(pv)
	}
	d.mu.Lock()
	cls, code := d.write(o, p, idx, vals, prio)
	d.mu.Unlock()
	if cls != 0 {
		return bacnet.ErrorAPDU(id, bacnet.SvcWriteProperty, cls, code)
	}
	if p == bacnet.PropPresentValue || p == bacnet.PropStatusFlags {
		go d.notify(o)
	}
	return []byte{bacnet.PDUSimpleACK << 4, id, bacnet.SvcWriteProperty}
}

// writeMultiple answers WritePropertyMultiple (clause 15.10): writes
// stop at the first failure, which the error names.
func (d *Device) writeMultiple(id byte, b []byte) []byte {
	var changed []bacnet.ObjectID
	defer func() {
		for _, o := range changed {
			go d.notify(o)
		}
	}()
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(b) > 0 {
		t, rest, err := bacnet.ReadTag(b)
		if err != nil || !t.Context || t.Num != 0 || len(t.Data) != 4 {
			return reject(id, 0)
		}
		o := bacnet.ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
		if t, rest, err = bacnet.ReadTag(rest); err != nil || !t.Open || t.Num != 1 {
			return reject(id, 0)
		}
		for {
			t, r, err := bacnet.ReadTag(rest)
			if err != nil {
				return reject(id, 0)
			}
			if t.Close && t.Num == 1 {
				rest = r
				break
			}
			if !t.Context || t.Num != 0 {
				return reject(id, 0)
			}
			pv, _ := bacnet.BeUnsigned(t.Data)
			p, idx := uint32(pv), -1
			t, r, err = bacnet.ReadTag(r)
			if err == nil && t.Context && t.Num == 1 && !t.Open {
				iv, _ := bacnet.BeUnsigned(t.Data)
				idx = int(iv)
				t, r, err = bacnet.ReadTag(r)
			}
			if err != nil || !t.Open || t.Num != 2 {
				return reject(id, 0)
			}
			vals, r2, err := bacnet.ValuesUntilClose(r, 2)
			if err != nil {
				return reject(id, 0)
			}
			prio := 0
			if t, r3, err := bacnet.ReadTag(r2); err == nil && t.Context && t.Num == 3 && !t.Open && !t.Close {
				pr, _ := bacnet.BeUnsigned(t.Data)
				prio, r2 = int(pr), r3
			}
			rest = r2
			if cls, code := d.write(o, p, idx, vals, prio); cls != 0 {
				var e bacnet.Enc
				e.Open(0)
				_ = e.App(bacnet.Enumerated(cls))
				_ = e.App(bacnet.Enumerated(code))
				e.Close(0)
				e.Open(1)
				e.CtxObjectID(0, o)
				e.CtxUnsigned(1, uint64(p))
				if idx >= 0 {
					e.CtxUnsigned(2, uint64(idx))
				}
				e.Close(1)
				return append([]byte{bacnet.PDUError << 4, id, bacnet.SvcWritePropertyMulti}, e.B...)
			}
			if p == bacnet.PropPresentValue || p == bacnet.PropStatusFlags {
				changed = append(changed, o)
			}
		}
		b = rest
	}
	return []byte{bacnet.PDUSimpleACK << 4, id, bacnet.SvcWritePropertyMulti}
}

// subscribeCOV answers SubscribeCOV (clause 13.14): a subscription, its
// renewal, or with no confirmation and lifetime its cancellation; a new
// subscription gets an initial notification.
func (d *Device) subscribeCOV(id byte, b []byte, src string, out Out) []byte {
	t, rest, err := bacnet.ReadTag(b)
	if err != nil || !t.Context || t.Num != 0 {
		return reject(id, 0)
	}
	process, _ := bacnet.BeUnsigned(t.Data)
	t, rest, err = bacnet.ReadTag(rest)
	if err != nil || !t.Context || t.Num != 1 || len(t.Data) != 4 {
		return reject(id, 0)
	}
	o := bacnet.ObjectIDFrom(binary.BigEndian.Uint32(t.Data))
	confirmed, lifetime, cancel := false, uint64(0), true
	if t, r, err := bacnet.ReadTag(rest); err == nil && t.Context && t.Num == 2 {
		confirmed, cancel, rest = t.Lvt != 0 || (len(t.Data) > 0 && t.Data[0] != 0), false, r
		if t, _, err := bacnet.ReadTag(rest); err == nil && t.Context && t.Num == 3 {
			lifetime, _ = bacnet.BeUnsigned(t.Data)
		}
	}
	key := subKey{addr: src, process: uint32(process), obj: o}
	d.mu.Lock()
	obj := d.objs[o]
	if obj == nil {
		d.mu.Unlock()
		return bacnet.ErrorAPDU(id, bacnet.SvcSubscribeCOV, ClassObject, CodeUnknownObject)
	}
	if cancel {
		delete(d.subs, key)
		d.mu.Unlock()
		return []byte{bacnet.PDUSimpleACK << 4, id, bacnet.SvcSubscribeCOV}
	}
	if _, ok := obj.Props[bacnet.PropPresentValue]; !ok && !obj.Commandable {
		d.mu.Unlock()
		return bacnet.ErrorAPDU(id, bacnet.SvcSubscribeCOV, ClassObject, 45) // optional-functionality-not-supported
	}
	s := &sub{out: out, confirmed: confirmed}
	if lifetime > 0 {
		s.expires = time.Now().Add(time.Duration(lifetime) * time.Second)
	}
	d.subs[key] = s
	d.mu.Unlock()
	go func() {
		time.Sleep(10 * time.Millisecond) // after the Simple-ACK
		d.notifyOne(key, s)
	}()
	return []byte{bacnet.PDUSimpleACK << 4, id, bacnet.SvcSubscribeCOV}
}

// notify sends a COV notification to every subscriber of o.
func (d *Device) notify(o bacnet.ObjectID) {
	d.mu.Lock()
	var keys []subKey
	var subs []*sub
	for k, s := range d.subs {
		if k.obj == o {
			keys = append(keys, k)
			subs = append(subs, s)
		}
	}
	d.mu.Unlock()
	for i := range keys {
		d.notifyOne(keys[i], subs[i])
	}
}

func (d *Device) notifyOne(k subKey, s *sub) {
	d.mu.Lock()
	pv, _, _ := d.prop(k.obj, bacnet.PropPresentValue)
	sf, _, _ := d.prop(k.obj, bacnet.PropStatusFlags)
	remaining := uint32(0)
	if !s.expires.IsZero() {
		remaining = uint32(max(time.Until(s.expires)/time.Second, 0))
	}
	d.invoke++
	inv := d.invoke
	d.mu.Unlock()
	body, err := bacnet.EncodeCOVNotification(bacnet.COVNotification{Process: k.process, Device: d.ID(), Object: k.obj,
		Values: map[uint32][]any{bacnet.PropPresentValue: {pv}, bacnet.PropStatusFlags: {sf}}}, remaining)
	if err != nil {
		d.log.Warn("bacnet device: COV notification", "err", err)
		return
	}
	var apdu []byte
	if s.confirmed {
		apdu = bacnet.Confirmed(inv, bacnet.SvcConfirmedCOV, body)
	} else {
		apdu = append([]byte{bacnet.PDUUnconfirmed << 4, bacnet.SvcUnconfirmedCOV}, body...)
	}
	if err := s.out(apdu, s.confirmed); err != nil {
		d.log.Debug("bacnet device: COV notification not sent", "err", err)
	}
}
