package bacnet

// BACnet/IPv6 (Annex U): the BVLL of type X'82' over UDP/IPv6. Nodes are
// known to the network layer by a 3-octet VMAC, the device instance
// (H.7.2), or a random instance VMAC when no instance is configured; the
// data link keeps a VMAC table (H.7.1, U.5) mapping VMACs to B/IPv6
// addresses (IPv6 address and UDP port), filled from every message
// received and, for an unknown destination, by Address-Resolution (the
// VMAC is known) or Virtual-Address-Resolution (the address is known).
// Broadcasts are multicasts to the configured group (default
// [FF02::BAC0]:47808), or Distribute-Broadcast-To-Network through a BBMD
// when registered as a foreign device. This node is never a BBMD: the
// BBMD-only requests are answered with their NAK (U.4.4, U.4.5.3,
// U.4.5.4).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// BVLC functions and result codes of Annex U (Table U-1, U.2.1.1).
const (
	bvlc6Type          = 0x82
	B6Result           = 0x00
	B6OriginalUnicast  = 0x01
	B6OriginalBcast    = 0x02
	B6AddrRes          = 0x03
	B6FwdAddrRes       = 0x04
	B6AddrResACK       = 0x05
	B6VirtAddrRes      = 0x06
	B6VirtAddrResACK   = 0x07
	B6ForwardedNPDU    = 0x08
	B6RegisterFD       = 0x09
	B6DeleteFDTEntry   = 0x0a
	B6DistributeBcast  = 0x0c
	R6OK               = 0x0000
	R6AddrResNAK       = 0x0030
	r6VirtAddrResNAK   = 0x0060
	R6RegisterFDNAK    = 0x0090
	R6DeleteFDTNAK     = 0x00a0
	R6DistributeNAK    = 0x00c0
	defaultIPv6Group   = "ff02::bac0"
	randomVMACBase     = 0x400000 // random instance VMACs are 0x400000..0x7FFFFF (H.7.2)
	B6AddrLen          = 18       // IPv6 address and UDP port
	maxVMACResolutions = 4        // random VMAC retries when another node answers for it
)

// VMAC6 is a B/IPv6 node's 3-octet VMAC (H.7.2).
type VMAC6 [3]byte

func (v VMAC6) Network() string { return "bacnet-ipv6" }
func (v VMAC6) String() string  { return fmt.Sprintf("%02X%02X%02X", v[0], v[1], v[2]) }

// Peer6 is a B/IPv6 node as the network layer sees it: its VMAC, and the
// B/IPv6 address it was heard from. It names the node by that address, as
// a configured device address does.
type Peer6 struct {
	UDP  *net.UDPAddr
	VMAC VMAC6
}

func (p Peer6) Network() string { return "bacnet-ipv6" }
func (p Peer6) String() string  { return p.UDP.String() }

// Instance is the device instance (or random instance) the VMAC carries.
func (v VMAC6) Instance() uint32 { return uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2]) }

// VMACOfInstance is the device instance as a VMAC: three octets, high
// order first, the top two bits zero.
func VMACOfInstance(i uint32) VMAC6 { return VMAC6{byte(i >> 16 & 0x3f), byte(i >> 8), byte(i)} }

// RandomInstanceVMAC is a random instance VMAC: B'01' then 22 random bits.
func RandomInstanceVMAC() VMAC6 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	r := binary.BigEndian.Uint32(b[:]) & 0x3fffff
	v := r | randomVMACBase
	return VMAC6{byte(v >> 16), byte(v >> 8), byte(v)}
}

// BVLC6 is one decoded (or to be encoded) Annex U BVLL message.
type BVLC6 struct {
	Fn     byte
	Src    VMAC6        // Source- or Original-Source-Virtual-Address
	Dst    VMAC6        // Destination- or Target-Virtual-Address
	Origin *net.UDPAddr // Original-Source-B/IPv6-Address (Forwarded-*), or the FDT entry
	Result uint16
	Ttl    uint16
	NPDU   []byte
}

// B6Addr is the 18-octet B/IPv6 address of a: IPv6 address then port.
func B6Addr(a *net.UDPAddr) []byte {
	b := make([]byte, B6AddrLen)
	if a != nil {
		copy(b, a.IP.To16())
		binary.BigEndian.PutUint16(b[16:], uint16(a.Port))
	}
	return b
}

func parseB6Addr(b []byte) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), b[:16]...), Port: int(binary.BigEndian.Uint16(b[16:]))}
}

func EncodeBVLC6(m BVLC6) []byte {
	b := []byte{bvlc6Type, m.Fn, 0, 0}
	b = append(b, m.Src[:]...)
	switch m.Fn {
	case B6Result:
		b = binary.BigEndian.AppendUint16(b, m.Result)
	case B6OriginalUnicast:
		b = append(append(b, m.Dst[:]...), m.NPDU...)
	case B6OriginalBcast, B6DistributeBcast:
		b = append(b, m.NPDU...)
	case B6AddrRes, B6AddrResACK, B6VirtAddrResACK:
		b = append(b, m.Dst[:]...)
	case B6FwdAddrRes:
		b = append(append(b, m.Dst[:]...), B6Addr(m.Origin)...)
	case B6VirtAddrRes:
	case B6ForwardedNPDU:
		b = append(append(b, B6Addr(m.Origin)...), m.NPDU...)
	case B6RegisterFD:
		b = binary.BigEndian.AppendUint16(b, m.Ttl)
	case B6DeleteFDTEntry:
		b = append(b, B6Addr(m.Origin)...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

// fixed6 is the exact length of each Annex U message without an NPDU, and
// the header length of those with one (negative: at least that much).
var fixed6 = map[byte]int{
	B6Result: 9, B6OriginalUnicast: -10, B6OriginalBcast: -7, B6AddrRes: 10, B6FwdAddrRes: 28, B6AddrResACK: 10,
	B6VirtAddrRes: 7, B6VirtAddrResACK: 10, B6ForwardedNPDU: -25, B6RegisterFD: 9, B6DeleteFDTEntry: 25, B6DistributeBcast: -7,
}

func DecodeBVLC6(b []byte) (BVLC6, error) {
	var m BVLC6
	if len(b) < 7 || b[0] != bvlc6Type {
		return m, errors.New("not a BACnet/IPv6 frame")
	}
	if l := int(binary.BigEndian.Uint16(b[2:])); l != len(b) {
		return m, fmt.Errorf("BVLC length %d does not match %d received", l, len(b))
	}
	m.Fn = b[1]
	want, ok := fixed6[m.Fn]
	switch {
	case !ok:
		return m, fmt.Errorf("unknown BACnet/IPv6 BVLC function %#02x", m.Fn)
	case want > 0 && len(b) != want, want < 0 && len(b) < -want:
		return m, fmt.Errorf("BACnet/IPv6 BVLC function %#02x has the wrong length %d", m.Fn, len(b))
	}
	copy(m.Src[:], b[4:7])
	p := b[7:]
	switch m.Fn {
	case B6Result:
		m.Result = binary.BigEndian.Uint16(p)
	case B6OriginalUnicast:
		copy(m.Dst[:], p)
		m.NPDU = p[3:]
	case B6OriginalBcast, B6DistributeBcast:
		m.NPDU = p
	case B6AddrRes, B6AddrResACK, B6VirtAddrResACK:
		copy(m.Dst[:], p)
	case B6FwdAddrRes:
		copy(m.Dst[:], p)
		m.Origin = parseB6Addr(p[3:])
	case B6ForwardedNPDU:
		m.Origin = parseB6Addr(p)
		m.NPDU = p[B6AddrLen:]
	case B6RegisterFD:
		m.Ttl = binary.BigEndian.Uint16(p)
	case B6DeleteFDTEntry:
		m.Origin = parseB6Addr(p)
	}
	return m, nil
}

// BIP6 is one B/IPv6 network port.
type BIP6 struct {
	Conn    *net.UDPConn // unicast (and the group, when it shares the port)
	mc      *net.UDPConn // the group's socket when its port differs; nil otherwise
	Group   *net.UDPAddr // where broadcasts go (a multicast group)
	BBMD    *net.UDPAddr // foreign-device registration; nil for none
	fanout  []*net.UDPAddr
	Timeout time.Duration
	Log     *slog.Logger
	Deliver func(src net.Addr, n NPDU)
	Result  func(from *net.UDPAddr, code uint16)

	Mu      sync.Mutex
	Self    VMAC6
	Random  bool // self is a random instance VMAC
	ByVMAC  map[VMAC6]*net.UDPAddr
	ByAddr  map[string]VMAC6
	Learned chan struct{} // closed and replaced whenever the table changes
	Clash   chan struct{} // closed when another node answers for self
}

// IPv6Settings selects BACnet/IPv6 (Annex U) as the data link.
type IPv6Settings struct {
	// Local is the unicast address to bind (default [::]:47808).
	Local string `json:"local,omitempty"`
	// Multicast is the B/IPv6 multicast address and port broadcasts go to
	// (default [FF02::BAC0]:47808, link-local scope).
	Multicast string `json:"multicast,omitempty"`
	// Interface is the network interface the group is joined on (needed
	// for link-local scope when the host has several).
	Interface string `json:"interface,omitempty"`
	// BBMD is a B/IPv6 BBMD to register with as a foreign device; its
	// time-to-live is bbmdTtl.
	BBMD string `json:"bbmd,omitempty"`
	// DeviceInstance is kind bacnet's VMAC (kind bacnet-server uses its
	// own); without it a random instance VMAC is used (H.7.2).
	DeviceInstance *uint32 `json:"deviceInstance,omitempty"`

	local, group, bbmd *net.UDPAddr
	ifi                *net.Interface
	// Fanout, when set, stands for the multicast domain member by member:
	// the group is not joined and broadcasts go to each (hosts and tests
	// without multicast, such as Linux loopback).
	fanout []*net.UDPAddr
}

func (s *IPv6Settings) Check() error {
	if s.Local == "" {
		s.Local = fmt.Sprintf("[::]:%d", DefaultPort)
	}
	if s.Multicast == "" {
		s.Multicast = fmt.Sprintf("[%s]:%d", defaultIPv6Group, DefaultPort)
	}
	var err error
	if s.local, err = net.ResolveUDPAddr("udp6", WithPort(s.Local)); err != nil {
		return fmt.Errorf("ipv6 local: %w", err)
	}
	if s.local.IP != nil && s.local.IP.To4() != nil && !s.local.IP.Equal(net.IPv6unspecified) {
		return fmt.Errorf("ipv6 local %q is not an IPv6 address", s.Local)
	}
	if s.group, err = net.ResolveUDPAddr("udp6", WithPort(s.Multicast)); err != nil || !s.group.IP.IsMulticast() || s.group.IP.To4() != nil {
		return fmt.Errorf("ipv6 multicast %q is not an IPv6 multicast address and port", s.Multicast)
	}
	if s.Interface != "" {
		if s.ifi, err = net.InterfaceByName(s.Interface); err != nil {
			return fmt.Errorf("ipv6 interface: %w", err)
		}
		if s.group.Zone == "" && s.group.IP.IsLinkLocalMulticast() {
			s.group.Zone = s.Interface
		}
	}
	if s.BBMD != "" {
		if s.bbmd, err = net.ResolveUDPAddr("udp6", WithPort(s.BBMD)); err != nil || s.bbmd.IP.To4() != nil {
			return fmt.Errorf("ipv6 bbmd %q is not an IPv6 address", s.BBMD)
		}
	}
	if s.DeviceInstance != nil && *s.DeviceInstance > 4194302 {
		return errors.New("ipv6 deviceInstance must be 0..4194302")
	}
	return nil
}

// openBIP6 binds the port. With the group on the unicast port one socket
// serves both; otherwise a second socket joins the group.
func openBIP6(s *IPv6Settings, instance *uint32, timeout time.Duration, log *slog.Logger) (*BIP6, error) {
	l := &BIP6{Group: s.group, BBMD: s.bbmd, Timeout: timeout, Log: log, ByVMAC: map[VMAC6]*net.UDPAddr{},
		ByAddr: map[string]VMAC6{}, Learned: make(chan struct{}), Clash: make(chan struct{})}
	if instance != nil {
		l.Self = VMACOfInstance(*instance)
	} else {
		l.Self, l.Random = RandomInstanceVMAC(), true
	}
	var err error
	if len(s.fanout) > 0 {
		if l.Conn, err = net.ListenUDP("udp6", s.local); err != nil {
			return nil, err
		}
		l.fanout = s.fanout
		return l, nil
	}
	if s.local.Port == s.group.Port && s.local.Port != 0 && (s.local.IP == nil || s.local.IP.IsUnspecified()) {
		l.Conn, err = net.ListenMulticastUDP("udp6", s.ifi, s.group)
		if err != nil {
			return nil, fmt.Errorf("joining %s: %w", s.group, err)
		}
		return l, nil
	}
	if l.Conn, err = net.ListenUDP("udp6", s.local); err != nil {
		return nil, err
	}
	if l.mc, err = net.ListenMulticastUDP("udp6", s.ifi, s.group); err != nil {
		_ = l.Conn.Close()
		return nil, fmt.Errorf("joining %s: %w", s.group, err)
	}
	return l, nil
}

func (l *BIP6) Close() {
	_ = l.Conn.Close()
	if l.mc != nil {
		_ = l.mc.Close()
	}
}

func (l *BIP6) LocalAddr() *net.UDPAddr {
	a, _ := l.Conn.LocalAddr().(*net.UDPAddr)
	return a
}

func (l *BIP6) MyVMAC() VMAC6 {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	return l.Self
}

// Serve reads both sockets until they close.
func (l *BIP6) Serve() {
	if l.mc != nil {
		go l.read(l.mc)
	}
	l.read(l.Conn)
}

func (l *BIP6) read(conn *net.UDPConn) {
	buf := make([]byte, 1600)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		m, err := DecodeBVLC6(append([]byte(nil), buf[:n]...))
		if err != nil {
			l.Log.Debug("BACnet/IPv6 frame ignored", "from", from, "error", err)
			continue
		}
		l.handle(from, m)
	}
}

// Handle is U.3 to U.5 for one message from the B/IPv6 address from.
func (l *BIP6) handle(from *net.UDPAddr, m BVLC6) {
	self := l.MyVMAC()
	src, srcAddr := m.Src, from
	if m.Fn == B6ForwardedNPDU || m.Fn == B6FwdAddrRes {
		srcAddr = m.Origin
	}
	if src == self && m.Fn != B6Result {
		// Our own multicast looped back; an answer for our VMAC from
		// elsewhere is a clash.
		if l.isSelf(srcAddr) {
			return
		}
		if m.Fn == B6AddrRes && m.Dst == self {
			// Another node checking the same random VMAC: tell it.
			l.send(srcAddr, BVLC6{Fn: B6AddrResACK, Src: self, Dst: self})
		}
		if m.Fn == B6AddrResACK || m.Fn == B6VirtAddrResACK {
			l.Mu.Lock()
			select {
			case <-l.Clash:
			default:
				close(l.Clash)
			}
			l.Mu.Unlock()
		}
		l.Log.Warn("another BACnet/IPv6 node uses this node's VMAC", "vmac", self, "from", srcAddr)
		return
	}
	if m.Fn != B6Result && m.Fn != B6RegisterFD && m.Fn != B6DeleteFDTEntry && m.Fn != B6DistributeBcast {
		l.learn(src, srcAddr)
	}
	switch m.Fn {
	case B6Result:
		l.Result(from, m.Result)
	case B6OriginalUnicast:
		if m.Dst != self {
			return // U.3: not for this node
		}
		l.up(from, m)
	case B6OriginalBcast:
		l.up(from, m)
	case B6ForwardedNPDU:
		l.up(m.Origin, m)
	case B6AddrRes, B6FwdAddrRes:
		if m.Dst == self {
			l.send(srcAddr, BVLC6{Fn: B6AddrResACK, Src: self, Dst: src})
		}
	case B6VirtAddrRes:
		l.send(from, BVLC6{Fn: B6VirtAddrResACK, Src: self, Dst: src})
	case B6AddrResACK, B6VirtAddrResACK:
		// Learned above
	case B6RegisterFD:
		l.send(from, BVLC6{Fn: B6Result, Src: self, Result: R6RegisterFDNAK})
	case B6DeleteFDTEntry:
		l.send(from, BVLC6{Fn: B6Result, Src: self, Result: R6DeleteFDTNAK})
	case B6DistributeBcast:
		l.send(from, BVLC6{Fn: B6Result, Src: self, Result: R6DistributeNAK})
	}
}

func (l *BIP6) isSelf(a *net.UDPAddr) bool {
	own := l.LocalAddr()
	if own == nil || a == nil || own.Port != a.Port {
		return false
	}
	if own.IP.Equal(a.IP) {
		return true
	}
	if !own.IP.IsUnspecified() {
		return false
	}
	addrs, _ := net.InterfaceAddrs()
	for _, x := range addrs {
		if n, ok := x.(*net.IPNet); ok && n.IP.Equal(a.IP) {
			return true
		}
	}
	return false
}

func (l *BIP6) up(src *net.UDPAddr, m BVLC6) {
	n, err := DecodeNPDU(NPDU{Fn: m.Fn}, m.NPDU)
	if err != nil {
		l.Log.Debug("BACnet/IPv6 NPDU ignored", "from", src, "error", err)
		return
	}
	l.Deliver(Peer6{UDP: src, VMAC: m.Src}, n)
}

// learn records vmac at a (U.5).
func (l *BIP6) learn(v VMAC6, a *net.UDPAddr) {
	if a == nil {
		return
	}
	l.Mu.Lock()
	defer l.Mu.Unlock()
	if old := l.ByVMAC[v]; old != nil && old.String() == a.String() {
		return
	}
	if old := l.ByVMAC[v]; old != nil {
		delete(l.ByAddr, old.String())
	}
	cp := *a
	l.ByVMAC[v] = &cp
	l.ByAddr[a.String()] = v
	close(l.Learned)
	l.Learned = make(chan struct{})
}

// Table is the VMAC table, for Virtual_MAC_Address_Table.
func (l *BIP6) Table() map[VMAC6]*net.UDPAddr {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	out := make(map[VMAC6]*net.UDPAddr, len(l.ByVMAC))
	for v, a := range l.ByVMAC {
		out[v] = a
	}
	return out
}

func (l *BIP6) LookupAddr(a *net.UDPAddr) (VMAC6, bool) {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	v, ok := l.ByAddr[a.String()]
	return v, ok
}

func (l *BIP6) LookupVMAC(v VMAC6) *net.UDPAddr {
	l.Mu.Lock()
	defer l.Mu.Unlock()
	return l.ByVMAC[v]
}

func (l *BIP6) send(to *net.UDPAddr, m BVLC6) {
	if _, err := l.Conn.WriteToUDP(EncodeBVLC6(m), to); err != nil {
		l.Log.Debug("BACnet/IPv6 message not sent", "to", to, "error", err)
	}
}

// wait blocks until the table changes, ctx ends or the deadline passes.
func (l *BIP6) wait(ctx context.Context, deadline <-chan time.Time) bool {
	l.Mu.Lock()
	ch := l.Learned
	l.Mu.Unlock()
	select {
	case <-ch:
		return true
	case <-ctx.Done():
	case <-deadline:
	}
	return false
}

// Unicast sends an NPDU to the node at a, learning its VMAC with
// Virtual-Address-Resolution first when it is not in the table; an NPDU
// whose destination cannot be translated is dropped (H.7.1).
func (l *BIP6) Unicast(a *net.UDPAddr, np []byte) error {
	v, ok := l.LookupAddr(a)
	if !ok {
		self := l.MyVMAC()
		t := time.NewTimer(l.Timeout)
		defer t.Stop()
		for !ok {
			l.send(a, BVLC6{Fn: B6VirtAddrRes, Src: self})
			if !l.wait(context.Background(), t.C) {
				return fmt.Errorf("no Virtual-Address-Resolution-ACK from %s", a)
			}
			v, ok = l.LookupAddr(a)
		}
	}
	_, err := l.Conn.WriteToUDP(EncodeBVLC6(BVLC6{Fn: B6OriginalUnicast, Src: l.MyVMAC(), Dst: v, NPDU: np}), a)
	return err
}

// unicastTo sends an NPDU to a node whose VMAC is known.
func (l *BIP6) unicastTo(p Peer6, np []byte) error {
	_, err := l.Conn.WriteToUDP(EncodeBVLC6(BVLC6{Fn: B6OriginalUnicast, Src: l.MyVMAC(), Dst: p.VMAC, NPDU: np}), p.UDP)
	return err
}

// Resolve is the B/IPv6 address of the node with VMAC v, found with
// Address-Resolution when it is not in the table.
func (l *BIP6) Resolve(ctx context.Context, v VMAC6) (*net.UDPAddr, error) {
	if a := l.LookupVMAC(v); a != nil {
		return a, nil
	}
	t := time.NewTimer(l.Timeout)
	defer t.Stop()
	if err := l.broadcastMsg(BVLC6{Fn: B6AddrRes, Src: l.MyVMAC(), Dst: v}); err != nil {
		return nil, err
	}
	for {
		if a := l.LookupVMAC(v); a != nil {
			return a, nil
		}
		if !l.wait(ctx, t.C) {
			return nil, fmt.Errorf("no Address-Resolution-ACK for VMAC %s (device %d)", v, v.Instance())
		}
	}
}

// broadcastMsg multicasts m to the group, or unicasts it to the BBMD when
// registered as a foreign device (which forwards Address-Resolution).
func (l *BIP6) broadcastMsg(m BVLC6) error {
	to := l.Group
	if l.BBMD != nil {
		to = l.BBMD
	} else if len(l.fanout) > 0 {
		for _, a := range l.fanout {
			l.send(a, m)
		}
		return nil
	}
	_, err := l.Conn.WriteToUDP(EncodeBVLC6(m), to)
	return err
}

// Broadcast sends an NPDU to every node: Original-Broadcast-NPDU to the
// Group, or Distribute-Broadcast-To-Network to the BBMD.
func (l *BIP6) Broadcast(np []byte) error {
	fn := byte(B6OriginalBcast)
	if l.BBMD != nil {
		fn = B6DistributeBcast
	}
	return l.broadcastMsg(BVLC6{Fn: fn, Src: l.MyVMAC(), NPDU: np})
}

// Register sends Register-Foreign-Device to the BBMD.
func (l *BIP6) Register(ttl uint16) error {
	_, err := l.Conn.WriteToUDP(EncodeBVLC6(BVLC6{Fn: B6RegisterFD, Src: l.MyVMAC(), Ttl: ttl}), l.BBMD)
	return err
}

// Claim checks that no other node answers for a random instance VMAC,
// choosing another when one does (H.7.2).
func (l *BIP6) Claim(ctx context.Context) {
	if !l.Random {
		return
	}
	for range maxVMACResolutions {
		l.Mu.Lock()
		self, clash := l.Self, l.Clash
		l.Mu.Unlock()
		_ = l.broadcastMsg(BVLC6{Fn: B6AddrRes, Src: self, Dst: self})
		t := time.NewTimer(l.Timeout)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
			return // nobody else has it
		case <-clash:
			t.Stop()
			l.Mu.Lock()
			l.Self, l.Clash = RandomInstanceVMAC(), make(chan struct{})
			l.Mu.Unlock()
			l.Log.Info("BACnet/IPv6 random VMAC in use elsewhere; chose another", "vmac", l.MyVMAC())
		}
	}
}

// FromResult6 maps an Annex U result code to the Annex J code the client
// expects for foreign-device registration and distribution; the others
// are kept apart.
func FromResult6(code uint16) uint16 {
	switch code {
	case R6OK:
		return ResultOK
	case R6RegisterFDNAK:
		return ResultRegisterFDNAK
	case R6DistributeNAK:
		return ResultDistributeNAK
	}
	return 0x8000 | code
}

// BBMDAddr is the BBMD address resolved by Check; nil for none.
func (s *IPv6Settings) BBMDAddr() *net.UDPAddr { return s.bbmd }

// GroupAddr is the multicast group address resolved by Check.
func (s *IPv6Settings) GroupAddr() *net.UDPAddr { return s.group }

// NetInterface is the network interface resolved by Check; nil for none.
func (s *IPv6Settings) NetInterface() *net.Interface { return s.ifi }

// SetFanout makes broadcasts go to each of addrs instead of the multicast
// Group, which is then not joined (hosts and tests without multicast,
// such as Linux loopback).
func (s *IPv6Settings) SetFanout(addrs []*net.UDPAddr) { s.fanout = addrs }
