package bacnet

// The BBMD function of a BACnet/IP port (Annex J.4, J.5): a Broadcast
// Distribution Table of peer BBMDs with their broadcast distribution
// masks, a Foreign Device Table of registered foreign devices with their
// time-to-live plus the 30 s grace period, and forwarding of broadcasts
// between the local subnet, the peers and the foreign devices as
// Forwarded-NPDUs. A port that is not a BBMD answers the BBMD-only
// requests with their NAK (J.2.1).

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"sync"
	"time"
)

// BVLC functions of Annex J used only by BBMDs (J.2).
const (
	BVLCWriteBDT      = 0x01
	BVLCReadBDT       = 0x02
	BVLCReadBDTAck    = 0x03
	BVLCReadFDT       = 0x06
	BVLCReadFDTAck    = 0x07
	BVLCDeleteFDT     = 0x08
	ResultWriteBDTNAK = 0x0010
	ResultReadBDTNAK  = 0x0020
	ResultReadFDTNAK  = 0x0040
	ResultDeleteNAK   = 0x0050
	fdGrace           = 30 * time.Second // J.5.2.3
	defaultMaxFD      = 128
)

// BDTEntry is a BDT entry: a BBMD's B/IP address and its broadcast
// distribution mask (J.4.3.2).
type BDTEntry struct {
	Addr *net.UDPAddr
	Mask [4]byte
}

// ForwardTo is where a Forwarded-NPDU for this entry goes: the inverted
// Mask ORed with the address (J.4.5), the BBMD itself for an all-ones
// Mask (two-hop) or the subnet's directed broadcast address (one-hop).
func (e BDTEntry) ForwardTo() *net.UDPAddr {
	ip := e.Addr.IP.To4()
	out := make(net.IP, 4)
	for i := range 4 {
		out[i] = ip[i] | ^e.Mask[i]
	}
	return &net.UDPAddr{IP: out, Port: e.Addr.Port}
}

func (e BDTEntry) TwoHop() bool { return e.Mask == [4]byte{255, 255, 255, 255} }

// fdtEntry is a registered foreign device.
type fdtEntry struct {
	Addr    *net.UDPAddr
	Ttl     uint16
	expires time.Time // registration time + TTL + grace
}

// bbmdState is the BBMD function of a client's B/IP socket.
type bbmdState struct {
	mu     sync.Mutex
	bdt    []BDTEntry
	own    int // index of this BBMD's own BDT entry
	accept bool
	maxFD  int
	fdt    map[string]*fdtEntry
	Now    func() time.Time
}

func NewBBMD(bdt []BDTEntry, own int, accept bool, maxFD int) *bbmdState {
	if maxFD <= 0 {
		maxFD = defaultMaxFD
	}
	return &bbmdState{bdt: bdt, own: own, accept: accept, maxFD: maxFD, fdt: map[string]*fdtEntry{}, Now: time.Now}
}

// OwnEntry finds this BBMD's entry in a BDT: the one with the socket's
// port whose address is the socket's or one of the host's.
func OwnEntry(bdt []BDTEntry, local *net.UDPAddr) (int, error) {
	var mine []net.IP
	if local.IP != nil && !local.IP.IsUnspecified() {
		mine = []net.IP{local.IP}
	} else {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				mine = append(mine, n.IP)
			}
		}
	}
	for i, e := range bdt {
		if e.Addr.Port != local.Port {
			continue
		}
		for _, ip := range mine {
			if ip.Equal(e.Addr.IP) {
				return i, nil
			}
		}
	}
	return -1, errors.New("the BDT has no entry for this BBMD (J.4.3.2: it lists the local BBMD too)")
}

// setBDT replaces the table and the accept flag (on ACTIVATE_CHANGES).
func (b *bbmdState) Set(bdt []BDTEntry, own int, accept bool) {
	b.mu.Lock()
	b.bdt, b.own, b.accept = bdt, own, accept
	b.mu.Unlock()
}

func (b *bbmdState) Table() ([]BDTEntry, int, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]BDTEntry(nil), b.bdt...), b.own, b.accept
}

// Register adds or renews a foreign device (J.5.2.2, J.5.2.3).
func (b *bbmdState) Register(from *net.UDPAddr, ttl uint16) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := from.String()
	if !b.accept || b.fdt[k] == nil && len(b.fdt) >= b.maxFD {
		return false
	}
	b.fdt[k] = &fdtEntry{Addr: from, Ttl: ttl, expires: b.Now().Add(time.Duration(ttl)*time.Second + fdGrace)}
	return true
}

func (b *bbmdState) registered(from *net.UDPAddr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.fdt[from.String()]
	return e != nil && b.Now().Before(e.expires)
}

func (b *bbmdState) delete(addr *net.UDPAddr) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := addr.String()
	if b.fdt[k] == nil {
		return false
	}
	delete(b.fdt, k)
	return true
}

// Purge clears the entries whose time has run out.
func (b *bbmdState) Purge(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, e := range b.fdt {
		if !now.Before(e.expires) {
			delete(b.fdt, k)
		}
	}
}

// Fds is the FDT in address order.
func (b *bbmdState) Fds() []fdtEntry {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]fdtEntry, 0, len(b.fdt))
	for _, e := range b.fdt {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.String() < out[j].Addr.String() })
	return out
}

// Remaining is an entry's seconds to purge, grace included (J.2.8.1).
func (b *bbmdState) Remaining(e fdtEntry) uint16 {
	s := time.Until(e.expires)
	if b.Now != nil {
		s = e.expires.Sub(b.Now())
	}
	if s < 0 {
		return 0
	}
	return uint16(min(s/time.Second, 65535))
}

func BDTBytes(bdt []BDTEntry) []byte {
	var p []byte
	for _, e := range bdt {
		p = append(p, BIPAddr(e.Addr)...)
		p = append(p, e.Mask[:]...)
	}
	return p
}

func (b *bbmdState) fdtBytes() []byte {
	var p []byte
	for _, e := range b.Fds() {
		p = append(p, BIPAddr(e.Addr)...)
		p = binary.BigEndian.AppendUint16(p, e.Ttl)
		p = binary.BigEndian.AppendUint16(p, b.Remaining(e))
	}
	return p
}

func parseBIP(b []byte) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(b[0], b[1], b[2], b[3]).To4(), Port: int(binary.BigEndian.Uint16(b[4:]))}
}

// ---- the client's side --------------------------------------------------------------

func (c *Client) sendRaw(pkt []byte, to *net.UDPAddr) {
	if _, err := c.Conn.WriteToUDP(pkt, to); err != nil {
		c.Log.Debug("BACnet/IP message not sent", "to", to, "error", err)
	}
}

// localBroadcast sends a BVLL message to every node of the local subnet:
// to the B/IP broadcast address, or to each of fanout (a subnet given
// member by member, for hosts and tests without broadcast).
func (c *Client) localBroadcast(pkt []byte) error {
	if len(c.Fanout) > 0 {
		for _, a := range c.Fanout {
			c.sendRaw(pkt, a)
		}
		return nil
	}
	if c.Broadcast == nil {
		return errors.New("no broadcast address is configured")
	}
	_, err := c.Conn.WriteToUDP(pkt, c.Broadcast)
	return err
}

// bvllService handles the BVLL requests that are not NPDUs. It reports
// whether the frame was consumed.
func (c *Client) bvllService(from *net.UDPAddr, f NPDU) bool {
	b := c.BBMDRole
	switch f.Fn {
	case BVLCWriteBDT:
		c.sendRaw(BVLC(BVLCResult, Be16(ResultWriteBDTNAK)), from) // J.4.4.2: always
	case BVLCReadBDT:
		if b == nil {
			c.sendRaw(BVLC(BVLCResult, Be16(ResultReadBDTNAK)), from)
		} else {
			bdt, _, _ := b.Table()
			c.sendRaw(BVLC(BVLCReadBDTAck, BDTBytes(bdt)), from)
		}
	case BVLCReadFDT:
		if b == nil {
			c.sendRaw(BVLC(BVLCResult, Be16(ResultReadFDTNAK)), from)
		} else {
			c.sendRaw(BVLC(BVLCReadFDTAck, b.fdtBytes()), from)
		}
	case BVLCDeleteFDT:
		code := uint16(ResultDeleteNAK)
		if b != nil && len(f.Data) == 6 && b.delete(parseBIP(f.Data)) {
			code = ResultOK
		}
		c.sendRaw(BVLC(BVLCResult, Be16(code)), from)
	case BVLCRegisterFD:
		code := uint16(ResultRegisterFDNAK)
		if b != nil && len(f.Data) == 2 && b.Register(from, binary.BigEndian.Uint16(f.Data)) {
			code = ResultOK
		}
		c.sendRaw(BVLC(BVLCResult, Be16(code)), from)
	default:
		return false
	}
	return true
}

// Forward is the BBMD's part for an NPDU frame received from from (J.4.5);
// it reports whether the NPDU is also for this node.
func (c *Client) forward(from *net.UDPAddr, f NPDU, np []byte) bool {
	b := c.BBMDRole
	switch f.Fn {
	case BVLCDistributeBcast:
		if b == nil || !b.registered(from) {
			c.sendRaw(BVLC(BVLCResult, Be16(ResultDistributeNAK)), from)
			return false
		}
		fwd := encodeForwarded(from, np)
		_ = c.localBroadcast(fwd)
		c.toPeers(fwd)
		c.toForeign(fwd, from)
		return true
	case BVLCOriginalBcast:
		if b == nil || c.isOwn(from) {
			return true
		}
		fwd := encodeForwarded(from, np)
		c.toPeers(fwd)
		c.toForeign(fwd, nil)
		return true
	case BVLCForwardedNPDU:
		if b == nil {
			return true
		}
		if c.isOwn(from) {
			return false // this BBMD's own local broadcast coming back
		}
		bdt, own, _ := b.Table()
		peer := false
		for i, e := range bdt {
			if i != own && e.ForwardTo().String() == from.String() || e.Addr.String() == from.String() {
				peer = true
			}
		}
		if !peer {
			return true // from another BBMD on this subnet, or a stray: only for this node
		}
		fwd := encodeForwarded(f.Origin, np)
		if own >= 0 && bdt[own].TwoHop() {
			// Came by unicast: the subnet has not seen it yet.
			_ = c.localBroadcast(fwd)
		}
		c.toForeign(fwd, nil)
		return true
	}
	return true
}

func encodeForwarded(origin *net.UDPAddr, np []byte) []byte {
	b := append([]byte{bvlcType, BVLCForwardedNPDU, 0, 0}, BIPAddr(origin)...)
	b = append(b, np...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}

func (c *Client) toPeers(pkt []byte) {
	bdt, own, _ := c.BBMDRole.Table()
	for i, e := range bdt {
		if i != own {
			c.sendRaw(pkt, e.ForwardTo())
		}
	}
}

func (c *Client) toForeign(pkt []byte, except *net.UDPAddr) {
	for _, e := range c.BBMDRole.Fds() {
		if except == nil || e.Addr.String() != except.String() {
			c.sendRaw(pkt, e.Addr)
		}
	}
}

// isOwn reports whether a is this BBMD's own B/IP address.
func (c *Client) isOwn(a *net.UDPAddr) bool {
	bdt, own, _ := c.BBMDRole.Table()
	if own >= 0 && bdt[own].Addr.String() == a.String() {
		return true
	}
	l, _ := c.Conn.LocalAddr().(*net.UDPAddr)
	return l != nil && l.String() == a.String()
}

// ownAddr is the address this BBMD gives as the origin of its own
// broadcasts.
func (c *Client) ownBIP() *net.UDPAddr {
	bdt, own, _ := c.BBMDRole.Table()
	if own >= 0 {
		return bdt[own].Addr
	}
	l, _ := c.Conn.LocalAddr().(*net.UDPAddr)
	return l
}
