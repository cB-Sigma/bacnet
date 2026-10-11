package bacnet

import (
	"fmt"
	"sort"
	"sync"
)

// discovered is one answering device.
type discovered struct {
	Instance     uint32 `json:"instance"`
	Address      string `json:"address"`
	Network      uint16 `json:"network,omitempty"`
	MAC          string `json:"mac,omitempty"`
	MaxAPDU      uint64 `json:"maxApdu"`
	Segmentation string `json:"segmentation"`
	Vendor       uint64 `json:"vendor"`
}

// iAmLog collects I-Ams while discovery rounds run: the periodic one and
// any Scan network at the same time, each with its own collector.
type iAmLog struct {
	mu   sync.Mutex
	next int
	subs map[int]map[uint32]discovered
}

// Start opens a collector.
func (l *iAmLog) Start() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.subs == nil {
		l.subs = map[int]map[uint32]discovered{}
	}
	l.next++
	l.subs[l.next] = map[uint32]discovered{}
	return l.next
}

// Stop closes a collector and returns what it saw, by instance.
func (l *iAmLog) Stop(id int) []discovered {
	l.mu.Lock()
	seen := l.subs[id]
	delete(l.subs, id)
	l.mu.Unlock()
	list := make([]discovered, 0, len(seen))
	for _, v := range seen {
		list = append(list, v)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Instance < list[j].Instance })
	return list
}

func (l *iAmLog) add(from Dest, i IAm) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.subs) == 0 {
		return
	}
	d := discovered{Instance: i.Device.Instance, MaxAPDU: i.MaxAPDU, Segmentation: segName(i.Segmentation), Vendor: i.Vendor, Network: from.Net}
	if from.Addr != nil {
		d.Address = from.Addr.String()
	}
	if len(from.MAC) > 0 {
		d.MAC = fmt.Sprintf("%x", from.MAC)
	}
	for _, seen := range l.subs {
		seen[d.Instance] = d
	}
}

func segName(e Enumerated) string {
	switch e {
	case 0:
		return "both"
	case 1:
		return "transmit"
	case 2:
		return "receive"
	case 3:
		return "none"
	}
	return fmt.Sprint(uint64(e))
}
