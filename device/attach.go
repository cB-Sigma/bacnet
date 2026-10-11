// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package device

import "github.com/cB-Sigma/bacnet"

// Attach serves the device on a bacnet.Client's data link instead of its
// own UDP socket: BACnet/IP, BACnet/IPv6 (NewClient6) or BACnet/SC
// (NewClientSC), so one port is both a client and a device. The client
// segments the answers and reassembles segmented requests itself. An
// OnUnconfirmed hook set before Attach still runs. Call it before the
// client's Serve.
func (d *Device) Attach(c *bacnet.Client) {
	out := func(from bacnet.Dest) Out {
		return func(b []byte, expectReply bool) error {
			return c.SendAPDU(from.Addr, bacnet.Dest{Net: from.Net, MAC: from.MAC}, expectReply, b)
		}
	}
	c.OnConfirmed = func(from bacnet.Dest, a bacnet.APDU) []byte {
		return d.Handle(a, from.Key(), out(from))
	}
	prev := c.OnUnconfirmed
	c.OnUnconfirmed = func(from bacnet.Dest, a bacnet.APDU) {
		o := out(from)
		d.unconfirmed(a, func(b []byte) { _ = o(b, false) })
		if prev != nil {
			prev(from, a)
		}
	}
}
