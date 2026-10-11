// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package bacnet_test

import (
	"fmt"

	"github.com/cB-Sigma/bacnet"
)

// Build the BACnet/IP frame of a confirmed ReadProperty request for the
// present-value of analog input 1, and read it back. The client
// (bacnet.NewClient, Client.ReadProperty) sends such frames; bacnet-sim has
// a runnable client example against a simulated device.
func ExampleEncodeReadProperty() {
	req := bacnet.EncodeReadProperty(bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 1}, bacnet.PropPresentValue)
	frame := bacnet.Frame(bacnet.Confirmed(1, bacnet.SvcReadProperty, req), true)
	fmt.Printf("% x\n", frame)

	apdu, err := bacnet.Unframe(frame)
	if err != nil {
		panic(err)
	}
	a, err := bacnet.ParseAPDU(apdu)
	fmt.Println(a.Service, err)
	// Output:
	// 81 0a 00 11 01 04 02 65 01 0c 0c 00 00 00 01 19 55
	// 12 <nil>
}
