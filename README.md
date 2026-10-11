# bacnet

A BACnet client in pure Go for BACnet/IP, BACnet/IPv6 and BACnet Secure Connect (ANSI/ASHRAE Standard 135-2024).

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/bacnet.svg)](https://pkg.go.dev/github.com/cB-Sigma/bacnet) [![test](https://github.com/cB-Sigma/bacnet/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/bacnet/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.27.1-00ADD8.svg)](go.mod)

The module encodes and decodes BVLC, NPDU and APDU, runs confirmed and
unconfirmed services with segmentation both ways, reaches devices behind
BACnet routers, registers as a foreign device and can act as a BBMD. On
BACnet/SC it is a hub connector with failover, a hub function and a node
with direct connections, over TLS 1.3 WebSockets. It has no cgo; TLS
comes from [tlsx](https://github.com/cB-Sigma/tlsx) (a fork of Go's
crypto/tls with on-demand key updates). It was written for SigmaM2M, a
oneM2M platform, where it serves the BACnet integrations; it does not
depend on it.

## Features

| Feature | Status |
|---|---|
| BACnet/IP (Annex J): unicast, local broadcast, foreign-device registration and re-registration, Distribute-Broadcast-To-Network | yes (tested against bacnet-stack) |
| BBMD function (BDT, FDT, forwarding) | yes |
| BACnet/IPv6 (Annex U): VMACs, address resolution, multicast or BBMD | yes |
| BACnet/SC (Annex AB): hub connector with failover, heartbeat, hub function, direct connections, TLS 1.3 key updates, data options | yes (hub connector tested against bacnet-stack's hub) |
| Routing: Who-Is-Router-To-Network, devices on remote networks | yes |
| ReadProperty, ReadPropertyMultiple, WriteProperty, WritePropertyMultiple | yes (RP, RPM, WP tested against bacnet-stack) |
| SubscribeCOV, SubscribeCOVProperty, COV notifications (confirmed and unconfirmed) | yes (SubscribeCOV tested against bacnet-stack) |
| ReadRange on log buffers (by position, sequence, time) | yes (by position and whole buffer tested against bacnet-stack) |
| Who-Is/I-Am, Who-Has/I-Have | yes |
| AcknowledgeAlarm, GetEventInformation, GetAlarmSummary, event notifications | yes |
| AtomicReadFile, AtomicWriteFile, AddListElement | yes |
| DeviceCommunicationControl, ReinitializeDevice, TimeSynchronization, UTCTimeSynchronization | yes |
| Segmentation, both directions, windowed Segment-ACKs (clause 5.4) | yes; only against this module's own simulator (no open peer implements it, see below) |
| Errors, rejects and aborts as Go errors | yes |
| Device object model (serving objects to other clients) | no: a client; SigmaM2M keeps its BACnet device side |
| MS/TP, Ethernet, ARCNET, LonTalk, PTP data links | no (reach MS/TP devices through a BACnet router) |

Security hooks: `SCTLS` takes the operational certificate and issuers,
and optional hooks for a crypto policy (`CheckCertificate`), revocation
(`CheckRevocation`) and TLS 1.3 cipher suites. Without them it makes the
certificate checks of AB.7.4 only.

## Choosing a BACnet library

Compared from each project's source at the version named, in October
2026. "Tested" means run against this module in the interop tests
below. Check the projects themselves before relying on a row.

| | this module | bacnet-stack 1.6.1 | BACpypes3 0.0.110 | alexbeltran/gobacnet (63505d3, 2024-03-16) |
|---|---|---|---|---|
| Language | Go, no cgo | C | Python (asyncio) | Go |
| Licence | Apache-2.0 | GPL-2.0 with the GCC linking exception (some files other licences) | MIT | GPL-2.0 |
| Client | yes | yes (command-line tools and library) | yes | ReadProperty, ReadPropertyMultiple, Who-Is only |
| Device (server) side | no | yes | yes | no |
| Segmentation | both ways | no state machine (the SEGMENT switch only changes what the device claims) | yes | no |
| Foreign device, BBMD | both | both (tested) | both | no |
| BACnet/IPv6 | yes | yes | yes | no |
| BACnet/SC | hub connector, hub function, direct connections | hub, node, direct connections (tested as hub) | hub and direct connections over the websockets package | no |
| Simulated device for tests | yes ([bacnet-sim](https://github.com/cB-Sigma/bacnet-sim)) | demo server | sample applications | no |

Pick this module for a Go program that reads, writes and subscribes to
BACnet devices, including over BACnet/SC, without cgo. Pick
bacnet-stack or BACpypes3 when you need to be a BACnet device (serve
objects) or need MS/TP; bacnet-stack for C and embedded targets,
BACpypes3 for Python. The Go packages found besides this one
(gobacnet and its forks, for example NubeDev/bacnet) cover reading and
discovery only and are GPL-2.0.

## Install

```
go get github.com/cB-Sigma/bacnet@latest
```

Requires Go 1.27.1 or later (as tlsx does).

## Quick start

```go
import "github.com/cB-Sigma/bacnet"

c, err := bacnet.NewClient("0.0.0.0:0", slog.Default())
defer c.Close()
go c.Serve()
addr, _ := net.ResolveUDPAddr("udp", "192.0.2.10:47808")
t := bacnet.Target{Dest: bacnet.Dest{Addr: addr}, Peer: bacnet.Peer{MaxAPDU: 1476, RecvSeg: true}, Timeout: 3 * time.Second, Retries: 3}
v, err := c.ReadProperty(ctx, t, bacnet.ObjectID{Type: bacnet.AnalogInput, Instance: 1}, bacnet.PropPresentValue)
err = c.WriteProperty(ctx, t, bacnet.ObjectID{Type: bacnet.AnalogValue, Instance: 1}, bacnet.PropPresentValue, float32(21), 8)
```

Through a BBMD as a foreign device:

```go
c.BBMD = bbmdAddr
err = c.RegisterForeign(ctx, 5*time.Minute, 3*time.Second, 2)
```

On BACnet/SC, a node connected to a hub:

```go
n := &bacnet.SCNode{Creds: creds, Primary: "wss://hub.example:443", UUID: bacnet.NewUUID(), VMAC: bacnet.RandomVMAC(),
	MinReconnect: time.Second, MaxReconnect: 30 * time.Second, ConnectWait: 10 * time.Second, DisconnectWait: 5 * time.Second, Heartbeat: 5 * time.Minute}
c := bacnet.NewClientSC(n, slog.Default())
n.Start(ctx)
```

The runnable example in this module is `ExampleEncodeReadProperty`;
bacnet-sim has a client example against the simulated device.

## Documentation

API reference: https://pkg.go.dev/github.com/cB-Sigma/bacnet

| Package | What it does |
|---|---|
| `bacnet` (module root) | the codec; `Client` over B/IP (`NewClient`), B/IPv6 (`NewClient6`) and BACnet/SC (`NewClientSC`); services, ReadRange, segmentation, BBMD state; BACnet/SC `SCNode`, `SCHub`, `NodeSwitch`, `SCTLS` |
| `interop` (nested module, tests only) | this module's client against bacnet-stack 1.6.1 in Docker |

The API is wide: SigmaM2M's adapter uses encoders, decoders and data
link internals directly. Narrowing it is planned before v1.

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments: requirement IDs of the
SigmaM2M project's compliance report, with no meaning outside it. Code
comments that cite `F-` numbers refer to SigmaM2M's register of readings
where the standard leaves a choice open; PROVENANCE.md explains them.
The tests that drive the simulated device are in
[bacnet-sim](https://github.com/cB-Sigma/bacnet-sim), so this module
does not depend on its simulator.

`interop/` is a nested module with its own go.mod. It builds
bacnet-stack 1.6.1 from its sources in a container (`interop/peer`;
bacnet-stack is GPL and used only as a test peer, nothing of it is
linked into this module) and runs this module against its demo server
and BACnet/SC hub. The tests are skipped unless `SIGMA_BACNET_INTEROP=1`
is set and Docker is running:

```
cd interop && SIGMA_BACNET_INTEROP=1 go test -race -v ./...
```

### Interop tested against

Run on 2026-10-11 on macOS with Docker Desktop; every item below passed.

bacnet-stack 1.6.1 (`bacserv`, BACnet/IP, its BBMD enabled), this
module's client:

| Area | What was checked |
|---|---|
| ReadProperty | device object-name and vendor-identifier, the 78-entry object-list, an analog input's present-value as REAL, an unknown object refused with object / unknown-object |
| ReadPropertyMultiple | several properties of two objects in one request, an unknown property answered with its error in place |
| WriteProperty | analog value at priority 8 and read back, relinquished with NULL, a wrong datatype refused |
| SubscribeCOV | unconfirmed notifications: the initial one and the one after a write, with present-value and status-flags |
| ReadRange | a trend log's log-buffer by position (5 records with their times) and whole (66 records, more-items set) |
| Foreign device | Register-Foreign-Device accepted and renewed; Who-Is through Distribute-Broadcast-To-Network and a directed Who-Is, both answered by an I-Am that bacserv broadcasts and its BBMD forwards (device, max APDU 1476, no segmentation, vendor 260) |
| Segmentation | only refusals: bacserv says it has none, and aborts a segmented request; the client reports the abort |

bacnet-stack 1.6.1 (`bacschub` and a `bacserv` node, BACnet/SC), this
module's hub connector and client: TLS 1.3 with certificates issued from
bacnet-stack's test CA, Connect-Request and Accept, Who-Is broadcast
through the hub and the I-Am from bacserv's VMAC, ReadProperty,
WriteProperty and ReadPropertyMultiple through the hub.

Found on the way and fixed in this module (v0.1.0):

- bacnet-stack 1.6.1's hub crashed (SIGSEGV) on the Hello header option
  this module puts in its Connect-Request. `SCNode.NoHello` leaves it
  out for such peers (test: `TestSCNoHello`); the default still sends
  it.
- There was no constructor for a client over BACnet/SC; `NewClientSC`
  wires a node to a client.

Defects of the reference peer met on the way (not ours; recorded so
nobody chases them): bacserv answers a 78-entry object-list unsegmented
to a client that accepts only 50 octets; its BBMD distributes a
broadcast from a device that has not registered instead of refusing it;
with `SEGMENT=true` the device claims segmentation it does not have.

Not tested against an independent implementation:

- Segmentation in either direction: bacnet-stack 1.6.1 has none.
  BACpypes3 has segmentation; it was not run.
- This module's hub function with bacnet-stack's node: under Docker
  Desktop the node in its container never opened a connection to a hub
  on the host (the test is in `interop/` and skipped by default).
  Direct connections, failover and key updates on BACnet/SC; BACnet/IPv6;
  the BBMD function; routing through a router; WritePropertyMultiple,
  SubscribeCOVProperty, alarm and event services, file access, device
  management services.
- Real controllers and BMS head ends.
- In process: the simulated device of bacnet-sim (same author, so not
  independent).

## Related repositories

- [bacnet-sim](https://github.com/cB-Sigma/bacnet-sim): a simulated
  BACnet/IP device, as a Go package and a command.
- [tlsx](https://github.com/cB-Sigma/tlsx): the TLS 1.3 stack used for
  BACnet/SC.

## Status

v0.x: the API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability privately.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). Copyright 2026
Abhinav Gautam. BACnet is a registered trademark of ASHRAE; this project
is not affiliated with or endorsed by ASHRAE.
