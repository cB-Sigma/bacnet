# Changelog

## v0.2.0 (2026-10-12)

The BACnet device role, and segmentation checked against an
independent implementation. Only additions.

- `device`: a BACnet device (server): the Device object and an object
  table; Who-Is and Who-Has; ReadProperty and ReadPropertyMultiple with
  array indexes and ALL, REQUIRED, OPTIONAL; WriteProperty and
  WritePropertyMultiple with priority arrays for commandable objects, an
  `OnWrite` hook and datatype checks; SubscribeCOV with confirmed and
  unconfirmed notifications, lifetimes and cancellation; segmented
  answers (windowed, with resends) and reassembly of segmented requests.
  `Listen` serves its own BACnet/IP socket; `Attach` serves it on a
  `Client`'s data link (BACnet/IP, BACnet/IPv6 or BACnet/SC).
- Interop: BACpypes3 0.0.110's client against the device role (a
  405-entry object-list in segments, RPM, a write at priority 8, COV),
  and this module's client against a BACpypes3 device (segmented
  object-list and RPM answers, segmented RPM and WPM requests). This is
  the first check of segmentation against another implementation.

## v0.1.0 (2026-10-11)

First release, checked against bacnet-stack 1.6.1 over BACnet/IP and
BACnet/SC (see README.md, "Interop tested against").

Added while preparing it:

- `NewClientSC`: a client on a BACnet/SC node, with the node's NPDUs
  delivered to it.
- `SCNode.NoHello`: leaves the Hello header option out of the
  Connect-Request; bacnet-stack 1.6.1's hub crashed on it.
- The hub function logs (at debug level) a refused WebSocket upgrade
  and a connection that sends no Connect-Request.

The simulated device and its command moved to
[bacnet-sim](https://github.com/cB-Sigma/bacnet-sim).
