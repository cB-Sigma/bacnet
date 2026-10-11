# Changelog

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
