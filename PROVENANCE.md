# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go from ANSI/ASHRAE Standard
135-2024 (BACnet), read in a licensed copy. No code was ported or copied
from another implementation: when the work started no Go BACnet library
was complete and maintained, so the BVLC, NPDU and APDU encoding is our
own. Numbers, octet layouts and procedures are facts every
implementation must use; the code around them (Go types, goroutines, the
transaction and segmentation state, the hub and node connection handling)
is our own design. No text of the standard is reproduced; comments cite
clause and annex numbers in our own words.

The code came with SigmaM2M's baseline (2026-09-27) and was extended in
later SigmaM2M work. It became a module of its own on 2026-10-06; the
identifiers SigmaM2M's adapter needs were exported then, which is why
the API is wider than a library designed from scratch would be. On
2026-10-11 the simulated device, its command and the example that drives
it moved to the separate module bacnet-sim (with `git mv`), so this
module does not depend on its simulator, and the bacnet-stack interop
tests (interop/) were added. They led to `SCNode.NoHello` and
`NewClientSC` (CHANGELOG.md).

## Notes on open readings (F- numbers)

Where the standard contradicts itself, the choice made was recorded in
SigmaM2M's register of findings, and two test comments cite its numbers.
In our words:

| Note | Where | Choice |
|---|---|---|
| F-951 | Annex F, ReadPropertyMultiple example | the example labels one octet as the OPTIONAL property but prints the code of present-value; the test vector uses the code of OPTIONAL |
| F-954 | Annex AB, Secure Path header option | the clause gives the option a must-understand flag, but as a data option that bit has another meaning and the figure leaves it clear; the encoder writes what the caller sets and the vector follows the figure |

## Sources

| Area (files) | Followed | Read for facts only (no code taken) |
|---|---|---|
| Tags, application and context encoding (codec.go) | clause 20.2, ASN.1 of clause 21 | none |
| NPDU, network messages, routing (codec.go, client.go) | clause 6 | none |
| BACnet/IP and BBMD (client.go, bbmd.go, addr.go) | Annex J | none |
| BACnet/IPv6, VMACs (bip6.go) | Annex U; H.7 (virtual MAC addressing) | none |
| Confirmed requests, transaction state machines, segmentation (client.go, segin.go, segout.go) | clause 5.4 | none |
| Services (services.go, clientmgmt.go, readrange.go, eventcodec.go, iamlog.go) | clauses 13, 15, 16 (alarm and event, object access, remote device management); 12.25 (trend log records) | none |
| BACnet Secure Connect (sc.go, scnode.go, schub.go, scdirect.go, sctls.go) | Annex AB (BVLC-SC, hub connector, hub function, direct connections, AB.7.4 TLS profile, AB.7.5.4 key updates); RFC 6455 (WebSocket) | none |
| Test vectors (vectors_test.go) | Annex F and AB.2.17 encoding examples | none |
| Interop peer (interop/peer) | bacnet-stack 1.6.1's build files, its demo programs' usage text and environment variables, read to build and drive them | bacnet-stack source files were read after the library code existed, only to explain behaviour seen in the tests (its BBMD handling of Distribute-Broadcast-To-Network, its segmentation build switch, its certificate path rules) |

## Other BACnet implementations

Open implementations include bacnet-stack (C, GPL-2.0 with a linking
exception), BACpypes and BACpypes3 (Python, MIT), BACnet4J (Java, GPL)
and several partial Go packages (gobacnet and its forks, GPL-2.0). None
of them was read for the library code. The owner decided on 2026-10-06
that no line-by-line comparison with those projects is needed; these
notes are the record.

On 2026-10-11 bacnet-stack 1.6.1 was used as an independent test peer
(interop/), after the library code existed. For the comparison in
README.md the sources of BACpypes3 0.0.110 and gobacnet (commit
63505d3) were looked at for which features they have; nothing was
taken from them.

For v0.2.0 (2026-10-12) the `device` package (the device role) was
written new, our own code from clauses 5.4 (segmentation), 12.11 (the
Device object), 13.1 and 13.14 (COV), 15.5, 15.7, 15.9 and 15.10
(property access), 16.9 and 16.10 (Who-Has, Who-Is) and 19.2
(commandable properties), on this module's codec. bacnet-sim's
simulated device was not moved into it: the simulator stays a test
device with fault switches. BACpypes3 0.0.110 was then run as a second
independent peer (interop/bacpypes3): our scripts call its client and
device classes in a container; nothing of it was copied.

## Test vectors and where they come from

| Test | Source |
|---|---|
| vectors_test.go | the encoding examples of Annex F and AB.2.17 named in each test |
| nohello_test.go | the Connect-Request this module sends, compared with what bacnet-stack 1.6.1's hub accepted in the interop tests |
| interop/ | bacnet-stack 1.6.1's demo server, BBMD and BACnet/SC hub and node |
| every other test and example_test.go | this module's own client, hub and nodes against each other, written from the same standard; not a real device |

All certificates, keys and addresses in the tests are generated or
made-up demo values.
