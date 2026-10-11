# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# bacnet-stack (https://github.com/bacnet-stack/bacnet-stack, Steve Karg and
# contributors, GPL-2.0 with a linking exception) as an interop test peer:
# its demo server, client tools and BACnet/SC hub, built from their own
# sources at a pinned tag. The image is built on the tester's machine and
# not redistributed; nothing of bacnet-stack is linked into this module.
FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
	build-essential ca-certificates curl libwebsockets-dev libssl-dev libcap-dev \
	&& rm -rf /var/lib/apt/lists/*
ARG TAG=bacnet-stack-1.6.1
RUN curl -fsSL https://github.com/bacnet-stack/bacnet-stack/archive/refs/tags/${TAG}.tar.gz | tar -xz -C /opt \
	&& mv /opt/bacnet-stack-${TAG} /opt/bip && cp -a /opt/bip /opt/bsc
# BACnet/IP with the BBMD and foreign-device client. Not SEGMENT=true:
# that switch only changes what the device claims; 1.6.1 has no
# segmentation state machine.
RUN make -s -C /opt/bip/apps BACDL=bip BBMD=full lib server.all readprop.all writeprop.all \
	readpropm.all writepropm.all whois.all readrange.all scov.all readfdt.all readbdt.all
# BACnet/SC: the hub application, a server node and a client node.
RUN make -s -C /opt/bsc/apps BACDL=bsc lib sc-hub server.all readprop.all

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
	libwebsockets17 libssl3 libcap2 iproute2 \
	&& rm -rf /var/lib/apt/lists/*
COPY --from=build /opt/bip/bin/ /opt/bacnet/bip/
COPY --from=build /opt/bsc/bin/ /opt/bacnet/bsc/
WORKDIR /opt/bacnet
