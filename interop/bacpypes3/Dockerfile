# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# BACpypes3 (https://github.com/JoelBender/BACpypes3, Joel Bender, MIT) as
# an interop test peer: our own scripts drive its client and its device
# side. Installed from PyPI at a pinned version at test time; nothing of it
# is copied into this repository.
FROM python:3.12.10-slim
RUN pip install --no-cache-dir bacpypes3==0.0.110
WORKDIR /peer
COPY client.py device.py ./
