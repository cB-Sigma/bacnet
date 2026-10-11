# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# BACpypes3's client against a device on the host: reads the device's
# object-list (long enough to need a segmented answer), reads several
# properties in one ReadPropertyMultiple, writes a commandable value at a
# priority and reads it back, subscribes to COV and waits for two
# notifications. One JSON line per result, prefixed "PEER ".
import asyncio
import json
import socket
import sys

from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.app import Application
from bacpypes3.pdu import Address
from bacpypes3.primitivedata import ObjectIdentifier, Real


def say(**kw):
    print("PEER " + json.dumps(kw, default=str), flush=True)


async def main():
    parser = SimpleArgumentParser()
    parser.add_argument("target")
    parser.add_argument("device")
    args = parser.parse_args()
    host, port = args.target.rsplit(":", 1)
    addr = Address(f"{socket.gethostbyname(host)}:{port}")
    dev = ObjectIdentifier(f"device,{args.device}")
    app = Application.from_args(args)
    try:
        objs = await app.read_property(addr, dev, "object-list")
        say(event="object-list", n=len(objs), first=str(objs[0]), last=str(objs[-1]))
        name = await app.read_property(addr, dev, "object-name")
        say(event="object-name", value=str(name))
        res = await app.read_property_multiple(
            addr, ["analog-input,1", ["object-name", "present-value", "units"], "analog-value,2", ["present-value"]]
        )
        say(event="rpm", values=[[str(o), str(p), str(v)] for o, p, i, v in res])
        await app.write_property(addr, "analog-value,2", "present-value", Real(23.5), priority=8)
        pv = await app.read_property(addr, "analog-value,2", "present-value")
        say(event="write", value=float(pv))
        pa = await app.read_property(addr, "analog-value,2", "priority-array")
        say(event="priority-array", n=len(pa))
        async with app.change_of_value(addr, ObjectIdentifier("analog-input,1"), 17, False, 120) as scm:
            say(event="subscribed")
            got = 0
            while got < 2:
                prop, value = await asyncio.wait_for(scm.get_value(), 15)
                if str(prop) == "present-value":
                    got += 1
                    say(event="cov", value=float(value))
    except Exception as e:
        say(event="error", error=repr(e))
    finally:
        say(event="done")
        app.close()


asyncio.run(main())
