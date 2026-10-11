# Copyright 2026 Abhinav Gautam
# SPDX-License-Identifier: Apache-2.0
#
# A BACpypes3 device with enough analog values that its object-list and a
# ReadPropertyMultiple of every object-name need segmented answers. It
# serves until stopped and prints "PEER ready" when it listens.
import asyncio
import sys

from bacpypes3.argparse import SimpleArgumentParser
from bacpypes3.app import Application
from bacpypes3.local.analog import AnalogValueObject


async def main():
    parser = SimpleArgumentParser()
    parser.add_argument("count", type=int)
    args = parser.parse_args()
    app = Application.from_args(args)
    for i in range(args.count):
        app.add_object(
            AnalogValueObject(
                objectIdentifier=("analog-value", 100 + i),
                objectName=f"Peer point {i} with a rather long name",
                presentValue=float(i),
                statusFlags=[0, 0, 0, 0],
                covIncrement=1.0,
                units="degreesCelsius",
            )
        )
    print("PEER ready", flush=True)
    await asyncio.Future()


asyncio.run(main())
