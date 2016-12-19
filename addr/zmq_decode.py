#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import array
import binascii
import zmq
import struct
import hashlib
import simplejson as json

from lib.utils import *
from lib.tx import *
from lib.block import *

#---------
port = 28332
zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtxlock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtxlock")
zmqSubSocket.connect("tcp://127.0.0.1:%i" % port)
try:
    while True:
        msg   = zmqSubSocket.recv_multipart()
        topic = str(msg[0].decode("utf-8"))
        body  = str(binascii.hexlify(msg[1]).decode("utf-8"))
        sequence = "Unknown";

        if len(msg[-1]) == 4:
          msgSequence = struct.unpack('<I', msg[-1])[-1]
          sequence = str(msgSequence)

        if topic == 'rawtx':
            x = decoderawtx(body)
            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))

        if topic == 'rawblock':
            x = decoderawblock(body)
            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))

        if topic == 'rawtxlock':
            x = decoderawtx(body)
            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))

except KeyboardInterrupt:
    zmqContext.destroy()
