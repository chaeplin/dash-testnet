#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import urllib.request as urlopen
import zmq
import array
import binascii
import struct
from ISStreamer.Streamer import Streamer

USERAGET = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_1) AppleWebKit/602.2.14 (KHTML, like Gecko) Version/10.0.1 Safari/602.2.14'

#
rpcbindip   = '127.0.0.1'

# zmq
zmqport     = 28332

# initialstate
iss_bucket_name   = 'bucket-name' # change
iss_bucket_key    = 'bucket-key' # change
iss_access_key    = 'access-key' # change
iss_prefix        = 'prefix'  # change to hostname or uniq name

def get_getblockcount():
    url = 'https://test.explorer.dash.org/chain/tDash/q/getblockcount'
    request  = urlopen.Request(url)
    request.add_header('User-agent', USERAGET)

    try:
        response = urlopen.urlopen(request, timeout=2)
        r = response.read().decode('utf-8')
        if int(r) > 0:
            return r
        else:
            return None

    except Exception as e:
#        print(e.args[0])
        return None

def get_getdifficulty():

    url = 'https://test.explorer.dash.org/chain/tDash/q/getdifficulty'
    request  = urlopen.Request(url)
    request.add_header('User-agent', USERAGET)

    try:
        response = urlopen.urlopen(request, timeout=2)
        r = response.read().decode('utf-8')
        if float(r) > 0:
            return r
        else:
            return None

    except Exception as e:
#        print(e.args[0])
        return None


def get_explorer():
    blockcount = get_getblockcount()
    difficulty = get_getdifficulty()
    if blockcount and difficulty:
        bucket = {}
        bucket['blocks'] = blockcount
        bucket['diff']   = difficulty
        streamer.log_object(bucket, key_prefix=iss_prefix)
        streamer.flush()


# zmq
zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.connect("tcp://%s:%i" % (rpcbindip, zmqport))

# iss
streamer = Streamer(bucket_name=iss_bucket_name, bucket_key=iss_bucket_key, access_key=iss_access_key, buffer_size=100)


#get_explorer()
#sys.exit()

# main
try:
    while True:
        msg = zmqSubSocket.recv_multipart()
        topic = str(msg[0].decode("utf-8"))
        body  = str(binascii.hexlify(msg[1]).decode("utf-8"))
        sequence = "Unknown"

        if len(msg[-1]) == 4:
          msgSequence = struct.unpack('<I', msg[-1])[-1]
          sequence = str(msgSequence)

        if topic == "hashblock":
            get_explorer()

except Exception as e:
    print(e.args[0])
    streamer.close()
    zmqContext.destroy()
    sys.exit()

except KeyboardInterrupt:
    streamer.close()
    #zmqContext.destroy()
    sys.exit()

