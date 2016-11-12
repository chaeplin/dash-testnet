#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time
import zmq
import array
import binascii
import struct
import psutil
import re
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from ISStreamer.Streamer import Streamer

# --- change 
# rpc
rpcuser     = 'rpc_user'    # change
rpcpassword = 'rpc_paasword' # change

rpcbindip   = '127.0.0.1'
rpcport     = 19998

# zmq
zmqport     = 28332

# initialstate
iss_bucket_name   = 'bucket-name' # change
iss_bucket_key    = 'bucket-key' # change
iss_access_key    = 'access-key' # change
iss_prefix        = 'prefix'  # change to hostname or uniq name

# --- / change

def checksynced():
    try:
        synced = access.mnsync('status')['IsSynced']
        return synced
    except:
        return False

def rpcgetinfo():
    try:
        now = time.time()
        getinfo = access.gobject('list')

        if len(getinfo) > 0:
            gsec = time.time() - now
            bucket = {}
            bucket['gsec'] = gsec
            bucket['len'] = len(getinfo)
            streamer.log_object(bucket, key_prefix=iss_prefix + '_gobject')
            streamer.flush()

    except:
        pass

# rpc 
serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

while(not checksynced()):
    time.sleep(30)

# zmq
zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.connect("tcp://%s:%i" % (rpcbindip, zmqport))

# iss
streamer = Streamer(bucket_name=iss_bucket_name, bucket_key=iss_bucket_key, access_key=iss_access_key, buffer_size=100)


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
            rpcgetinfo()

except Exception as e:
    print(e.args[0])
    streamer.close()
    zmqContext.destroy()
    sys.exit()

except KeyboardInterrupt:
    streamer.close()
    #zmqContext.destroy()
    sys.exit()
