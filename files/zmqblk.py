#!/usr/bin/env python
# -*- coding: utf-8 -*-
import io
import os
import sys
import re
import simplejson as json
import datetime
import yaml
from time import time, sleep
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from ISStreamer.Streamer import Streamer

import array
import binascii
import zmq

import logging

def rpcgetblock(x):
    block = access.getblock(x)
    logging.info("---> new block: %s" % block['height'])

    mncount = access.masternode('count', 'all')
    match         = re.search('Total: (.*) \(PS Compatible: (.*) / Enabled: (.*) / Qualify: (.*)\)$', mncount)
    if match:
        mn_total   = match.group(1)
        mn_compat  = match.group(2)
        mn_enabld  = match.group(3)
        mn_qualify = match.group(4)

    streamer = Streamer(bucket_name=iss_bucket, bucket_key=iss_bkey, access_key=iss_akey)
    streamer.log(iss_svname + "_blk", block['height'])
    if int(mn_total) > 0:
        streamer.log(iss_svname + "_mn_total", mn_total)
        streamer.log(iss_svname + "_mn_compat", mn_compat)
        streamer.log(iss_svname + "_mn_enabled", mn_enabld)
        streamer.log(iss_svname + "_mn_qualify", mn_qualify)
    streamer.close()

def checksynced():
    try:
        synced = access.mnsync('status')['IsSynced']
        return synced
    except:
        return False

#-----------------------------
config      = yaml.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'zmqblk.conf'), 'r'))
rpcuser     = config.get('RPCUSER')
rpcpassword = config.get('RPCPASSWD')
rpcbind     = config.get('RPCBIND')
rpcport     = config.get('RPCPORT')
zmqport     = config.get('ZMQPort')
logfile     = config.get('LOGFILE')
iss_bucket  = config.get('ISS_BUCKET')
iss_bkey    = config.get('ISS_BKEY')
iss_akey    = config.get('ISS_AKEY')
iss_svname  = config.get('ISS_SVNAME')
#-------
log_file    = os.path.join(os.path.dirname(os.path.abspath(__file__)), logfile)
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(message)s')

#-----------------------------
serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbind + ':' + rpcport
access = AuthServiceProxy(serverURL)

logging.info("waiting for dashd to finish synchronizing")
while(not checksynced()):
    sleep(30)

logging.info("---> zmqblk started")

# zmq
zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.connect("tcp://%s:%i" % (rpcbind, int(zmqport)))

# main
try:
    while True:
        msg = zmqSubSocket.recv_multipart()
        topic = str(msg[0].decode("utf-8"))
        body  = str(binascii.hexlify(msg[1]).decode("utf-8"))

        if topic == "hashblock":
            rpcgetblock(body)

except KeyboardInterrupt:
    zmqContext.destroy()
    sys.exit()


# end