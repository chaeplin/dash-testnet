#!/usr/bin/env python3
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
import struct

import logging

# sequence
hashblock_seq  = "Unknown"
hashtx_seq     = "Unknown"
hashtxlock_seq = "Unknown"
rawblock_seq   = "Unknown"
rawtx_seq      = "Unknown"
rawtxlock_seq  = "Unknown"

def checksynced():
    try:
        synced = access.mnsync('status')['IsSynced']
        return synced
    except:
        return False

def check_seq(topic, sequence):
    global hashblock_seq, hashtx_seq, hashtxlock_seq, rawblock_seq, rawtx_seq, rawtxlock_seq
    
    streamer = Streamer(bucket_name=iss_bucket, bucket_key=iss_bkey, access_key=iss_akey)

    if topic == "hashblock":
        if hashblock_seq != "Unknown":
            if int(sequence) - int(hashblock_seq) > 1:
                streamer.log(iss_svname + "_hashblock_missed", str(int(sequence) - int(hashblock_seq)))
            else:
                streamer.log(iss_svname + "_hashblock", sequence)
        hashblock_seq = sequence                
        logging.info("---> new hashblock: %s" % sequence)

    if topic == "hashtx":
        if hashtx_seq != "Unknown":
            if int(sequence) - int(hashtx_seq) > 1:
                streamer.log(iss_svname + "_hashtx_missed", str(int(sequence) - int(hashtx_seq)))
            else:
                streamer.log(iss_svname + "_hashtx", sequence)
        hashtx_seq = sequence                
        logging.info("---> new hashtx: %s" % sequence)
 
    if topic == "hashtxlock":
        if hashtxlock_seq != "Unknown":
            if int(sequence) - int(hashtxlock_seq) > 1:
                streamer.log(iss_svname + "_hashtxlock_missed", str(int(sequence) - int(hashtxlock_seq)))
            else:
                streamer.log(iss_svname + "_hashtxlock", sequence)
        hashtxlock_seq = sequence                
        logging.info("---> new hashtxlock: %s" % sequence)

    if topic == "rawblock":
        if rawblock_seq != "Unknown":
            if int(sequence) - int(rawblock_seq) > 1:
                streamer.log(iss_svname + "_rawblock_missed", str(int(sequence) - int(rawblock_seq)))
            else:
                streamer.log(iss_svname + "_rawblock", sequence)
        rawblock_seq = sequence                
        logging.info("---> new rawblock: %s" % sequence)

    if topic == "rawtx":
        if rawtx_seq != "Unknown":
            if int(sequence) - int(rawtx_seq) > 1:
                streamer.log(iss_svname + "_rawtx_missed", str(int(sequence) - int(rawtx_seq)))
            else:
                streamer.log(iss_svname + "_rawtx", sequence)
        rawtx_seq = sequence                
        logging.info("---> new rawtx: %s" % sequence)

    if topic == "rawtxlock":
        if rawtxlock_seq != "Unknown":
            if int(sequence) - int(rawtxlock_seq) > 1:
                streamer.log(iss_svname + "_rawtxlock_missed", str(int(sequence) - int(rawtxlock_seq)))
            else:
                streamer.log(iss_svname + "_rawtxlock", sequence)
        rawtxlock_seq = sequence                
        logging.info("---> new rawtxlockk: %s" % sequence)

    streamer.flush()
    streamer.close()
    
#-----------------------------
config      = yaml.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'conf/zmqblk.conf'), 'r'))
rpcuser     = config.get('RPCUSER')
rpcpassword = config.get('RPCPASSWD')
rpcbind     = config.get('RPCBIND')
rpcport     = config.get('RPCPORT')
zmqport     = config.get('ZMQPort')
logfile     = config.get('LOGFILE2')
iss_bucket  = config.get('ISS_BUCKET')
iss_bkey    = config.get('ISS_BKEY')
iss_akey    = config.get('ISS_AKEY')
iss_svname  = config.get('ISS_SVNAME')
#-------
log_file    = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'log/' + logfile)
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s %(message)s')

#-----------------------------
serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbind + ':' + rpcport
access = AuthServiceProxy(serverURL)

logging.info("waiting for dashd to finish synchronizing")
while(not checksynced()):
    sleep(30)

logging.info("---> count started")

# zmq
zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtxlock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtxlock")
zmqSubSocket.connect("tcp://%s:%i" % (rpcbind, int(zmqport)))


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

        if sequence != "Unknown":
            check_seq(topic, sequence)

except KeyboardInterrupt:
    zmqContext.destroy()
    sys.exit()