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

def rpcgobjects():
    try:
        getgovernanceinfo = access.getgovernanceinfo()

        if getgovernanceinfo:
            nextsuperblock = getgovernanceinfo['nextsuperblock']

    except:
        pass


    try:
        mnsync = access.mnsync('status')

        if mnsync:
            m = {}
            m['AssetID']                = mnsync['AssetID']
            m['Attempt']                = mnsync['Attempt']
            m['IsBlockchainSynced']     = int(mnsync['IsBlockchainSynced'])
            m['IsMasternodeListSynced'] = int(mnsync['IsMasternodeListSynced'])
            m['IsWinnersListSynced']    = int(mnsync['IsWinnersListSynced'])
            m['IsSynced']               = int(mnsync['IsSynced'])
            m['IsFailed']               = int(mnsync['IsFailed'])
            streamer.log_object(m, key_prefix=iss_prefix + '_m')

    except:
        pass


    try:
        g = {}
        g['hash']                  = -1
        g['hashint']               = -1
        g['AbsoluteYesCount']      = -1
        g['YesCount']              = -1
        g['NoCount']               = -1
        g['AbstainCount']          = -1
        g['fBlockchainValidity']   = -1
        g['fCachedValid']          = -1
        g['fCachedFunding']        = -1
        g['fCachedDelete']         = -1
        g['fCachedEndorsed']       = -1
        g['eventheight']           = -1

        gobjects = access.gobject('list')
        keys = gobjects.keys()
        if len(keys) > 0:
            for x in keys:
                gobjectDataString     = json.loads(gobjects[x]['DataString'])
                gobjecttype           = gobjectDataString[0][0]
                g['hash']                  = x[:10]
                g['hashint']               = int(g['hash'], 16)
                g['AbsoluteYesCount']      = gobjects[x]['AbsoluteYesCount']
                g['YesCount']              = gobjects[x]['YesCount']
                g['NoCount']               = gobjects[x]['NoCount']
                g['AbstainCount']          = gobjects[x]['AbstainCount']
                g['fBlockchainValidity']   = int(gobjects[x]['fBlockchainValidity'])
                g['fCachedValid']          = int(gobjects[x]['fCachedValid'])
                g['fCachedFunding']        = int(gobjects[x]['fCachedFunding'])
                g['fCachedDelete']         = int(gobjects[x]['fCachedDelete'])
                g['fCachedEndorsed']       = int(gobjects[x]['fCachedEndorsed'])

                if gobjecttype == 'trigger':
                    g['eventheight'] = gobjectDataString[0][1]['event_block_height']
                    if g['eventheight'] == nextsuperblock and g['fCachedFunding'] == int(True):
                        streamer.log_object(g, key_prefix=iss_prefix + '_g') 

                    elif g['eventheight'] == nextsuperblock and g['fCachedFunding'] == int(False):
                        streamer.log_object(g, key_prefix=iss_prefix + '_x')

                    streamer.flush()

    except:
        streamer.log_object(g, key_prefix=iss_prefix + '_g')
        streamer.flush()
        pass


# rpc 
serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

while(not checksynced()):
    time.sleep(30)

streamer = Streamer(bucket_name=iss_bucket_name, bucket_key=iss_bucket_key, access_key=iss_access_key, buffer_size=100)

try:
    while True:
        rpcgobjects()
        time.sleep(30)

except Exception as e:
    print(e.args[0])
    sys.exit()

except KeyboardInterrupt:
    sys.exit()


