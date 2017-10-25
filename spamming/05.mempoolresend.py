#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io, os, sys
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# --- change 
# rpc
rpcuser     = 'xxx'
rpcpassword = 'xxxxxx'
rpcbindip   = '127.0.0.1'
rpcport     = 19998

def getrawmempool():
    r = access.getrawmempool()
    return r

def getrawtransaction(txid_):
    r = access.getrawtransaction(txid_)
    return r

def sendrawtransaction(hex_):
    r = access.sendrawtransaction(hex_)
    return r

def sendrawtransaction_is(hex_):
    r = access.sendrawtransaction(hex_, True, True)
    return r

def now():
    return int(time.time())

serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

m = getrawmempool()
try:
    for i in m:
        hex_ = getrawtransaction(i)
        try:
            s = sendrawtransaction(hex_)
            print(s)

        except:
            pass


except Exception as e:
    print(e.args)
    sys.exit()

except KeyboardInterrupt:
    sys.exit()


