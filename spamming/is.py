#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time
import redis
from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# --- change 
# rpc
rpcuser     = 'xx'    # change
rpcpassword = 'xx--xx=' # change
rpcbindip   = '127.0.0.1'
rpcport     = 19998

sv   = 's2'
addr = 'ydTFx35B7YRuPaqnkDVvh9X4YCtdJZVXFD'
fee  = 10000
rate = 5

r_hash_ix    = 'r_hash_ix'
#r_hash_block = 'r_hash_block'

def get_listunspent():
    rpc = access.listunspent()
    return rpc

def sendtoaddress(a):
    rpc = access.sendtoaddress(my_addr, a, '', '', True)
    return rpc

def instantsendtoaddress(a, b):
    rpc = access.instantsendtoaddress(a, b, '', '', True)
    return rpc

def createrawtransaction(in_, out_):
    rpc = access.createrawtransaction([in_], out_)
    return rpc

def signrawtransaction(hex_):
    rpc = access.signrawtransaction(hex_)
    return rpc

def sendrawtransaction(hex_):
    rpc = access.sendrawtransaction(hex_)
    return rpc

def getinfo():
    rpc = access.getinfo()
    return rpc

def mempoolinfo():
    rpc = access.getmempoolinfo()
    return rpc


serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

# redis
#POOL = redis.ConnectionPool(host='192.168.10.10', port=6379, db=0)
#r = redis.StrictRedis(connection_pool=POOL)

try:
    while True:
        unspent = get_listunspent()
        for x in unspent:
            spendable = x.get('spendable')
            amount    = x.get('amount') 

            if spendable and amount < 5 and amount >=  0.3:
                s = instantsendtoaddress(addr, amount)
                data = s
#                i = getinfo()
#                m = mempoolinfo()
#
#                #
#                data = {
#                    "sv":           sv,
#                    "tstamp":       time.time(),
#                    "israte":       rate,
#                    "blocks":       i.get('blocks'),
#                    "connections":  i.get('connections'),
#                    "difficulty":   str(i.get('difficulty')),
#                    "mempoolsize":  m.get('size')
#                }
#
#                r.hset(r_hash_ix + sv, s, data)

                print(data)

            time.sleep(1/rate)

        time.sleep(10)

except Exception as e:
    print(e.args[0])
    sys.exit()

except KeyboardInterrupt:
    sys.exit()

