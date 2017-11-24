#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time
from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

#pip3 install git+https://github.com/verigak/progress
from progress.bar import Bar

from random import shuffle

# --- change 
# rpc
rpcuser     = 'xxx'
rpcpassword = 'xxxxxx'
rpcbindip   = '127.0.0.1'
rpcport     = 19998

# 12.1 10000 --> 0.00010000
# 12.2 1000  --> 0.00001000
# 12.2 IS    --> 0.00010000

# size  : 12 + (148 * number of inputs) + (33 * number of outputs )

feeperkb = 1000 # per KB

toquery = 500

numberofinputs = 1
timestosleep = 0.01

minamount = 1

#fee =  12 + (148 * numberofinputs) + (33 * 3)
fee =  15 + (150 * numberofinputs) + (35 * 3)


BIP32_EXTENDED_KEY_TO = 'tpubDECu9MCfNhRYSRUfJsLb6vYUNhS4gxQnk7qDhiBdPpXP4Cbg7xdAts39avYrXmW42V1GEhy3sv3jdZDF3PWGH5fHFUKLh8q1fT32tfsxDpt'
BIP32_EXTENDED_KEY_MY = 'tpubDFA3CuvdBb5YwZkBQFtanXFj9pcTnYrZb8rQy2SUMnta6BqkmRHMSdWzsneJSC9AogorrLsTNo9KFYUfVgYmNZurUhzjLYxysWAN8GSYza1'

def get_to_addrs(tol):
    ii = 0
    while True:
        yield tol[str(ii)]
        ii = ii + 1
        if ii >= len(tol):
            ii = 0

def get_listunspent():
    try:
        r = access.listunspent()
        return r
    except:
        return None

def get_listunspentaddr(addr):
    try:
        r = access.listunspent(6, 9999999, addr)
        return r
    except:
        return None

def get_addressutxos(addr):
    try:
        params = {
            "addresses": addr
        }
        r = access.getaddressutxos(params)
        return r
    except:
        return None

def sendtoaddress(a):
    try:
        r = access.sendtoaddress(my_addr, a, '', '', True)
        print (r)
    except:
        return None

def createrawtransaction(in_, out_):
    try:
        r = access.createrawtransaction(in_, out_)
        return r
    except:
        return None

def signrawtransaction(hex_):
    try:
        r = access.signrawtransaction(hex_)
        return r
    except:
        return None

def sendrawtransaction(hex_):
    try:
        r = access.sendrawtransaction(hex_)
        return r
    except:
        return None

def sendrawtransaction_is(hex_):
    try:
        r = access.sendrawtransaction(hex_, True, True)
        return r
    except:
        return None

def checksynced():
    try:
        synced = access.mnsync('status')['IsSynced']
        return synced
    except:
        return False

def getblockchaininfo():
    try:
        r = access.getblockchaininfo()
        blocks  = r.get('blocks', None) 
        headers = r.get('headers', None)
        if blocks and headers:
            if blocks == headers:
                return True
        return False
    except:
        return False

def getblockcount():
    try:
        r = access.getblockcount()
        return r
    except:
        return None         

#-------------------
start = time.time()

serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

#
if not checksynced():
    sys.exit('not synced')

if not getblockchaininfo():
    sys.exit('downloading headers')    

cur_blockcount = getblockcount()

#
addrsdir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'addrs')
addrs_my_file = os.path.join(addrsdir, BIP32_EXTENDED_KEY_MY)
addrs_to_file = os.path.join(addrsdir, BIP32_EXTENDED_KEY_TO)

if not os.path.exists(addrs_my_file) or not os.path.exists(addrs_to_file):
    print("\n\t===> no addr file")
    sys.exit()

#
try:
    with open(addrs_my_file) as data_my_file:
        all_my_addrs = json.load(data_my_file)

    with open(addrs_to_file) as data_to_file:
        all_to_addrs = json.load(data_to_file)

except:
    print("\n\t===> invalid my addr file\n")
    sys.exit()


#
my_addridx = []
for m in all_my_addrs:
    my_addridx.append(all_my_addrs[m])

#shuffle(my_addridx)
sublist = [my_addridx[ix:ix + toquery] for ix in range(0, len(my_addridx), toquery)]

bip32_to_addrs = get_to_addrs(all_to_addrs)

signedtx_hex_cnt = 0

try:
    unspent =[]
    print('get getaddressutxos')
    i = 0
    for m in sublist:
        qstart = time.time()
        while True:
            eachunspent = get_addressutxos(m)
            if eachunspent != None:
                unspent = unspent + eachunspent
                break
            else:
                print('----')
                time.sleep(timestosleep)        

        i = i + len(m)
        print('{:6d} {:6d} {:7d} {}'.format(i, len(eachunspent), len(unspent), time.time() - qstart))

        time.sleep(3)

    print('get getaddressutxos', len(unspent), time.time() - start)
    print('making txs')

#[
#  {
#    "address": "yUFs9RTXQDmvrFR1VPfzWiBwcfps5wZvXt",
#    "txid": "709e240e5b0ad2a9c034b7cf3794093f2994df7234e377cd1f650ec286e2dec8",
#    "outputIndex": 0,
#    "script": "76a91457139fdb7c1a3c02a68b31b24d0891706a33eafa88ac",
#    "satoshis": 1304566,
#    "height": 19502
#  }
#]
    unspent_sublist =  [unspent[i:i + numberofinputs] for i in range(0, len(unspent), numberofinputs)]

    bar = Bar('Processing', max=len(unspent_sublist))
    for x in unspent_sublist:
        amount_total = 0
        inputs = []
        for y in x:
            amount    = round(Decimal(float(y['satoshis'] / 1e8)), 8)
            txid      = y.get('txid')
            vout      = y.get('outputIndex')
            height    = y.get('height')

            if cur_blockcount - height >= 1:
                amount_total = amount_total + amount

                input_ = {
                            "txid": txid,
                            "vout": vout
                }

                inputs.append(input_)

        if amount_total > minamount:

            outamount = amount_total - round(Decimal(fee / 1e8), 8) 
            outeach   = round(outamount / 3, 8)
                
            addr1 = bip32_to_addrs.__next__()
            addr2 = bip32_to_addrs.__next__()
            addr3 = bip32_to_addrs.__next__()
    
            outputs = {
                      addr1: outeach,
                      addr2: outeach,
                      addr3: outeach
            }
    
            rawtx = createrawtransaction(inputs, outputs)
            if rawtx != None:
                signedtx = signrawtransaction(rawtx)
                if signedtx != None:
                    if signedtx.get('complete') == True:
                        signedtx_hex = signedtx.get('hex')
                        s = sendrawtransaction(signedtx_hex)
                        signedtx_hex_cnt = signedtx_hex_cnt + 1
                else:
                    time.sleep(timestosleep)

        bar.next()

    bar.finish()
    stop = time.time()

    print('number of txs :', signedtx_hex_cnt)
    print('took %f sec' % (stop - start))

except Exception as e:
    print(e.args)
    sys.exit()

except KeyboardInterrupt:
    sys.exit()

