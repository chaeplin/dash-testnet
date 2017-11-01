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

fee     = 100000
toquery = 100

numberofinputs = 3


BIP32_EXTENDED_KEY_MY = 'tpubDF14hq81zXCcJnCvFfXzCPbxKWatfBcNfBRLWhbXRfymdJ6uUioTPQJdCsRxXUXu6bU6nLgoAhNvbYGKZP1HjXctqLixBdz5ZBMvrPhp2aN'
BIP32_EXTENDED_KEY_TO = 'tpubDEE1eWLKMRzDdUkscT1VQb7pZ1PCS9pKi3f7ZoCNWzZgeoKaxPLXPW7aQ6Zdwg4nranvvmhhjVZRxxMufNHp1APNT3BaXHYMeG358aym1Qk'


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

#-------------------
start = time.time()

serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

addrsdir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'addrs')
addrs_my_file = os.path.join(addrsdir, BIP32_EXTENDED_KEY_MY)
addrs_to_file = os.path.join(addrsdir, BIP32_EXTENDED_KEY_TO)

txsdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'txs')
txs_to_file = os.path.join(txsdir, BIP32_EXTENDED_KEY_TO)

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


my_addridx = []
for m in all_my_addrs:
    my_addridx.append(all_my_addrs[m])

shuffle(my_addridx)
sublist = [my_addridx[ix:ix + toquery] for ix in range(0, len(my_addridx), toquery)]

bip32_to_addrs = get_to_addrs(all_to_addrs)

alltxs = {}
signedtx_hex_cnt = 0

try:
    unspent =[]
    print('get unspentlist')
    i = 0
    #shuffle(my_addridx)
    #sublist = [my_addridx[ix:ix + toquery] for ix in range(0, len(my_addridx), toquery)]
    for m in sublist:
        qstart = time.time()
        while True:
            eachunspent = get_listunspentaddr(m)
            if eachunspent != None:
                unspent = unspent + eachunspent
                break
            else:
                print('----')
                time.sleep(3)        

        i = i + len(m)
        print('{:5d} {:5d} {:5d} {}'.format(i, len(eachunspent), len(unspent), time.time() - qstart))

        time.sleep(3)

    print('get unspentlist', len(unspent), time.time() - start)
    print('making txs')

    unspent_sublist =  [unspent[i:i + numberofinputs] for i in range(0, len(unspent), numberofinputs)]

    bar = Bar('Processing', max=len(unspent_sublist))
    for x in unspent_sublist:
        amount_total = 0
        inputs = []
        for y in x:
            amount    = y.get('amount') 
            txid      = y.get('txid')
            vout      = y.get('vout')

            amount_total = amount_total + amount

            input_ = {
                        "txid": txid,
                        "vout": vout
            }

            inputs.append(input_)

        outamount = amount_total - round(Decimal((fee * len(inputs)) / 1e8), 8) 
        outeach   = round(outamount / 3, 8)
            
        addr1 = bip32_to_addrs.__next__()
        addr2 = bip32_to_addrs.__next__()
        addr3 = bip32_to_addrs.__next__()

        outputs = {
                  addr1: outeach,
                  addr2: outeach,
                  addr3: outeach
        }

        while True:
            rawtx = createrawtransaction(inputs, outputs)
            if rawtx != None:
                break
            else:
                time.sleep(3)

        while True:
            signedtx = signrawtransaction(rawtx)
            if signedtx != None:
                if signedtx.get('complete') == True:
                    signedtx_hex = signedtx.get('hex')
                    alltxs[signedtx_hex_cnt] = signedtx_hex
                    signedtx_hex_cnt = signedtx_hex_cnt + 1
                    bar.next()
            else:
                time.sleep(3)

    bar.finish()
    stop = time.time()

    with open(txs_to_file, 'w') as outfile:
        json.dump(alltxs, outfile)

    print('number of txs :', signedtx_hex_cnt)
    print('took %f sec' % (stop - start))

except Exception as e:
    print(e.args)
    sys.exit()

except KeyboardInterrupt:
    sys.exit()

