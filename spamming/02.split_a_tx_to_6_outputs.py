#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time
from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

#pip3 install git+https://github.com/verigak/progress
#from progress.bar import Bar

# --- change 
# rpc
rpcuser     = 'xxx'
rpcpassword = 'xxxxxx'
rpcbindip   = '127.0.0.1'
rpcport     = 19998

fee = 10000

minamount = 1
toquery = 500
querysleep = 1

BIP32_EXTENDED_KEY_MY = 'tpubDDvnLXV1e1LX2fdBnC9GhYzR2CbzjD8DgfBo7izY4K9EA8jQAub5fjEsNPiDGeMxPMTu6Z1QY39Br4K1KrRB7eCTSp1qdYgU3LV8pEMmLcF'
BIP32_EXTENDED_KEY_TO = 'tpubDFWu1Np5EN31CfJzgCxxuQiBmfPDfzcMUyHpEozYzh4RUKjiv8sEN7uB5PgdEFocX41FkHe9idoJ8f6uhtWqFKkxop2FCN2ywPycuAASdFv'

def get_to_addrs(tol):
    ii = 0
    while True:
        yield tol[str(ii)]
        ii = ii + 1
        if ii >= len(tol):
            ii = 0

def get_listunspent():
    r = access.listunspent()
    return r

def get_listunspentaddr(addr):
    r = access.listunspent(1, 9999999, addr)
    return r

def sendtoaddress(a):
    r = access.sendtoaddress(my_addr, a, '', '', True)
    print (r)

def createrawtransaction(in_, out_):
    r = access.createrawtransaction([in_], out_)
    return r

def signrawtransaction(hex_):
    r = access.signrawtransaction(hex_)
    return r

def sendrawtransaction(hex_):
    r = access.sendrawtransaction(hex_)
    return r

serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

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


my_addridx = []
for m in all_my_addrs:
    my_addridx.append(all_my_addrs[m])

sublist = [my_addridx[i:i + toquery] for i in range(0, len(my_addridx), toquery)]

bip32_to_addrs = get_to_addrs(all_to_addrs)

try:
    while True:
        aaa = time.time()
        unspent =[]
        print('get unspentlist')
        i = 0
        #sublist = [my_addridx[ix:ix + toquery] for ix in range(0, len(my_addridx), toquery)]
        for m in sublist:
            qstart = time.time()
            eachunspent = get_listunspentaddr(m)
            unspent = unspent + eachunspent
            
            i = i + len(m)
            print('{:5d} {:5d} {:5d} {}'.format(i, len(eachunspent), len(unspent), time.time() - qstart))

            time.sleep(querysleep)

        print('unspentlist', len(unspent), time.time() - aaa)
        
        print('sending txs')
        
        for x in unspent:
            spendable = x.get('spendable')
            amount    = x.get('amount') 
            txid      = x.get('txid')
            vout      = x.get('vout')
            outamount = amount - round(Decimal(fee / 1e8), 8)

            if spendable:

                input_ = {
                            "txid": txid,
                            "vout": vout
                }

                if amount > minamount:
                    outeach   = round(outamount / 6, 8)
                
                    addr1 = bip32_to_addrs.__next__()
                    addr2 = bip32_to_addrs.__next__()
                    addr3 = bip32_to_addrs.__next__()
                    addr4 = bip32_to_addrs.__next__()
                    addr5 = bip32_to_addrs.__next__()
                    addr6 = bip32_to_addrs.__next__()

                    output_ = {
                            addr1: outeach,
                            addr2: outeach,
                            addr3: outeach,
                            addr4: outeach,
                            addr5: outeach,
                            addr6: outeach
                    }

                else:
                    addr1 = bip32_to_addrs.__next__()
                    output_ = {
                            addr1: outamount
                    }

                rawtx = createrawtransaction(input_, output_)
                signedtx = signrawtransaction(rawtx)

                if signedtx.get('complete') == True:
                    s = sendrawtransaction(signedtx.get('hex'))
                    print(s)

                time.sleep(0.01)

        print('sleep 5 sec')
        time.sleep(5)

except Exception as e:
    print(e.args)
    sys.exit()

except KeyboardInterrupt:
    sys.exit()


