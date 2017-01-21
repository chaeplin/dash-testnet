#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time
from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# --- change 
# rpc
rpcuser     = 'x'    # change
rpcpassword = 'x--x=' # change
rpcbindip   = '127.0.0.1'
rpcport     = 19998

addr1 = 'yW9HT4Qq8dsc2Z1gJNcDrLdZJgjdFnxm9R'
addr2 = 'yNAa3P6TU6HdCf3afBgWPJgcr5ALkAR6FE'
addr3 = 'yd9QugGWmNE4Yn5mqaPPEepQnzkKtuJ64i'

splitto = 3
fee     = 10000

def get_listunspent():
    r = access.listunspent()
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

try:
    while True:
        unspent = get_listunspent()
        for x in unspent:
            spendable = x.get('spendable')
            amount    = x.get('amount') 
            txid      = x.get('txid')
            vout      = x.get('vout')
            outamount = amount - round(Decimal(fee / 1e8), 8)
            outeach   = round(outamount / 3, 8)

            if spendable and amount > 1:
                input_ = {
                            "txid": txid,
                            "vout": vout
                        }

                output_ = {
                            addr1: outeach,
                            addr2: outeach,
                            addr3: outeach
                        }

                rawtx = createrawtransaction(input_, output_)
                signedtx = signrawtransaction(rawtx)

                if signedtx.get('complete') == True:
                    s = sendrawtransaction(signedtx.get('hex'))
                    print(s)

                    #sys.exit()

                time.sleep(0.3)

        time.sleep(10)

except Exception as e:
    print(e.args[0])
    sys.exit()

except KeyboardInterrupt:
    sys.exit()

