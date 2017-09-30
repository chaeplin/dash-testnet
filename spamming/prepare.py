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
rpcuser     = 'xxx'
rpcpassword = 'xxx--xxx'
rpcbindip   = '127.0.0.1'
rpcport     = 19998

addr1 = 'yhjookC8oZZNtFC3CT8Er1fxLyp7K2o2j5'
addr2 = 'yUeEdMNHFAAkWwHQLLjh44AkUb8gNkq7as'
addr3 = 'yefBFeLyVi4BiLRiashyg4Si7vFo8E4Zvw'
addr4 = 'yiea7RVP8ZWvABkGV9eecKGU91v15qVVPG'
addr5 = 'yTokd3SW1QjBVNdgaQ3geoNZHt33zSK2o2'
addr6 = 'yQfxebZZUJxxcN6tawL9vz9eTTNAsrkSdA'

splitto = 6
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
        print(time.time())
        unspent = get_listunspent()
        print(time.time())
        for x in unspent:
            spendable = x.get('spendable')
            amount    = x.get('amount') 
            txid      = x.get('txid')
            vout      = x.get('vout')
            outamount = amount - round(Decimal(fee / 1e8), 8)
            outeach   = round(outamount / splitto, 8)

            if spendable and amount > 0.3:
                input_ = {
                            "txid": txid,
                            "vout": vout
                        }

                output_ = {
                            addr1: outeach,
                            addr2: outeach,
                            addr3: outeach,
                            addr4: outeach,
                            addr5: outeach,
                            addr6: outeach
                        }

                rawtx = createrawtransaction(input_, output_)
                signedtx = signrawtransaction(rawtx)

                if signedtx.get('complete') == True:
                    s = sendrawtransaction(signedtx.get('hex'))
                    print(s)

                    #sys.exit()

                time.sleep(0.01)

        time.sleep(2)

except Exception as e:
    print(e.args[0])
    sys.exit()

except KeyboardInterrupt:
    sys.exit()
