#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

# pip3 install git+https://github.com/chaeplin/bip32utils
from bip32utils import BIP32Key

#pip3 install git+https://github.com/verigak/progress
from progress.bar import Bar

#addressindex=1
#spentindex=1
#timestampindex=1
#txindex=1

def bip32_getaddress(xpub, index_no):
    assert isinstance(index_no, int)
    acc_node = BIP32Key.fromExtendedKey(xpub)
    addr_node = acc_node.ChildKey(index_no)
    address = addr_node.Address()
    return address


def validateaddress(address):
    try:
        r = access.validateaddress(address)
        scriptPubKey = r.get('scriptPubKey')[0:30]        
        return scriptPubKey

    except Exception as e:
        print('rpc error : ', e)
        sys.exit()

def getaddressdeltas(address):
    try:
        params = {
            "addresses": address
        }
        r = access.getaddressdeltas(params)
        return r

    except Exception as e:
        print('rpc error : ', e)
        sys.exit()

#
BIP32_EXTENDED_KEY = input("Please enter BIP32 Extended Public Key: ")

if not BIP32_EXTENDED_KEY.startswith('tpub'):
    sys.exit("\n\t===> not bip32 ext pub key for testnet\n")

try:
    bip32_getaddress(BIP32_EXTENDED_KEY, 1)

except:
    print("\n\t===> invalid bip32 ext pub key for testnet\n")
    sys.exit()

start = time.time()
max_unused_key  = 30

addrsdir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'addrs')
addrsfile = os.path.join(addrsdir, BIP32_EXTENDED_KEY)

if not os.path.exists(addrsfile):
    print("\n\t===> no addr file")
    sys.exit()

#
rpcuser         = 'xxxx'
rpcpassword     = 'xxxx'
rpcbindip       = '127.0.0.1'
rpcport         = 19998

#
serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

#
try:
    with open(addrsfile) as data_file:
        alladdrs = json.load(data_file)

except:
    print("\n\t===> invalid addr file\n")
    sys.exit()

#
addridx = []
for m in alladdrs:
    addridx.append(alladdrs[m])

sublist = [addridx[i:i + 20] for i in range(0, len(addridx), 20)]


txcnt = {}
for i in range(len(alladdrs)):
    txcnt[alladdrs[str(i)]] = 0

for m in sublist:
    x = getaddressdeltas(m)
    for y in x:
        txaddr = y.get('address')
        txcnt[txaddr] = txcnt[txaddr] + 1

z = 0
m = 0
for i in range(len(alladdrs)):
    testaddr = alladdrs[str(i)]
    if txcnt[testaddr] == 0:
        m = m + 1
        z = z + 1
        print('%d\t\t%d\t%s\t%s' % (i, m, testaddr, validateaddress(testaddr)))

        if z > max_unused_key:
           stop = time.time()
           print('\ntook %f sec' % (stop - start))
           sys.exit()        

#
    else:
        if m > 0:
            m = 0
            print('-----------')
            print('%d\t\t%d\t%s\t%s' % (i, m, testaddr, validateaddress(testaddr)))
        else:
            m = 0
