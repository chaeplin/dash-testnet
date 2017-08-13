#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time

# pip3 install git+https://github.com/chaeplin/bip32utils
from bip32utils import BIP32Key

#pip3 install git+https://github.com/verigak/progress
from progress.bar import Bar

# http://chaeplin.github.io/bip39/
# tpub of m/44'/1'/0'/0

def bip32_getaddress(xpub, index_no):
    assert isinstance(index_no, int)
    acc_node = BIP32Key.fromExtendedKey(xpub)
    addr_node = acc_node.ChildKey(index_no)
    address = addr_node.Address()
    return address

def get_bip32_addrs(xpub):
    i = 0
    while True:
        child_address = bip32_getaddress(xpub, i)    
        yield i, child_address
        i = i + 1


max_child_index = 10000

BIP32_EXTENDED_KEY = input("Please enter BIP32 Extended Public Key: ")

if not BIP32_EXTENDED_KEY.startswith('tpub'):
    sys.exit("\n\t===> not bip32 ext pub key for testnet\n")

try:
    bip32_getaddress(BIP32_EXTENDED_KEY, 1)

except:
    print("\n\t===> invalid bip32 ext pub key for testnet\n")
    sys.exit()

start = time.time()

addrsdir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'addrs')
addrsfile = os.path.join(addrsdir, BIP32_EXTENDED_KEY)

if not os.path.exists(addrsdir):
    os.mkdir(addrsdir)

bip32addrs = {}

try:
    bip32_tpub = get_bip32_addrs(BIP32_EXTENDED_KEY)
    bar = Bar('Processing', max=max_child_index)
    for i in range(max_child_index):
        bip32_index, bip32_address = bip32_tpub.__next__()
        bip32addrs[bip32_index] = bip32_address

        bar.next()

    bar.finish()

    with open(addrsfile, 'w') as outfile:
        json.dump(bip32addrs, outfile)

    stop = time.time()

    print('took %f sec' % (stop - start))

except KeyboardInterrupt:
    sys.exit()
