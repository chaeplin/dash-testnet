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


max_child_index = 15000

try:
    if len(sys.argv) == 1:
        BIP32_EXTENDED_KEY = input("Please enter BIP32 Extended Public Key: ")
    else:
        BIP32_EXTENDED_KEY = sys.argv[1]

except:
    sys.exit()

if not BIP32_EXTENDED_KEY.startswith('tpub'):
    sys.exit("\n\t===> not bip32 ext pub key for testnet\n")

try:
    first_addr = bip32_getaddress(BIP32_EXTENDED_KEY, 0)

except:
    print("\n\t===> invalid bip32 ext pub key for testnet\n")
    sys.exit()

start = time.time()

addrsdir  = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'addrs')
addrsfile = os.path.join(addrsdir, BIP32_EXTENDED_KEY)

if not os.path.exists(addrsdir):
    os.mkdir(addrsdir)

FILE_EXIST = False
FILE_LEN   = 0
alladdrs   = {}

if os.path.exists(addrsfile):
    try:
        with open(addrsfile) as data_file:
            alladdrs = json.load(data_file)

    except:
        print("\n\t===> invalid addr file\n")
        sys.exit()

    first_addr_in_file = alladdrs.get('0', None)

    if first_addr_in_file == first_addr:
        FILE_EXIST = True 
        FILE_LEN   = len(alladdrs)

if max_child_index < FILE_LEN:
    print("\n\t===> max_child_index : %d less than current index %d\n" % (max_child_index, FILE_LEN))
    sys.exit() 

try:
    bar = Bar('Processing', max=max_child_index)
    for i in range(max_child_index):
        addr_exist = alladdrs.get(str(i), None)
        if addr_exist == None:
            new_addr = bip32_getaddress(BIP32_EXTENDED_KEY, i)
            alladdrs[i] = new_addr 

        bar.next()

    bar.finish()

    with open(addrsfile, 'w') as outfile:
        json.dump(alladdrs, outfile)

    stop = time.time()

    print('took %f sec' % (stop - start))

except KeyboardInterrupt:
    sys.exit()

