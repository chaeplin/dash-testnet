#!/usr/bin/python3
# -*- coding: utf-8 -*-

import io, os, sys
import simplejson as json
import datetime
import time
import array
import hashlib
import binascii
from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

#pip3 install git+https://github.com/verigak/progress
from progress.bar import Bar

# --- change 
# rpc
rpcuser     = 'xxx'
rpcpassword = 'xxxxxx'
rpcbindip   = '127.0.0.1'
rpcport     = 19998

BIP32_EXTENDED_KEY_TO = 'tpubDFnBaeiK1ZUB2Qo9TmAvT5HM7QSc7oZGc6cc2sZFP3DP58YAU3fzXP4XPF2q9Ebjtq88QDR76ThUA7DDZK1VPd8h6ZnS78HszBiwMCpMpKp'

start_number = 40010
number_tx_to_send = 120000
time_to_sleep = 0.001

SEND_IS = False

def get_tx(txs, tx_start_number):
    ii = tx_start_number
    while True:
        yield txs[str(ii)]
        ii = ii + 1
        if ii >= len(txs):
            raise ValueError('max tx n reached')

def sendrawtransaction(hex_):
    r = access.sendrawtransaction(hex_)
    return r

def sendrawtransaction_is(hex_):
    r = access.sendrawtransaction(hex_, True, True)
    return r


def getrawtransaction(txid_):
    try:
        r = access.getrawtransaction(txid_)
        return r
    except:
        return None

def now():
    return int(time.time())

def format_hash(hash_):
    return str(binascii.hexlify(hash_[::-1]).decode("utf-8"))

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

###
start = time.time()

serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

txsdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'txs')
txs_to_file = os.path.join(txsdir, BIP32_EXTENDED_KEY_TO)


logsdir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
logs_to_file = os.path.join(logsdir, BIP32_EXTENDED_KEY_TO)


if not os.path.exists(txs_to_file):
    sys.exit("\n\t===> no txs file")

#
try:
    with open(txs_to_file) as data_my_file:
        all_my_txs = json.load(data_my_file)

except:
    sys.exit("\n\t===> invalid my addr file\n")

print('txs length ===>  ', len(all_my_txs))

if start_number >= len(all_my_txs):
    sys.exit('no more txs available')


txs_to_send = get_tx(all_my_txs, start_number)
i = start_number
f = open(logs_to_file, 'a')
bar = Bar('Processing', max=number_tx_to_send)

try:
    while True:
        signedtx = txs_to_send.__next__()
        txid = format_hash(double_sha256(binascii.unhexlify(signedtx)))
        is_in_block = getrawtransaction(txid)
        if not is_in_block:
            if SEND_IS:
                s = sendrawtransaction_is(signedtx)

            else:
                s = sendrawtransaction(signedtx)

            ts = time.strftime('%Y-%m-%d-%H:%M:%S', time.gmtime(now()))
            if SEND_IS:
                f.write(ts + ' ' + str(now()) + ' ' + s + '\n')
                f.flush()

        bar.next()
        i = i + 1
       
        time.sleep(time_to_sleep)
 
        if i >= number_tx_to_send + start_number:
            break

    bar.finish()
    stop = time.time()
    f.close()
    print('\n\t ==> took %f sec' % (stop - start))

except Exception as e:
    print('\n')
    print(e.args)
    f.close()
    sys.exit()

except KeyboardInterrupt:
    f.close()
    sys.exit()


