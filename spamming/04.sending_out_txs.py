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
rpcpassword = 'xxx--xxx='
rpcbindip   = '127.0.0.1'
rpcport     = 19998

BIP32_EXTENDED_KEY_TO = 'tpubDECjUCx7mQeP2wYMPdJftw85UdArsbSdauk7dcsHkj2Gunofqhk4bYoQMhSnFFeJUPMYZ9YqUKrzmDaHaMubQXfWtJDNg6v12p5UGtpQ2kW'

time_to_sleep  = 0.001
#time_to_sleep = 0.001
is_time_to_sleep = 5
#SEND_IS = True
SEND_IS = False
DEFAULT_TXS_TO_SEND = 10

#---------
def get_tx(txs):
    first_unused = False
    checking_gap = 100
    i = 0
    while True:
        rawtx = txs[str(i)]
        txid = format_hash(double_sha256(binascii.unhexlify(rawtx)))

        if first_unused:
            is_in_block = None
        else:
            is_in_block = getrawtransaction(txid)

        if not is_in_block:
            if first_unused:
                yield i, txs[str(i)]

            else:
                first_unused = True

                if i == 0:
                    yield i, txs[str(i)]

                else:
                    i = i - checking_gap             

        if first_unused:
            i = i + 1

        else:       
            i = i + checking_gap

        if i >= total_no_of_txs:
            raise ValueError('max tx n reached')

def sendrawtransaction(hex_):
    try:
        r = access.sendrawtransaction(hex_)
        return r
    except:
        pass

def sendrawtransaction_is(hex_):
    try:
        r = access.sendrawtransaction(hex_, True, True)
        return r
    except:
        pass

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

#----------------------------------------------
try:
    if len(sys.argv) == 1:
        number_tx_to_send = DEFAULT_TXS_TO_SEND
    else:
        number_tx_to_send = int(sys.argv[1])

except Exception as e:
    print(e.args)
    sys.exit()

#

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

print('took %f sec' % (time.time() - start))
print('txs length ===>', len(all_my_txs))
print('will send  ===>', number_tx_to_send)

txs_to_send = get_tx(all_my_txs)
total_no_of_txs = len(all_my_txs)
bar = Bar('Processing', max=number_tx_to_send)

try:
    i = 0
    while True:
        signedtx_seq, signedtx = txs_to_send.__next__()
        if SEND_IS:
            s = sendrawtransaction_is(signedtx)

        else:
            s = sendrawtransaction(signedtx)

        i = i + 1
        if i >= number_tx_to_send:
            break
      
        if i % 10 == 0:
            if SEND_IS:
                time.sleep(is_time_to_sleep)
            else:
                time.sleep(time_to_sleep)
        else: 
            time.sleep(time_to_sleep)

        bar.next()


    bar.finish()
    stop = time.time()
    print('\n\t ==> %d txs remained' % (total_no_of_txs - signedtx_seq))
    print('\t ==> took %f sec' % (stop - start))

except Exception as e:
    print('\n')
    print(e.args)
    sys.exit()

except KeyboardInterrupt:
    sys.exit()

