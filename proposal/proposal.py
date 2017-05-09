#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys, os
import simplejson
import binascii
import time

from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

#
def now():
    return int(time.time())

def checksynced():
    try:
        r = access.mnsync('status')
        return (r['IsSynced'])

    except JSONRPCException as e:
        print(e.args)
        sys.exit()

    except Exception as e:
        print(e.args)
        sys.exit()

def get_governance():
    try:
        r = access.getgovernanceinfo()
        ginfo = {
            "proposalfee": r.get('proposalfee'),
            "superblockcycle": r.get('superblockcycle'),
            "nextsuperblock": r.get('nextsuperblock')
        }
        return ginfo

    except JSONRPCException as e:
        print(e.args)
        sys.exit()

    except Exception as e:
        print(e.args)
        sys.exit()

def get_getblockcount():
    try:
        r = access.getblockcount()
        return r

    except JSONRPCException as e:
        print(e.args)
        sys.exit()

    except Exception as e:
        print(e.args)
        sys.exit()

def get_prepare(preparetime, proposalhex):
    try:
        r = access.gobject('prepare', str(0), str(1), str(preparetime), proposalhex)
        return r

    except JSONRPCException as e:
        print(e.args)
        sys.exit()

    except Exception as e:
        print(e.args)
        sys.exit()

def get_submit(preparetime, proposalhex, feetxid):
    try:
        r = access.gobject('submit', str(0), str(1), str(preparetime), proposalhex, feetxid)
        return r

    except JSONRPCException as e:
        print(e.args)
        sys.exit()

    except Exception as e:
        print(e.args)
        sys.exit()

def get_vote(proposalhash):
    try:
        r = access.gobject('vote-many', proposalhash, 'funding', 'yes')    
        return r

    except JSONRPCException as e:
        print(e.args)
        sys.exit()

    except Exception as e:
        print(e.args)
        sys.exit()


def get_rawtxid(txid):
    try:
        r = access.getrawtransaction(txid, 1)
        confirmations = r.get('confirmations')
        if confirmations:
            print('confirmations : ', confirmations)
            return confirmations
        else:
            print('confirmations : 0')
            return 0


    except JSONRPCException as e:
        print(e.args)
        sys.exit()

    except Exception as e:
        print(e.args)
        sys.exit()


# https://github.com/dashpay/sentinel/blob/master/lib/dashlib.py#L226-L236
def deserialise(hexdata):
    json = binascii.unhexlify(hexdata)
    obj = simplejson.loads(json, use_decimal=True)
    return obj

def serialise(dikt):
    json = simplejson.dumps(dikt, sort_keys=True, use_decimal=True)
    hexdata = binascii.hexlify(json.encode('utf-8')).decode('utf-8')
    return hexdata

#--------------------------------------------
# --- change 
# rpc // testnet
rpcuser     = 'xxx'
rpcpassword = 'xxxxx'
payout_address = 'xxxxx'
payout_amount = 1.2
payout_month = 10

###
rpcbindip   = '127.0.0.1'
rpcport     = 19998

serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)


while(not checksynced()):
    print('not yet synced, sleep 30 sec')
    time.sleep(30)

govinfo  = get_governance()
curblock = get_getblockcount() 
curunixtime = now()

proposalfee = govinfo.get('proposalfee')
superblockcycle = govinfo.get('superblockcycle')
nextsuperblock = govinfo.get('nextsuperblock')

#
if nextsuperblock - curblock > 10:
    start_epoch = curunixtime

else:
    start_epoch = int(curunixtime + (superblockcycle * 2.6))

end_epoch = int(start_epoch + payout_month * (superblockcycle * 2.6) + (superblockcycle/2 * 2.6) )


proposal = [[
    "proposal",
    {
        "end_epoch": str(end_epoch),
        "name": "test_proposal_" + str(start_epoch),
        "payment_address": payout_address,
        "payment_amount": str(payout_amount),
        "start_epoch": str(start_epoch),
        "type": 1,
        "url": "https://www.dashcentral.org/p/" + "test_proposal_" + str(start_epoch)
    }
]]

print("proposal : ", proposal )
print()

json = simplejson.dumps(proposal, separators=(',', ':'), sort_keys=True, use_decimal=True)
hexdata = binascii.hexlify(json.encode('utf-8')).decode('utf-8')

print("json : ", json)
print()

print("hexdata : ", hexdata)
print()

#
unixpreparetime = now()
txid = get_prepare(unixpreparetime, hexdata)
#
print("txid : ", txid)
print()

while(int(get_rawtxid(txid)) < 6):
    print('wating 6 confirmations')
    time.sleep(60)

#
phash = get_submit(unixpreparetime, hexdata, txid)
print("proposalhash : ", phash)
print()
#
#
vresult = get_vote(phash)
print("Vote yes: done")
#
#

