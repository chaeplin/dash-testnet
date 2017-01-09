#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# codes form code from https://github.com/dashpay/electrum-dash
# ref : https://github.com/dashpay/dash/blob/v0.12.1.x/dash-docs/protocol-documentation.md

import io, os, sys
import simplejson as json
import time
import hmac
import hashlib
import binascii
import base64
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from bip32utils import BIP32Key

from lib.config import *
from lib.b58 import *
from lib.hashs import *
from lib.jacobian import *
from lib.keys import *
from lib.utils import *

from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_hid import HidTransport


from pyfiglet import Figlet
from progress.spinner import Spinner

_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))

# --- change 
# rpc
rpcuser     = 'rpcuser'
rpcpassword = 'rpc_password'
rpcbindip   = '127.0.0.1'
rpcport     = 19998

# keepkey config
# path used on keepkey to store 1K tDash
mpath   = "44'/165'/1990'/0"
xpub    = 'tpubDEiBemN1QNqgAMu41t2ojcbeib5YUrJ4Vtx4dUToo1Q6R5gseuY6acV3Y2Sh6xUBpbB982ehrJAUuActSwpq8VVG7xZjtcyjTCLawuLKhU4'
max_gab = 20

announce = True

# masternode config
# Format: "alias IP:port masternodeprivkey collateral_output_txid collateral_output_index collateral_address"
masternode_conf = [
    "mn1 133.130.97.225:19999 92xM17btJMuDHBad7aBQYhviexiuhmC9VzjWajDMQdnSBrgQ5K8 db6730133f883f64cc52725ed7cca5f1d8b98b3120bc9eb4260415c1865e090f 10 ydWWT8kCMij5LhMMGVzBDyXZ9j3ZPkkuiN",
    "mn2 150.95.138.230:19999 92towRFBfcU5Yfdtyvn8e2V7c6UN4c7BzHQ7qCMWRcB5K6w3Rtp db6730133f883f64cc52725ed7cca5f1d8b98b3120bc9eb4260415c1865e090f 7 yX1MJBGdmLWNkyh3bcSQLPj3a4aKbyPXs1",
    "mn3 133.130.103.78:19999 92ufDJMw8KCy9JnN8D1qgzW43bk2iyaLKQdgKF1NTMbUeNpeYoQ db6730133f883f64cc52725ed7cca5f1d8b98b3120bc9eb4260415c1865e090f 3 yNEPZQQZdGeJYdqMjF2wL7SmRevFfJA3zC",
    "mn4 150.95.133.185:19999 92dEJ4uCJQtsnrtsJPyqbCw2axmAPZpSpBDXT4Mmk1AfpWM83fy db6730133f883f64cc52725ed7cca5f1d8b98b3120bc9eb4260415c1865e090f 9 yamNx8kKSmgDfHKTapsRYWRJsJ952Hmocb"
]

# ----- change

# rpc 
serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

#-----------
def serialize_input_str(tx, prevout_n, sequence, scriptSig):
    """Used by MasternodePing in its serialization for signing."""
    s = ['CTxIn(']
    s.append('COutPoint(%s, %s)' % (tx, prevout_n))
    s.append(', ')
    if tx == '00'*32 and prevout_n == 0xffffffff:
        s.append('coinbase %s' % scriptSig)
    else:
        scriptSig2 = scriptSig
        if len(scriptSig2) > 24:
            scriptSig2 = scriptSig2[0:24]
        s.append('scriptSig=%s' % scriptSig2)

    if sequence != 0xffffffff:
        s.append(', nSequence=%d' % sequence)
    s.append(')')
    return ''.join(s)

def keepkeysign(serialize_for_sig, mpath, address):
    print()
    print('---> check keepkey and press button')
    print()
    # change 165/1990/0 to mpath
    sig = client.sign_message('tDash', [44 | 0x80000000, 165 | 0x80000000, 1990 | 0x80000000, 0, int(mpath)], serialize_for_sig)
    if sig.address != address:
        sys.exit('**** ----> check key path')

    return sig.signature.hex()

def signmessage(last_ping_serialize_for_sig, address):
    try:
        print(last_ping_serialize_for_sig, address)
        r = access.signmessage(address, last_ping_serialize_for_sig)
        return(base64.b64decode(r).hex())

    except Exception as e:
        print(e.args)
        sys.exit("\n\nPlease enter the wallet passphrase with walletpassphrase first\n")

def validateaddress(address):
    r = access.validateaddress(address)
    return r['ismine']

def importprivkey(privkey, alias):
    try:
        r = access.importprivkey(privkey, alias, False)

    except Exception as e:
        print(e.args)
        sys.exit("\n\nPlease enter the wallet passphrase with walletpassphrase first\n")

def make_mnb(alias, mn_conf):
    print()
    print('---> making mnb for %s' % alias)
    print()

    # ------ some default config
    scriptSig = ''
    sequence = 0xffffffff
    protocol_version = 70204
    sig_time = int(time.time())

    cur_block_height = access.getblockcount()
    block_hash = access.getblockhash(cur_block_height - 12)

    vinc   = num_to_varint(1).hex() # ? count of rx 
    vintx  = bytes.fromhex(mn_conf['collateral_txid'])[::-1].hex()
    vinno  = mn_conf['collateral_txidn'].to_bytes(4, byteorder='big')[::-1].hex()
    vinsig = num_to_varint(len(scriptSig)/2).hex() + bytes.fromhex(scriptSig)[::-1].hex()
    vinseq = sequence.to_bytes(4, byteorder='big')[::-1].hex()

    ip, port = mn_conf['ipport'].split(':')

    ipv6map = '00000000000000000000ffff'
    ipdigit = map(int, ip.split('.'))
    for i in ipdigit:  
        ipv6map  += i.to_bytes(1, byteorder='big')[::-1].hex()

    ipv6map += int(port).to_bytes(2, byteorder='big').hex()

    collateral_in = num_to_varint(len(mn_conf['collateral_pubkey'])/2).hex() + mn_conf['collateral_pubkey']
    delegate_in   = num_to_varint(len(mn_conf['masternode_pubkey'])/2).hex() + mn_conf['masternode_pubkey']

    serialize_for_sig = str(mn_conf['ipport']) + str(sig_time) \
                      + format_hash(Hash160(bytes.fromhex(mn_conf['collateral_pubkey']))) \
                      + format_hash(Hash160(bytes.fromhex(mn_conf['masternode_pubkey']))) + str(protocol_version)

    sig = keepkeysign(serialize_for_sig, mn_conf['collateral_mpath'], mn_conf['collateral_address'])

    work_sig_time     = sig_time.to_bytes(8, byteorder='big')[::-1].hex() 
    work_protoversion = protocol_version.to_bytes(4, byteorder='big')[::-1].hex()

    last_ping_block_hash = bytes.fromhex(block_hash)[::-1].hex() 

    last_ping_serialize_for_sig  = serialize_input_str(mn_conf['collateral_txid'], mn_conf['collateral_txidn'], sequence, scriptSig) + block_hash + str(sig_time)

    if not validateaddress(mn_conf['masternode_address']):
        keyalias = alias + '-' + ip
        importprivkey(mn_conf['masternode_privkey'], keyalias)

    sig2 = signmessage(last_ping_serialize_for_sig, mn_conf['masternode_address'])

    work = vinc + vintx + vinno + vinsig + vinseq \
        + ipv6map + collateral_in + delegate_in \
        + num_to_varint(len(sig)/2).hex() + sig \
        + work_sig_time + work_protoversion \
        + vintx + vinno + vinsig + vinseq \
        + last_ping_block_hash + work_sig_time \
        + num_to_varint(len(sig2)/2).hex() + sig2

    return work

def process_chain(collateral_address):
    acc_node = BIP32Key.fromExtendedKey(xpub)
    i = 0
    while True:
        mpathi = '%s/%d' % (mpath, i)
        addr_node = acc_node.ChildKey(i)
        address   = addr_node.Address()
        addrpkey  = addr_node.PublicKey().hex()
        if address == collateral_address:
            return {"mpath": i, "addrpubkey": addrpkey}

        if i > max_gab:
            sys.exit("Can't find mpath and publickey of " + collateral_address + " , check masternode_conf")

        i += 1

def parse_masternode_conf(lines):
    mn_conf = {}
    for line in lines:
        # Comment.
        if line.startswith('#'):
            continue

        s = line.split(' ')
        if len(s) < 6:
            continue

        alias = s[0]
        ipport = s[1]
        mnprivkey_wif = s[2]
        txid = s[3]
        txidn = s[4]
        mnaddr = s[5]

        check_mpath        = process_chain(mnaddr)
        collateral_mpath   = check_mpath.get('mpath')
        collateral_pubkey  = check_mpath.get('addrpubkey')

        masternode_pubkey  = get_public_key(wif_to_privkey(mnprivkey_wif).get('privkey')).get('pubkeyhex')
        masternode_address = pubkey_to_address(masternode_pubkey)

        mn_conf[alias] = {
            "ipport": ipport,
            "masternode_privkey": mnprivkey_wif,
            "masternode_pubkey": masternode_pubkey,
            "masternode_address": masternode_address,
            "collateral_txid": txid,
            "collateral_txidn": int(txidn),
            "collateral_address": mnaddr,
            "collateral_mpath": collateral_mpath,
            "collateral_pubkey": collateral_pubkey
        }

    return mn_conf

def checksynced():
    try:
        status = access.mnsync('status')
        return status['IsSynced']

    except:
        return False

#-------------------
def clear_screen():
    # pyfiglet screen
    os.system('cls')  # For Windows
    os.system('clear')  # For Linux/OS X

def logo_show():
    print('========================================================')
    f = Figlet(font='slant')
    print(f.renderText('DashPay Masternode KeepKey'))
    print('========================================================')

def check_masternode():
    try:
        mn_of_net = access.masternodelist()
        return mn_of_net

    except Exception as e:
        print(e.args)
        sys.exit("\n\nDash-QT or dashd running ?\n")

def check_wallet_lock():
    try:
        getinfo = access.getinfo()
        if getinfo.get('unlocked_until', None) != None:
            print('\n---> please unlock wallet \n\t==> Menu | Setting | Unlock Wallet or \n\t==> (dash-cli) walletpassphrase "passphrase" timeout')

    except Exception as e:
        print(e.args)
        sys.exit("\n\nDash-QT or dashd running ?\n")

def start_masternode(alias, mnconfig):
#    for x in mn_config:
#        print()
#        work = make_mnb(x, mn_config[x])
#        print('result --> : ', work)
#    
#        verify = access.masternodebroadcast("decode", work)
#        print(json.dumps(verify, sort_keys=True, indent=4, separators=(',', ': ')))
#
#        if announce:
#            relay  = access.masternodebroadcast("relay", work)
#            print(json.dumps(relay, sort_keys=True, indent=4, separators=(',', ': ')))
#

    print()
    work = make_mnb(alias, mnconfig)
    print('result --> : ', work)
    
    verify = access.masternodebroadcast("decode", work)
    print(json.dumps(verify, sort_keys=True, indent=4, separators=(',', ': ')))
    
    if announce:
        relay  = access.masternodebroadcast("relay", work)
        print(json.dumps(relay, sort_keys=True, indent=4, separators=(',', ': ')))    



#-------------------
if __name__ == "__main__":

    clear_screen()
    logo_show()
    
    # keepkey
    devices = HidTransport.enumerate()
    
    if len(devices) == 0:
        print('No KeepKey found')
        sys.exit()
    
    else:
        transport = HidTransport(devices[0])
        client = KeepKeyClient(transport)
    
    # mn_config
    print('---> checking masternoe config')
    mn_config = parse_masternode_conf(masternode_conf)
    
    # 
    print('---> run Dash-QT or dashd')
    
    spinner = Spinner('---> checking dashd syncing status ')
    while(not checksynced()):
        try:
            spinner.next()
            time.sleep(1)
    
        except:
            sys.exit()
    
    check_wallet_lock()
    mns = check_masternode()

    for x in mn_config:
        txidtxidn = mn_config[x]['collateral_txid'] + '-' + str(mn_config[x]['collateral_txidn'])
        if txidtxidn in mns:
            if (mns[txidtxidn] != 'ENABLED' and  mns[txidtxidn] != 'PRE_ENABLED'):
                start_masternode(x, mn_config[x])
        else:
            start_masternode(x, mn_config[x])


    print()
    print('done')
# end

