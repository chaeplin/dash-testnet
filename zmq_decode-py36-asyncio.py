#!/usr/bin/env python3.6
# Copyright (c) 2014-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# 2017 chaeplin#dash.org

"""
    ZMQ example using python3's asyncio
    dashd should be started with the command line arguments:
        dashd -testnet -daemon \
                -zmqpubhashblock=tcp://127.0.0.1:28332 \
                -zmqpubrawtx=tcp://127.0.0.1:28332 \
                -zmqpubhashtx=tcp://127.0.0.1:28332 \
                -zmqpubhashblock=tcp://127.0.0.1:28332
    We use the asyncio library here.  `self.handle()` installs itself as a
    future at the end of the function.  Since it never returns with the event
    loop having an empty stack of futures, this creates an infinite loop.  An
    alternative is to wrap the contents of `handle` inside `while True`.
"""

import binascii
import asyncio
import zmq
import zmq.asyncio
import signal
import struct
import sys

import io, os, sys
import array
import hashlib
import simplejson as json
import x11_hash
import time
import re
from decimal import Decimal
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from collections import deque
import datetime
import hues

#--
MAINNET = False

if MAINNET:
    wif_prefix = 204  # cc
    addr_prefix = 76   # 4c
    script_prefix = 16 # 10

else:
    wif_prefix = 239  # ef
    addr_prefix = 140  # 8c
    script_prefix = 19 # 13

### rawtx
OP_DUP = 0x76
OP_HASH160 = 0xa9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xac
OP_RETURN   = 0x6a

string_types = (str)
string_or_bytes_types = (str, bytes)
int_types = (int, float)

code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}

# address / key
_base58_codestring = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_base58_codestring_len = len (_base58_codestring)

long = int
_bchr = lambda x: bytes([x])
_bord = lambda x: x

def b58encode (x):
    q = int.from_bytes (x, 'big')
    result = bytearray ()
    while q > 0:
            q, r = divmod (q, _base58_codestring_len)
            result.append (_base58_codestring[r])
    for c in x:
            if c == 0:
                    result.append (_base58_codestring[0])
            else:
                    break

    result.reverse ()
    return bytes (result).decode("utf-8")

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def Hash160(msg):
    return hashlib.new('ripemd160', hashlib.sha256(msg).digest()).digest()

def script_to_addr(script_hex):
    # list : outpu of deserialize_script
    if isinstance(script_hex, list):
        if len(script_hex) == 2:
            script_bin = binascii.unhexlify(script_hex[1])
        elif len(script_hex) == 1:
            return 'pay_to_pubkey'
        elif len(script_hex) > 2:
            return 'pay_to_scripthash'
    
    else:
        script_bin = binascii.unhexlify(script_hex)


    if (_bord(script_bin[0]) == OP_RETURN):
        return 'nulldata'

    # format # 5
    elif (len(script_bin) == 25
            and _bord(script_bin[0])  == OP_DUP
            and _bord(script_bin[1])  == OP_HASH160
            and _bord(script_bin[2])  == 0x14               # 20 byte
            and _bord(script_bin[23]) == OP_EQUALVERIFY
            and _bord(script_bin[24]) == OP_CHECKSIG):
        data = script_bin[3:23]                             # take 20 byte
        vs = _bchr(addr_prefix) + data
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # 1
    elif (len(script_bin) == 67
            and _bord(script_bin[0])  == 0x41
            and _bord(script_bin[66]) == OP_CHECKSIG):
        data = script_bin[1:66]                             # 65 byte
        data_hash = Hash160(data)
        vs = _bchr(addr_prefix) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # 2, technically invalid.
    elif (len(script_bin) == 66
            and _bord(script_bin[65]) == OP_CHECKSIG):
        data = script_bin[0:65]                             # 65 byte
        data_hash = Hash160(data)
        vs = _bchr(addr_prefix) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # x, technically invalid ?.
    elif (len(script_bin) == 65):
        data = script_bin[0:65]                             # 65 byte
        data_hash = Hash160(data)
        vs = _bchr(addr_prefix) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # 3
    elif (len(script_bin) >= 25
            and _bord(script_bin[0]) == OP_DUP
            and _bord(script_bin[1]) == OP_HASH160
            and _bord(script_bin[2]) == 0x14):             # 20 byte        
        data = script_bin[3:23]                            # take 20 byte
        vs = _bchr(addr_prefix) + data
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # 4
    elif (len(script_bin) == 5
            and _bord(script_bin[0]) == OP_DUP
            and _bord(script_bin[1]) == OP_HASH160
            and _bord(script_bin[2]) == 0x00               # 0 byte
            and _bord(script_bin[3]) == OP_EQUALVERIFY
            and _bord(script_bin[4]) == OP_CHECKSIG):
        return 'unspendable'

    # 33 byte (spend coinbase tx ?)
    elif (len(script_bin) == 33):
        data_hash = Hash160(script_bin)
        vs = _bchr(addr_prefix) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    elif (len(script_bin) == 35 # compressed
            and _bord(script_bin[0])  == 0x21
            and _bord(script_bin[34]) == OP_CHECKSIG):
        data = script_bin[1:34]
        data_hash = Hash160(data)
        vs = _bchr(addr_prefix) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # scriptHash

    elif (len(script_bin) == 23
            and _bord(script_bin[0]) == OP_HASH160
            and _bord(script_bin[22]) == OP_EQUAL):
        
        data = script_bin[2:22]
        vs = _bchr(script_prefix) + data
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    else:
        return 'invalid'


def format_hash(hash_):
    return str(binascii.hexlify(hash_[::-1]).decode("utf-8"))

def json_changebase(obj, changer):
    if isinstance(obj, string_or_bytes_types):
        return changer(obj)
    elif isinstance(obj, int_types) or obj is None:
        return obj
    elif isinstance(obj, list):
        return [json_changebase(x, changer) for x in obj]
    return dict((x, json_changebase(obj[x], changer)) for x in obj)

def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")

def from_int_to_byte(a):
    return bytes([a])

def from_byte_to_int(a):
    return a

def safe_hexlify(a):
    return str(binascii.hexlify(a), 'utf-8')

def decode(string, base):
    if base == 256 and isinstance(string, str):
        string = bytes(bytearray.fromhex(string))
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 256:
        def extract(d, cs):
            return d
    else:
        def extract(d, cs):
            return cs.find(d if isinstance(d, str) else chr(d))

    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += extract(string[0], code_string)
        string = string[1:]
    return result

def deserialize_script(script):
    if isinstance(script, str) and re.match('^[0-9a-fA-F]*$', script):
       return json_changebase(deserialize_script(binascii.unhexlify(script)),
                              lambda x: safe_hexlify(x))
    out, pos = [], 0
    while pos < len(script):
        code = from_byte_to_int(script[pos])
        if code == 0:
            out.append(None)
            pos += 1
        elif code <= 75:
            out.append(script[pos+1:pos+1+code])
            pos += 1 + code
        elif code <= 78:
            szsz = pow(2, code - 76)
            sz = decode(script[pos+szsz: pos:-1], 256)
            out.append(script[pos + 1 + szsz:pos + 1 + szsz + sz])
            pos += 1 + szsz + sz
        elif code <= 96:
            out.append(code - 80)
            pos += 1
        else:
            out.append(code)
            pos += 1
    return out

def deserialize(tx):
    if isinstance(tx, str) and re.match('^[0-9a-fA-F]*$', tx):
        return json_changebase(deserialize(binascii.unhexlify(tx)),
                              lambda x: safe_hexlify(x))
    pos = [0]

    def read_as_int(bytez):
        pos[0] += bytez
        return decode(tx[pos[0]-bytez:pos[0]][::-1], 256)

    def read_var_int():
        pos[0] += 1
        
        val = from_byte_to_int(tx[pos[0]-1])
        if val < 253:
            return val
        return read_as_int(pow(2, val - 252))

    def read_bytes(bytez):
        pos[0] += bytez
        return tx[pos[0]-bytez:pos[0]]

    def read_var_string():
        size = read_var_int()
        return read_bytes(size)

    obj = {"ins": [], "outs": []}
    obj["version"] = read_as_int(4)
    ins = read_var_int()
    for i in range(ins):
        obj["ins"].append({
            "outpoint": {
                "hash": read_bytes(32)[::-1],
                "index": read_as_int(4)
            },
            "script": read_var_string(),
            "sequence": read_as_int(4)
        })
    outs = read_var_int()
    for i in range(outs):
        obj["outs"].append({
            "n": i,
            "value": read_as_int(8),
            "script": read_var_string()
        })
    obj["locktime"] = read_as_int(4)
    return obj

def decoderawtx(rawtx):
    txo  = deserialize(rawtx)
    txid = format_hash(double_sha256(binascii.unhexlify(rawtx)))

    addrcheck = {}
    addrfromall = []
    addrinputno = len(txo.get('ins'))
    addroutputno = len(txo.get('outs'))   
 
    for x in txo.get('ins'):
        hashn = x.get('outpoint')['hash']
        if hashn != '0000000000000000000000000000000000000000000000000000000000000000':
            des_script = deserialize_script(x.get('script'))

            addrn      = script_to_addr(des_script)
            if (addrn != 'pay_to_pubkey'
                    and addrn != 'unspendable'
                    and addrn != 'nulldata'
                    and addrn != 'invalid'):
                addrcheck['good'] = {
                    "hashin":   hashn + '-' + str(x.get('outpoint')['index']),
                    "addrfrom": addrn
                }
                addrfromall.append(addrn)

            elif (addrn == 'pay_to_pubkey'):
                addrcheck['pubkey'] = {
                    "hashin":   hashn + '-' + str(x.get('outpoint')['index']),
                    "addrfrom": 'pay_to_pubkey'
                }
                addrfromall.append('pay_to_pubkey')

            elif (addrn == 'pay_to_scripthash'):
                addrcheck['pubkey'] = {
                    "hashin":   hashn + '-' + str(x.get('outpoint')['index']),
                    "addrfrom": 'pay_to_scripthash'
                }
                addrfromall.append('pay_to_scripthash')


        else:
            addrcheck['coinbase'] = {
                    "hashin":   '0000000000000000000000000000000000000000000000000000000000000000' + '-' + str(0),
                    "addrfrom": 'coinbase'
            }
            addrfromall.append('coinbase')

    if addrcheck.get('coinbase', None) != None:
        hashin   = addrcheck.get('coinbase')['hashin']
        addrfrom = addrcheck.get('coinbase')['addrfrom']         

    if addrcheck.get('pubkey', None) != None:
        hashin   = addrcheck.get('good')['hashin']
        addrfrom = addrcheck.get('good')['addrfrom']      


    if addrcheck.get('good', None) != None:
        hashin   = addrcheck.get('good')['hashin']
        addrfrom = addrcheck.get('good')['addrfrom']

    addrval = {}

    for x in txo.get('outs'):
        script = x.get('script')
        valout = x.get('value')
        outno  = x.get('n')
        value  = str('{0:.8f}'.format(float(valout / 1e8)))
        addrto = script_to_addr(script)

        hashout = txid + '-' + str(outno)

        if addrval.get(addrto, None) == None:
            addrval[addrto] = {
                "inputno": addrinputno,
                "outputno": addroutputno,
                "from": addrfrom,
                "fromall": addrfromall,
                "hashin": hashin,
                "txid": hashout,
                "to": addrto,
                "value": value
            }

        else:
            addrval[addrto]["value"] = str('{0:.8f}'.format(float(addrval[addrto]["value"]) + float(valout / 1e8)))

    return addrval

def calc_difficulty(nBits):
    nShift = (nBits >> 24) & 0xff
    dDiff = float(0x0000ffff) / float(nBits & 0x00ffffff)
    while nShift < 29:
        dDiff *= 256.0
        nShift += 1
    while nShift > 29:
        dDiff /= 256.0
        nShift -= 1
    return dDiff

def decode_uint32(data):
    assert(len(data) == 4)
    return struct.unpack("<I", data)[0]

def decode_varint(data):
    assert(len(data) > 0)
    size = int(data[0])
    assert(size <= 255)

    if size < 253:
        return size, 1

    format_ = None
    if size == 253:
        format_ = '<H'
    elif size == 254:
        format_ = '<I'
    elif size == 255:
        format_ = '<Q'
    else:
        assert 0, "unknown format_ for size : %s" % size

    size = struct.calcsize(format_)
    return struct.unpack(format_, data[1:size+1])[0], size + 1

def Inputfromhex(raw_hex):
    _script_length, varint_length = decode_varint(raw_hex[36:])
    _script_start = 36 + varint_length
    _size = _script_start + _script_length + 4
    _hex = raw_hex[:_size]
    return _size, _hex

def Outputfromhex(raw_hex):
    script_length, varint_size = decode_varint(raw_hex[8:])
    script_start = 8 + varint_size
    _script_hex = raw_hex[script_start:script_start+script_length]
    _size = script_start + script_length
    _hex = raw_hex[:8]
    return _size, _hex

def Transactionfromhex(raw_hex):
    n_inputs = 0
    n_outputs = 0
    
    offset = 4
    n_inputs, varint_size = decode_varint(raw_hex[offset:])
    offset += varint_size

    for i in range(n_inputs):
        input = Inputfromhex(raw_hex[offset:])
        offset += input[0]

    n_outputs, varint_size = decode_varint(raw_hex[offset:])
    offset += varint_size
    
    for i in range(n_outputs):
        output = Outputfromhex(raw_hex[offset:])
        offset += output[0]
    
    _size = offset + 4
    _hex = raw_hex[:_size]
    return _size, _hex

def decoderawblock(rawblock):
    block_hex = binascii.unhexlify(rawblock)
    bversion  = block_hex[:4]
    bpbhash   = block_hex[4:36]
    bmkroot   = block_hex[36:68]
    btime     = block_hex[68:72]
    bbits     = block_hex[72:76]
    bnonce    = block_hex[76:80]

    block = {}
    block['hash']       = format_hash(x11_hash.getPoWHash(block_hex[:80]))
    block['version']    = decode_uint32(bversion)
    block['p_b_hash']   = format_hash(bpbhash)
    block['merkleroot'] = format_hash(bmkroot)
    block['time']       = decode_uint32(btime)
    block['difficulty'] = calc_difficulty(decode_uint32(bbits))
    block['nonce']      = decode_uint32(bnonce)

    transaction_data = block_hex[80:]
    n_transactions, offset = decode_varint(transaction_data)

    txs = {}
    for i in range(n_transactions):
        transaction = Transactionfromhex(transaction_data[offset:])
        offset += transaction[0]
        rawtx = binascii.hexlify(transaction[1]).decode("utf-8")
        rawtx_hash = format_hash(double_sha256(transaction[1]))
        txs[rawtx_hash] = rawtx

    block['txs'] = txs

    return block


def checksynced():
    try:
        synced = access.mnsync('status')['IsSynced']
        return synced
    except:
        return False

def rpcgetinfo():
    try:
        getblockcount = access.getblockcount()

        if getblockcount:
            return int(getblockcount)
    except:
        return None

def rpcgetblock(bhash):
    try:
        bhashinfo = access.getblock(bhash)

        if bhashinfo:
            return bhashinfo

    except:
        return None

def now():
    return int(time.time())


#----
port = 28332

# rpc
rpcuser     = 'xxx'
rpcpassword = 'xxx--xxxx'

rpcbindip   = '127.0.0.1'
rpcport     = 19998

#
q  = deque(maxlen=100)
qq = deque(maxlen=100)
current_sequence = 0
lastblcokzmq = 0

#-
if not (sys.version_info.major >= 3 and sys.version_info.minor >= 5):
    print("This example only works with Python 3.5 and greater")
    sys.exit(1)


serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

while(not checksynced()):
    time.sleep(30)

blockcount = rpcgetinfo()

###
class ZMQHandler():

    def __init__(self):
        self.loop = zmq.asyncio.install()
        self.zmqContext = zmq.asyncio.Context()

        self.zmqSubSocket = self.zmqContext.socket(zmq.SUB)
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "hashblock")
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "hashtx")
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "rawblock")
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "rawtx")
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "hashtxlock")
        self.zmqSubSocket.setsockopt_string(zmq.SUBSCRIBE, "rawtxlock")
        self.zmqSubSocket.connect("tcp://127.0.0.1:%i" % port)

    async def handle(self):
        global blockcount, lastblcokzmq

        msg = await self.zmqSubSocket.recv_multipart()
        topic = str(msg[0].decode("utf-8"))
        body  = str(binascii.hexlify(msg[1]).decode("utf-8"))
        sequence = "Unknown";

        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(now()))

        if len(msg[-1]) == 4:
          msgSequence = struct.unpack('<I', msg[-1])[-1]
          sequence = str(msgSequence)

        if topic == 'rawtxlock':
            x = decoderawtx(body)
            txid = format_hash(double_sha256(binascii.unhexlify(body)))
            if txid not in q:
                q.append(txid)
                n = 0
                for y in x:
                    v = float(Decimal(x[y]['value']))
                    inputno  = x[y].get('inputno')
                    outputno = x[y].get('outputno')
                    fromnumberuniq = len(list(set(x[y].get('fromall'))))
                    toaddruniq = len(x)

                    if n == 0:
                        fromaddr = x[y].get('fromall')[n]
                        print('{} {:34} {:3d} {:4d} {:34} {:16.8f} is {}'.format(ts, fromaddr, inputno, outputno, y, v, txid))

                    else:
                        print('{:58d} {:4d} {:34} {:16.8f} is'.format(inputno, outputno, y, v))

                    n = n + 1

        if topic == 'rawtx':
            txid = format_hash(double_sha256(binascii.unhexlify(body)))
            x = decoderawtx(body)

#            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))

            if txid not in qq:
                qq.append(txid)
                n = 0
                for y in x:
                    v = float(Decimal(x[y]['value']))

                    inputno  = x[y].get('inputno')
                    outputno = x[y].get('outputno')

                    fromnumberuniq = len(list(set(x[y].get('fromall'))))
                    toaddruniq = len(x)
    
                    if n == 0:
                        fromaddr = x[y].get('fromall')[n]
                        print('{} {:34} {:3d} {:4d} {:34} {:16.8f} {}'.format(ts, fromaddr, inputno, outputno, y, v, txid))
                    else:
                        if inputno == outputno and inputno > 3:
                            fromaddr = x[y].get('fromall')[n]
                            if inputno != fromnumberuniq or outputno != toaddruniq:
                                print('{:>54} {:3d} {:4d} {:34} {:16.8f} --> **** {:3d} {:4d}'.format(fromaddr, inputno, outputno, y, v, fromnumberuniq, toaddruniq))
                            else:
                                print('{:>54} {:3d} {:4d} {:34} {:16.8f}'.format(fromaddr, inputno, outputno, y, v))

                        else:
                            print('{:58d} {:4d} {:34} {:16.8f}'.format(inputno, outputno, y, v))

                    n = n + 1

        if topic == 'rawblock':
            x = decoderawblock(body)
            txno = len(x['txs'])
            binfo = rpcgetblock(x['hash'])
            binfo_time = binfo.get('time')
            curtime = now()
            
            block_no_colorized = hues.huestr(str(blockcount + 1)).green.bold.colorized
            block_time_colorized = hues.huestr(str(curtime - lastblcokzmq)).red.colorized
            print('{} {} {} {:3d} {:3d} {:5}'.format(ts, block_no_colorized, x['hash'], txno, curtime - binfo_time, block_time_colorized))

            blockcount = blockcount + 1
            lastblcokzmq = curtime

        asyncio.ensure_future(self.handle())

    def start(self):
        self.loop.add_signal_handler(signal.SIGINT, self.stop)
        self.loop.create_task(self.handle())
        self.loop.run_forever()

    def stop(self):
        self.loop.stop()
        self.zmqContext.destroy()

#--


daemon = ZMQHandler()
daemon.start()
