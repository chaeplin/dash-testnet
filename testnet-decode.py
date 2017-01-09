#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io, os, sys
import array
import binascii
import zmq
import struct
import hashlib
import simplejson as json
import x11_hash
import re
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
import datetime

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
    
    else:
        script_bin = binascii.unhexlify(script_hex)

    # format # 5
    if (len(script_bin) == 25
            and _bord(script_bin[0])  == OP_DUP
            and _bord(script_bin[1])  == OP_HASH160
            and _bord(script_bin[2])  == 0x14               # 20 byte
            and _bord(script_bin[23]) == OP_EQUALVERIFY
            and _bord(script_bin[24]) == OP_CHECKSIG):
        data = script_bin[3:23]                             # take 20 byte
        vs = _bchr(140) + data
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # 1
    elif (len(script_bin) == 67
            and _bord(script_bin[0])  == 0x41
            and _bord(script_bin[66]) == OP_CHECKSIG):
        data = script_bin[1:66]                             # 65 byte
        data_hash = Hash160(data)
        vs = _bchr(140) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # 2, technically invalid.
    elif (len(script_bin) == 66
            and _bord(script_bin[65]) == OP_CHECKSIG):
        data = script_bin[0:65]                             # 65 byte
        data_hash = Hash160(data)
        vs = _bchr(140) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    # format # 3
    elif (len(script_bin) >= 25
            and _bord(script_bin[0]) == OP_DUP
            and _bord(script_bin[1]) == OP_HASH160
            and _bord(script_bin[2]) == 0x14):             # 20 byte        
        data = script_bin[3:23]                            # take 20 byte
        vs = _bchr(140) + data
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
        vs = _bchr(140) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    elif (len(script_bin) == 35 # compressed
            and _bord(script_bin[0])  == 0x21
            and _bord(script_bin[34]) == OP_CHECKSIG):
        data = script_bin[1:34]
        data_hash = Hash160(data)
        vs = _bchr(140) + data_hash
        check = double_sha256(vs)[0:4]
        return b58encode(vs + check)

    elif (_bord(script_bin[0]) == OP_RETURN):
        return 'nulldata'

    else:
        return 'invalid'


def script_forma_5():                                      
    script_hex = '76a914fd85adfcf0c5c6a3f671428a7bfa3944cb84030588ac'
    print('yjRwwxf95GtmK41oEH9VDPdDCtV1Jczmip', script_to_addr(script_hex), len(binascii.unhexlify(script_hex)))

def script_forma_1(): 
    script_hex = '41047559d13c3f81b1fadbd8dd03e4b5a1c73b05e2b980e00d467aa9440b29c7de23664dde6428d75cafed22ae4f0d302e26c5c5a5dd4d3e1b796d7281bdc9430f35ac'
    print('yb21342iADyqAotjwcn4imqjvAcdYhnzeH', script_to_addr(script_hex), len(binascii.unhexlify(script_hex)))

def script_forma_2(): 
    script_hex = '047559d13c3f81b1fadbd8dd03e4b5a1c73b05e2b980e00d467aa9440b29c7de23664dde6428d75cafed22ae4f0d302e26c5c5a5dd4d3e1b796d7281bdc9430f35ac'
    print('yb21342iADyqAotjwcn4imqjvAcdYhnzeH', script_to_addr(script_hex), len(binascii.unhexlify(script_hex)))

def script_forma_3():
    script_hex = '76a914fd85adfcf0c5c6a3f671428a7bfa3944cb84030588acacaa'
    print('yjRwwxf95GtmK41oEH9VDPdDCtV1Jczmip', script_to_addr(script_hex), len(binascii.unhexlify(script_hex)))

def script_forma_4():                                       
    script_hex = '76a90088ac'
    print('unspendable', script_to_addr(script_hex), len(binascii.unhexlify(script_hex)))

def script_p2p():
    script_hex = '6a281adb1bf4cef81ede4a63ad5ca5943e5288fffc210d90a861a60a96658d7f90580000000000000000'
    print('nulldata', script_to_addr(script_hex))

def script_compressed():
    script_hex = '2103717f7082f58395f02afb45b1ae871cae31293b33c64c8d9568d9cac09fa70c51ac'
    print('yhF732jM8hA2e5svfBCa1heFbdHVNXdM8n', script_to_addr(script_hex), len(binascii.unhexlify(script_hex)))    

# check
"""
script_forma_5()
script_forma_1()
script_forma_2()
script_forma_3()
script_forma_4()
script_p2p()
script_compressed()
"""


### rawtx
OP_DUP = 0x76
OP_HASH160 = 0xa9
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

    #print(txid)
    #print(json.dumps(txo, sort_keys=True, indent=4, separators=(',', ': ')))

    addrcheck = {}
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

            elif (addrn == 'pay_to_pubkey'):
                addrcheck['pubkey'] = {
                    "hashin":   hashn + '-' + str(x.get('outpoint')['index']),
                    "addrfrom": addrn
                }
        else:
            addrcheck['coinbase'] = {
                    "hashin":   '0000000000000000000000000000000000000000000000000000000000000000' + '-' + str(0),
                    "addrfrom": 'coinbase'
            }

    if addrcheck.get('coinbase', None) != None:
        hashin   = addrcheck.get('coinbase')['hashin']
        addrfrom = addrcheck.get('coinbase')['addrfrom']         

    if addrcheck.get('pubkey', None) != None:
        hashin   = addrcheck.get('good')['hashin']
        addrfrom = addrcheck.get('good')['addrfrom']      

    if addrcheck.get('good', None) != None:
        hashin   = addrcheck.get('good')['hashin']
        addrfrom = addrcheck.get('good')['addrfrom']

    #print(json.dumps(addrcheck, sort_keys=True, indent=4, separators=(',', ': ')))

    addrval = {}

    for x in txo.get('outs'):
        script = x.get('script')
        valout = x.get('value')
        outno  = x.get('n')
        value  = str('{0:.8f}'.format(float(valout / 1e8)))
        addrto = script_to_addr(script)

        hashout = txid + '-' + str(outno)

        #print(hashout, addrto, value)
        addrval[addrto] = {
            "from": addrfrom,
            "hashin": hashin,
            "txid": hashout,
            "to": addrto,
            "value": value
        }

    return addrval


def check_rawtx():
    rawtx_hex = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff06039ab7010101ffffffff0240230e4300000000232103717f7082f58395f02afb45b1ae871cae31293b33c64c8d9568d9cac09fa70c51ac40230e43000000001976a9146753f211b0fb9ec2b5db90a0a4e08169c25629a388ac00000000'
    x = decoderawtx(rawtx_hex)
    print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))

# check_rawtx()

# block

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

#--------
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


def rpc_getrawtransaction(txid):
    print('rpc_rawtx: %s' % txid)
    try:
        txidjson = access.getrawtransaction(txid, 1)
        print(json.dumps(txidjson, sort_keys=True, indent=4, separators=(',', ': ')))

    except Exception as e:
        print(e.args[0])
        pass

#---------
# rpc
rpcuser     = 'nemo'    # change
rpcpassword = 'ze0riiHgZvzFSHX5--WbkPcmtEtIXjGokTNvjmPAVVc=' # change

rpcbindip   = '127.0.0.1'
rpcport     = 19998

port = 28332


#--------------
# rpc 
serverURL = 'http://' + rpcuser + ':' + rpcpassword + '@' + rpcbindip + ':' + str(rpcport)
access = AuthServiceProxy(serverURL)

while(not checksynced()):
    time.sleep(30)

blockcount = rpcgetinfo()

zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtxlock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtxlock")
zmqSubSocket.connect("tcp://127.0.0.1:%i" % port)

current_sequence = 0

try:
    while True:
        msg   = zmqSubSocket.recv_multipart()
        topic = str(msg[0].decode("utf-8"))
        body  = str(binascii.hexlify(msg[1]).decode("utf-8"))
        sequence = "Unknown";

        if len(msg[-1]) == 4:
          msgSequence = struct.unpack('<I', msg[-1])[-1]
          sequence = str(msgSequence)


        if topic == 'rawtx':
            x = decoderawtx(body)
            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))
        
#        if topic == 'hashtx':
#            rpc_getrawtransaction(body)

        if topic == 'rawblock':
            print('--> ', blockcount + 1, '---> ', sequence)
            x = decoderawblock(body)
            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))
            blockcount = blockcount + 1


except Exception as e:
    print(e.args[0])
    zmqContext.destroy()
    sys.exit()

except KeyboardInterrupt:
    zmqContext.destroy()
    sys.exit()
