#!/usr/bin/env python3

import hashlib
import struct
import simplejson as json
import binascii
from datetime import datetime
import x11_hash
import sys
import re

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

_bchr = chr
_bord = ord
long = int
_bchr = lambda x: bytes([x])
_bord = lambda x: x

def calc_difficulty(nBits):
    """Calculate difficulty from nBits target"""
    nShift = (nBits >> 24) & 0xff
    dDiff = float(0x0000ffff) / float(nBits & 0x00ffffff)
    while nShift < 29:
        dDiff *= 256.0
        nShift += 1
    while nShift > 29:
        dDiff /= 256.0
        nShift -= 1
    return dDiff

def format_hash(hash_):
    return str(binascii.hexlify(hash_[::-1]).decode("utf-8"))

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

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
            "value": read_as_int(8),
            "script": read_var_string()
        })
    obj["locktime"] = read_as_int(4)
    return obj

#------
_base58_codestring = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
_base58_codestring_len = len (_base58_codestring)

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

def scriptSig_decode(pub):
#    scriptSig = binascii.unhexlify(pub)
#    h4 = hashlib.new('ripemd160', hashlib.sha256(scriptSig).digest()).digest()
#    result = _bchr(140) + h4
#    h6 = hashlib.sha256(hashlib.sha256(result).digest())
#    result += h6.digest()[0:4]
#    return b58encode(result)

    scriptSig = binascii.unhexlify(pub)
    h1 = hashlib.new('ripemd160', hashlib.sha256(scriptSig).digest()).digest()
    vs = _bchr(140) + h1
    check = hashlib.sha256(hashlib.sha256(vs).digest()).digest()[0:4]
    return b58encode(vs + check)

def scriptPubKey_decode(pub):
    OP_DUP = 0x76
    OP_HASH160 = 0xa9
    OP_EQUALVERIFY = 0x88
    OP_CHECKSIG = 0xac

    scriptPubKey = binascii.unhexlify(pub)
    if (len(scriptPubKey) == 25
             and _bord(scriptPubKey[0])  == OP_DUP
             and _bord(scriptPubKey[1])  == OP_HASH160
             and _bord(scriptPubKey[2])  == 0x14
             and _bord(scriptPubKey[23]) == OP_EQUALVERIFY
             and _bord(scriptPubKey[24]) == OP_CHECKSIG):
        data = scriptPubKey[3:23]
        vs = _bchr(140) + data
        check = hashlib.sha256(hashlib.sha256(vs).digest()).digest()[0:4]
        return b58encode(vs + check)
    else:
        return 'can\'t decode'

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

#------------
blockjson = {
  "hash": "00000005df0740c2bb40d9a1dc73c2306116f8a271b99cf33c9348a5dff9aaee",
  "confirmations": 969,
  "size": 666,
  "height": 110369,
  "version": 536870912,
  "merkleroot": "e31c21f84b251cb7c379d9d4466f9839f1f0722b9d209fe58aa37ee81560d912",
  "tx": [
    "bb38482b4c6cbda60cb4e09b6305357bf760eb4f5ecb79ffec63f80c0196d7d1", 
    "a5830a905b09b3bce13c87a4023532c9792739ce4c5653e1d8e05668fee62838", 
    "d17e593a4063ee786a02e4a9a2935a5d4d052600e2996325cba90b54ec7c140f"
  ],
  "time": 1480352702,
  "mediantime": 1480352005,
  "nonce": 2300023,
  "bits": "1e0179e4",
  "difficulty": 0.002646227969299152,
  "chainwork": "0000000000000000000000000000000000000000000000000000082a7329ffad",
  "previousblockhash": "00000179e3d56728c05f7c70123ef57891f6dd4401fd33a6a7e1a1c72b6b2964",
  "nextblockhash": "0000013ce1549e59ff88174afbc9ce67638722583732df0a8de86c03d24d75a6"
}

rawblock_str = "0000002064296b2bc7a1e1a7a633fd0144ddf69178f53e12707c5fc02867d5e37901000012d96015e87ea38ae59f209d2b72f0f139986f46d4d979c3b71c254bf8211ce3be633c58e479011e771823000301000000010000000000000000000000000000000000000000000000000000000000000000ffffffff060321af010103ffffffff02e1340e4300000000232103d5bbec914a715f26ad8bedb7e2dcdeedfffa7f987bb557be21ae0195db34144eacdb340e43000000001976a9149d6495ba4f13848ffdf2b1803b67e55bd01c851288ac000000000100000001bdc14bd0cd26eaad8a01f1cf9521fb5b1679302e8094cb0b24e92fc02ed85964010000006a473044022050786c6f8cebd41aaf38193d461f1e38fe781294bd7b412c0429b6c2ade19221022030c67ce89779cd7351ba8aa1c9def0bf9edaa1415b78e1e19e3a508f42c8b58e012102bc8afc95c2f4d85d82fdd59f5f92213982c4347d58dbd809e7126d5ed9113836feffffff02e043727c100000001976a9143fac1ed699d6fddd1892488d129b775d6206af7c88ac8cea44c7a90000001976a91433963f7065ddcdf7f3e39c78c3aa02c58f0a82cc88ac20af01000100000001d7dae185396113aea49d6773364f554b4680862cffb2424ed027def4c9413df3010000006a4730440220559769e63ab712a9a4ab1a8fa5b6786223518f1e416070a72ecb075e8422788602206a02099a0c70ab2ec92d89aea614bb4e9a708450d36ede3bab40b077a72c89a70121020ff9a502715373a8076deaf423eb854761c67e45e54ce36aeb3562664c2d2749feffffff0200e87648170000001976a9143fac1ed699d6fddd1892488d129b775d6206af7c88ac64a9bb67290000001976a9145a799e9cd0abf2d7ebf5ab71b44319230cff903788ac20af0100"

rawtx_h   = {}
rawtx_str = {}

rawtx_h[0]   = "bb38482b4c6cbda60cb4e09b6305357bf760eb4f5ecb79ffec63f80c0196d7d1"
rawtx_str[0] = "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff060321af010103ffffffff02e1340e4300000000232103d5bbec914a715f26ad8bedb7e2dcdeedfffa7f987bb557be21ae0195db34144eacdb340e43000000001976a9149d6495ba4f13848ffdf2b1803b67e55bd01c851288ac00000000"

rawtx_h[1]   = "a5830a905b09b3bce13c87a4023532c9792739ce4c5653e1d8e05668fee62838"
rawtx_str[1] = "0100000001bdc14bd0cd26eaad8a01f1cf9521fb5b1679302e8094cb0b24e92fc02ed85964010000006a473044022050786c6f8cebd41aaf38193d461f1e38fe781294bd7b412c0429b6c2ade19221022030c67ce89779cd7351ba8aa1c9def0bf9edaa1415b78e1e19e3a508f42c8b58e012102bc8afc95c2f4d85d82fdd59f5f92213982c4347d58dbd809e7126d5ed9113836feffffff02e043727c100000001976a9143fac1ed699d6fddd1892488d129b775d6206af7c88ac8cea44c7a90000001976a91433963f7065ddcdf7f3e39c78c3aa02c58f0a82cc88ac20af0100"

rawtx_h[2]   = "d17e593a4063ee786a02e4a9a2935a5d4d052600e2996325cba90b54ec7c140f"
rawtx_str[2] = "0100000001d7dae185396113aea49d6773364f554b4680862cffb2424ed027def4c9413df3010000006a4730440220559769e63ab712a9a4ab1a8fa5b6786223518f1e416070a72ecb075e8422788602206a02099a0c70ab2ec92d89aea614bb4e9a708450d36ede3bab40b077a72c89a70121020ff9a502715373a8076deaf423eb854761c67e45e54ce36aeb3562664c2d2749feffffff0200e87648170000001976a9143fac1ed699d6fddd1892488d129b775d6206af7c88ac64a9bb67290000001976a9145a799e9cd0abf2d7ebf5ab71b44319230cff903788ac20af0100"

#-----
print(json.dumps(blockjson, sort_keys=True, indent=4, separators=(',', ': '))) 
print()
print('rawblock_str: ', rawblock_str)
print()

#----
block_hex = binascii.unhexlify(rawblock_str)

#----
print('rawblock_str [0:160]: ', rawblock_str[0:160])
print('block_hex [0:80]:     ', binascii.hexlify(block_hex[:80]).decode("utf-8"))
print('header_format_hash:   ', format_hash(block_hex[:80]))
print()

bversion  = block_hex[:4]
bpbhash   = block_hex[4:36]
bmkroot   = block_hex[36:68]
btime     = block_hex[68:72]
bbits     = block_hex[72:76]
bnonce    = block_hex[76:80]

#-----------------------
# 80 bytes Blockheader
print('version:    ', decode_uint32(bversion))
print('p_b_hash:   ', format_hash(bpbhash))
print('merkleroot: ', format_hash(bmkroot))
print('time:       ', datetime.utcfromtimestamp(decode_uint32(btime)))
print('difficulty: ', calc_difficulty(decode_uint32(bbits)))
print('nonce:      ', decode_uint32(bnonce))

block_hash = format_hash(x11_hash.getPoWHash(block_hex[:80]))
print('block_hash: ', block_hash)
print()

#---------------------
transaction_data = block_hex[80:]
n_transactions, offset = decode_varint(transaction_data)
print('n_transactions, offset: ', n_transactions, offset)
print()

for i in range(n_transactions):
    transaction = Transactionfromhex(transaction_data[offset:])
    offset += transaction[0]
    rawtx = binascii.hexlify(transaction[1]).decode("utf-8")
    rawtx_hash = format_hash(double_sha256(transaction[1]))

    print('tx no: ------------------ ', i+1)
#    print('rawtx_hash: ', rawtx_hash)
#    print('rawtx_h     ', rawtx_h[i])
#    print('rawtx:      ', rawtx)
#    print('rawtx_str:  ', rawtx_str[i])
#    print()

    txo = deserialize(rawtx)
#    print(json.dumps(txo, sort_keys=True, indent=4, separators=(',', ': ')))

    
    for x in txo.get('ins'):
        hashin   = x.get('outpoint')['hash']
        sriptsig = x.get('script')
        if hashin != '0000000000000000000000000000000000000000000000000000000000000000':
            des_sriptsig = deserialize_script(sriptsig)
            pub_key = des_sriptsig[1]
            addr  = scriptSig_decode(pub_key)
            print('send:     %s' % addr)
            
    for x in txo.get('outs'):
        script = x.get('script')
        value  = x.get('value')
   #     if hashin != '0000000000000000000000000000000000000000000000000000000000000000':
        value = str('{0:.8f}'.format(float(value / 1e8)))
        print('recev:    %s, val: %s' % (scriptPubKey_decode(script), value))

    print()
