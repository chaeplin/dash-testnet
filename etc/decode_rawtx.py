#!/usr/bin/env python3
# code from
# https://github.com/vbuterin/pybitcointools/
# https://github.com/petertodd/python-bitcoinlib

import hashlib
from bitcoin import *

long = int
_bchr = lambda x: bytes([x])
_bord = lambda x: x


#{
#  "hex": "010000000128efb830f177a0fb4c4f0f3d7fee81e46a61c36ebd06b6d5ad5945f2f384f69d010000006b483045022100ea9275dad2aa4f17cd55409d87e1de80e86e14413f9419329dd06cb3f1fde35a0220535e251becb19eb3aec82ef28cdf8f60fe3eee8c9f08e0d7759d32a9e3fdf284012102d1c997d942867336302bd9e5c28f109cf851df0ceeee25563b4f36ae83a2bf2bffffffff020dc0530d000000001976a9147f561dc61197267f553385f53f8eb9623f0a472e88ac62d30928000000001976a914d36f11b42b491b9204d11c34f70f045271031e9988ac00000000",
#  "txid": "52e9accee1678361d3f8057a69b3f18383a3d67f0373edebb5ba699f8f48212b",
#  "size": 226,
#  "version": 1,
#  "locktime": 0,
#  "vin": [
#    {
#      "txid": "9df684f3f24559add5b606bd6ec3616ae481ee7f3d0f4f4cfba077f130b8ef28",
#      "vout": 1,
#      "scriptSig": {
#        "asm": "3045022100ea9275dad2aa4f17cd55409d87e1de80e86e14413f9419329dd06cb3f1fde35a0220535e251becb19eb3aec82ef28cdf8f60fe3eee8c9f08e0d7759d32a9e3fdf284[ALL] 02d1c997d942867336302bd9e5c28f109cf851df0ceeee25563b4f36ae83a2bf2b",
#        "hex": "483045022100ea9275dad2aa4f17cd55409d87e1de80e86e14413f9419329dd06cb3f1fde35a0220535e251becb19eb3aec82ef28cdf8f60fe3eee8c9f08e0d7759d32a9e3fdf284012102d1c997d942867336302bd9e5c28f109cf851df0ceeee25563b4f36ae83a2bf2b"
#      },
#      "sequence": 4294967295
#    }
#  ],
#  "vout": [
#    {
#      "value": 2.23592461,
#      "valueSat": 223592461,
#      "n": 0,
#      "scriptPubKey": {
#        "asm": "OP_DUP OP_HASH160 7f561dc61197267f553385f53f8eb9623f0a472e OP_EQUALVERIFY OP_CHECKSIG",
#        "hex": "76a9147f561dc61197267f553385f53f8eb9623f0a472e88ac",
#        "reqSigs": 1,
#        "type": "pubkeyhash",
#        "addresses": [
#          "yXvjq2mAaC6FTXxGkKALg6juaj4PqAgxFY"
#        ]
#      }
#    }, 
#    {
#      "value": 6.71732578,
#      "valueSat": 671732578,
#      "n": 1,
#      "scriptPubKey": {
#        "asm": "OP_DUP OP_HASH160 d36f11b42b491b9204d11c34f70f045271031e99 OP_EQUALVERIFY OP_CHECKSIG",
#        "hex": "76a914d36f11b42b491b9204d11c34f70f045271031e9988ac",
#        "reqSigs": 1,
#        "type": "pubkeyhash",
#        "addresses": [
#          "yfbQUu87xwa89cBvfnLUCtLf6gLDkFkAa2"
#        ]
#      }
#    }
#  ],
#  "blockhash": "00000055ee6cfd6de73d9ce22ecf448a0b2f0c8e202837702e50b6474ece084e",
#  "height": 109560,
#  "confirmations": 5,
#  "time": 1480225182,
#  "blocktime": 1480225182
#}


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
    scriptPubKey = binascii.unhexlify(pub)
    data = scriptPubKey[3:23]
    vs = _bchr(140) + data
    check = hashlib.sha256(hashlib.sha256(vs).digest()).digest()[0:4]
    return b58encode(vs + check)

rawtx = '010000000128efb830f177a0fb4c4f0f3d7fee81e46a61c36ebd06b6d5ad5945f2f384f69d010000006b483045022100ea9275dad2aa4f17cd55409d87e1de80e86e14413f9419329dd06cb3f1fde35a0220535e251becb19eb3aec82ef28cdf8f60fe3eee8c9f08e0d7759d32a9e3fdf284012102d1c997d942867336302bd9e5c28f109cf851df0ceeee25563b4f36ae83a2bf2bffffffff020dc0530d000000001976a9147f561dc61197267f553385f53f8eb9623f0a472e88ac62d30928000000001976a914d36f11b42b491b9204d11c34f70f045271031e9988ac00000000'

txo = deserialize(rawtx)
print(json.dumps(txo, sort_keys=True, indent=4, separators=(',', ': ')))
print()

for x in txo.get('ins'):
    hashin   = x.get('outpoint')['hash']
    sriptsig = x.get('script')
    if hashin != '0000000000000000000000000000000000000000000000000000000000000000':
        des_sriptsig = deserialize_script(sriptsig)
        pub_key = des_sriptsig[1]
        addr = scriptSig_decode(pub_key)
        print('sender addr:  %s' % addr)
        print('check:        yPW87ZjCYTgpVYvp9Fwas2GPZ5FqNBzvwE')

print()

#	
	
for x in txo.get('outs'):
    script = x.get('script')
    print('recev:    %s' % scriptPubKey_decode(script))

print('check:    yXvjq2mAaC6FTXxGkKALg6juaj4PqAgxFY')
print('check:    yfbQUu87xwa89cBvfnLUCtLf6gLDkFkAa2')

