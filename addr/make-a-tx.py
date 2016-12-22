#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.config import *
from lib.b58 import *
from lib.hashs import *
from lib.jacobian import *
from lib.keys import *
from lib.tx import *
from lib.utils import *
import hmac

long = int
_bchr = lambda x: bytes([x])
_bord = lambda x: x

def serialize(txobj):
    o = []    
    o.append(txobj["version"].to_bytes(4, byteorder='little').hex())
    o.append(num_to_varint(len(txobj["ins"])).hex())
    for inp in txobj["ins"]:
        o.append(bytes.fromhex(inp["outpoint"]["hash"])[::-1].hex())
        o.append(inp["outpoint"]["index"].to_bytes(4, byteorder='little').hex())
        o.append(num_to_varint(len(inp["script"])//2).hex())
        if inp["script"]:
            o.append(inp["script"])
        o.append(inp["sequence"].to_bytes(4, byteorder='little').hex())
    o.append(num_to_varint(len(txobj["outs"])).hex())
    for out in txobj["outs"]:
        o.append(out["value"].to_bytes(8, byteorder='little').hex())
        o.append(num_to_varint(len(out["script"])//2).hex() + out["script"])
    o.append(txobj["locktime"].to_bytes(4, byteorder='little').hex())

    return ''.join(o)   

def address_to_script(addr):
    return '76a914' + b58decode(addr).hex()[2:-8] + '88ac'

def is_inp(arg):
    return len(arg) > 64 or "output" in arg or "outpoint" in arg

def mktx(*args, **kwargs):
    # [in0, in1...],[out0, out1...] or in0, in1 ... out0 out1 ...
    ins, outs = [], []
    for arg in args:
        if isinstance(arg, list):
            for a in arg: (ins if is_inp(a) else outs).append(a)
        else:
            (ins if is_inp(arg) else outs).append(arg)

    txobj = {"locktime": kwargs.get('locktime', 0), "version": 1, "ins": [], "outs": []}
    
    for i in ins:
        if isinstance(i, dict) and "outpoint" in i:
            txobj["ins"].append(i)
        else:
            if isinstance(i, dict) and "output" in i:
                i = i["output"]
            txobj["ins"].append({
                "outpoint": {"hash": i[:64], "index": int(i[65:])},
                "script": "",
                "sequence": 4294967295
            })
    for o in outs:
        if isinstance(o, (str, bytes)):
            addr = o[:o.find(':')]
            val = int(o[o.find(':')+1:])
            o = {}
            if re.match('^[0-9a-fA-F]*$', addr):
                o["script"] = addr
            else:
                o["address"] = addr
            o["value"] = val

        outobj = {}
        if "address" in o:
            outobj["script"] = address_to_script(o["address"])
        elif "script" in o:
            outobj["script"] = o["script"]
        else:
            raise Exception("Could not find 'address' or 'script' in output.")
        outobj["value"] = o["value"]
        txobj["outs"].append(outobj)

    return serialize(txobj)


#---------------
# Hashing transactions for signing

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x81

def deterministic_generate_k(msghash, priv):
    v = b'\x01' * 32
    k = b'\x00' * 32
    priv = bytes.fromhex(priv)
    msghash = decode_hexto_int(msghash.hex()).to_bytes(32, byteorder='big')
    k = hmac.new(k, v+b'\x00'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v+b'\x01'+priv+msghash, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    return decode_hexto_int(hmac.new(k, v, hashlib.sha256).digest().hex())

def ecdsa_raw_sign(msghash, priv):
    z = decode_hexto_int(msghash.hex())
    k = deterministic_generate_k(msghash, priv)

    r, y = fast_multiply(G, k)
    s = inv(k, N) * (z + r*decode_hexto_int(priv)) % N
    v, r, s = 27+((y % 2) ^ (0 if s * 2 < N else 1)), r, s if s * 2 < N else N - s
    v += 4
    return v, r, s    

def der_encode_sig(v, r, s):
    b1, b2 = r.to_bytes(32, byteorder='big').hex(), s.to_bytes(32, byteorder='big').hex()
    if len(b1) and b1[0] in '89abcdef':
        b1 = '00' + b1
    if len(b2) and b2[0] in '89abcdef':
        b2 = '00' + b2
    left = '02'+(len(b1)//2).to_bytes(1, byteorder='big').hex()+b1
    right = '02'+(len(b2)//2).to_bytes(1, byteorder='big').hex()+b2
    return '30'+(len(left+right)//2).to_bytes(1, byteorder='big').hex()+left+right 

def ecdsa_tx_sign(tx, priv, hashcode=SIGHASH_ALL):
    msghash_ = double_sha256(bytes.fromhex(tx) + hashcode.to_bytes(4, byteorder='little'))
    rawsig = ecdsa_raw_sign(msghash_, priv)
    return der_encode_sig(*rawsig)+hashcode.to_bytes(1, byteorder='big').hex()

def signature_form(tx, i, script, hashcode=SIGHASH_ALL):
    i, hashcode = int(i), int(hashcode)
    newtx = deserialize(tx)
    for inp in newtx["ins"]:
        inp["script"] = ""
    newtx["ins"][i]["script"] = script
    if hashcode == SIGHASH_NONE:
        newtx["outs"] = []
    elif hashcode == SIGHASH_SINGLE:
        newtx["outs"] = newtx["outs"][:len(newtx["ins"])]
        for out in newtx["outs"][:len(newtx["ins"]) - 1]:
            out['value'] = 2**64 - 1
            out['script'] = ""
    elif hashcode == SIGHASH_ANYONECANPAY:
        newtx["ins"] = [newtx["ins"][i]]
    else:
        pass
    return serialize(newtx)

def serialize_script_unit(unit):
    if isinstance(unit, int):
        if unit < 16:
            return (unit + 80).to_bytes(1, byteorder='big')
        else:
            return unit.to_bytes(1, byteorder='big')
    elif unit is None:
        return b'\x00'
    else:
        if len(unit) <= 75:
            return (len(unit)).to_bytes(1, byteorder='big')+unit
        elif len(unit) < 256:
            return (76).to_bytes(1, byteorder='big')+(len(unit)).to_bytes(1, byteorder='big')+unit
        elif len(unit) < 65536:
            return (77).to_bytes(1, byteorder='big')+len(unit).to_bytes(2, byteorder='little')+unit
        else:
            return (78).to_bytes(1, byteorder='big')+len(unit).to_bytes(4, byteorder='little')+unit

def serialize_script(script):
     result = bytes()
     for b in map(serialize_script_unit, script):
         result += b #if isinstance(b, bytes) else bytes(b, 'utf-8')
     return result.hex()

def sign(tx, i, priv, hashcode=SIGHASH_ALL):
    i = int(i)
    pub = get_public_key(priv).get('pubkeyhex_compressed')
    address = pubkey_to_address(pub)
    print(address)
    signing_tx = signature_form(tx, i, address_to_script(address), hashcode)
    sig = ecdsa_tx_sign(signing_tx, priv, hashcode)
    txobj = deserialize(tx)
    txobj["ins"][i]["script"] = serialize_script([bytes.fromhex(sig), bytes.fromhex(pub)])
    return serialize(txobj)



#priv = '57c617d9b4e1f7af6ec97ca2ff57e94a28279a7eedd4d12a99fa11170e94f5a4'
#h = [{'output': u'97f7c7d8ac85e40c255f8a763b6cd9a68f3a94d2e93e8bfa08f977b92e55465e:0', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}]
##, {'output': u'4cc806bb04f730c445c60b3e0f4f44b54769a1c196ca37d8d4002135e4abd171:1', 'value': 50000, 'address': u'1CQLd3bhw4EzaURHbKCwM5YZbUQfA4ReY6'}]
#outs = [{'value': 90000, 'address': u'16iw1MQ1sy1DtRPYw3ao1bCamoyBJtRB4t'}]



#	  {
#	    "txid": "920e7a6ecb3387ec39ca231ba76c6e42c945fdddf257138af23d8220bfefe0ff",
#	    "vout": 0,
#	    "address": "yYicJq1HyiZeMXRu6CeNYwPgPcqoWhNLVf",
#	    "account": "pingpong2",
#	    "scriptPubKey": "76a9148802f8f921f2ff5399001bc430c6dfd5d31182af88ac",
#	    "amount": 5.00000000,
#	    "confirmations": 17537,
#	    "spendable": true
#	  }
#	]
#	yYicJq1HyiZeMXRu6CeNYwPgPcqoWhNLVf cVgmh3zFLPVXpdxi473SMmxmfbFJuN4S7pvgAn7m7y9ci4upr19H
#	yUq9EziPwC7rWnAEt5r4ij4QBj6L6zpbDZ

priv_wif = 'cVgmh3zFLPVXpdxi473SMmxmfbFJuN4S7pvgAn7m7y9ci4upr19H'
priv = wif_to_privkey(priv_wif).get('privkey')
h =  [{'output': u'920e7a6ecb3387ec39ca231ba76c6e42c945fdddf257138af23d8220bfefe0ff:0', 'value': 500000000, 'address': u'yYicJq1HyiZeMXRu6CeNYwPgPcqoWhNLVf'}]
outs = [{'value': 499999999, 'address': u'yUq9EziPwC7rWnAEt5r4ij4QBj6L6zpbDZ'}]
tx = mktx(h,outs)
tx2 = sign(tx,0,priv)
#tx3 = sign(tx2,1,priv)
print(tx2)

#	
#	coind@test-01:~ $ dash-cli sendrawtransaction 0100000001ffe0efbf20823df28a1357f2ddfd45c9426e6ca71b23ca39ec8733cb6e7a0e92000000006a47304402201bae21b75f387b234fe27f066bedf54c43534be86ccec956487160c6dddaae1d02203eb8aa7a211e34448ebddd1d0cbc0f0b1b83b03561ab88e93b532dc1318bd2f00121021cc7408bda0048f525f79d619fb08631ade2dcdef21d3ed30a2457b82bd839e0ffffffff01ff64cd1d000000001976a9145d5ec99b2495a3bb1545a07db82a2b630e6b121288ac00000000
#	7799189191772f3d6c52bce79ee1b80859420817af73f9feefcf122e7021e442
#	
#	{
#	  "hex": "0100000001ffe0efbf20823df28a1357f2ddfd45c9426e6ca71b23ca39ec8733cb6e7a0e92000000006a47304402201bae21b75f387b234fe27f066bedf54c43534be86ccec956487160c6dddaae1d02203eb8aa7a211e34448ebddd1d0cbc0f0b1b83b03561ab88e93b532dc1318bd2f00121021cc7408bda0048f525f79d619fb08631ade2dcdef21d3ed30a2457b82bd839e0ffffffff01ff64cd1d000000001976a9145d5ec99b2495a3bb1545a07db82a2b630e6b121288ac00000000",
#	  "txid": "7799189191772f3d6c52bce79ee1b80859420817af73f9feefcf122e7021e442",
#	  "size": 191,
#	  "version": 1,
#	  "locktime": 0,
#	  "vin": [
#	    {
#	      "txid": "920e7a6ecb3387ec39ca231ba76c6e42c945fdddf257138af23d8220bfefe0ff",
#	      "vout": 0,
#	      "scriptSig": {
#	        "asm": "304402201bae21b75f387b234fe27f066bedf54c43534be86ccec956487160c6dddaae1d02203eb8aa7a211e34448ebddd1d0cbc0f0b1b83b03561ab88e93b532dc1318bd2f0[ALL] 021cc7408bda0048f525f79d619fb08631ade2dcdef21d3ed30a2457b82bd839e0",
#	        "hex": "47304402201bae21b75f387b234fe27f066bedf54c43534be86ccec956487160c6dddaae1d02203eb8aa7a211e34448ebddd1d0cbc0f0b1b83b03561ab88e93b532dc1318bd2f00121021cc7408bda0048f525f79d619fb08631ade2dcdef21d3ed30a2457b82bd839e0"
#	      },
#	      "sequence": 4294967295
#	    }
#	  ],
#	  "vout": [
#	    {
#	      "value": 4.99999999,
#	      "valueSat": 499999999,
#	      "n": 0,
#	      "scriptPubKey": {
#	        "asm": "OP_DUP OP_HASH160 5d5ec99b2495a3bb1545a07db82a2b630e6b1212 OP_EQUALVERIFY OP_CHECKSIG",
#	        "hex": "76a9145d5ec99b2495a3bb1545a07db82a2b630e6b121288ac",
#	        "reqSigs": 1,
#	        "type": "pubkeyhash",
#	        "addresses": [
#	          "yUq9EziPwC7rWnAEt5r4ij4QBj6L6zpbDZ"
#	        ]
#	      }
#	    }
#	  ],
#	  "blockhash": "00000034214987418dab53f2664880046460ccb8c6e154ff0dfd16e8cc270263",
#	  "height": 123611,
#	  "confirmations": 2,
#	  "time": 1482441278,
#	  "blocktime": 1482441278
#	}
#	
#	

