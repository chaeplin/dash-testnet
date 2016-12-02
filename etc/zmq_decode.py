#!/usr/bin/env python3

"""
http://codesuppository.blogspot.kr/2014/01/how-to-parse-bitcoin-blockchain.html
Output Section : O3 : Output Script : length bytes

This is where the magic sauce happens.  Even though we don't have to execute the script to validate it, we do need to inspect the script to figure out where the output goes.

The public key in the output script will be stored in one of two forms.  Either as the full 65 byte public key or as the 20 byte hash of the public key.  
Early on most public keys were stored as 65 bytes but, later, the vast majority of all transactions store the public key in the 20 byte form both to save memory and for added security.

You can learn more about bitcoin public key addresses by looking at these links.

ECDSA key (Elliptic Curve Digital Signature)

https://en.bitcoin.it/wiki/ECDSA

http://en.wikipedia.org/wiki/Elliptic_Curve_DSA

You can decipher the public key for almost all of the outputs in one of the following few forms without necessarily having to write a full script interpreter.  
These usage patterns appear to be able to decode essentially every single valid public key address in the entire blockchain.  
There is a chance that scripts could change in form or be more complicated in the future, but for now these seem sufficient.



Format 1 : 67 byte long output script containing a full  ECDSA 65 byte public key address.

If you see an output script with a length of 67 bytes, the first byte is equal to 65 (indicating the length of the public key which follows), 
the next 65 bytes after the first byte are the public key, and the 67th byte (array index 66) is equal to 0xAC (172) which is the 'CHECKSIG' opcode.

Script[0] =65 : Length of the public key to follow
Script[1-65]=The public key data
Script[66]=OP_CHECKSIG (0xAC)



Format 2 : 66 byte long output script.  Contains a 65 byte public key address.

This script I believe is technically invalid.  The 'length' field is missing, which is required for a valid script to execute.  
Nevertheless, this usage pattern does appear in the blockchain and is properly interpreted by a number of applications, so we need to accept it as well.  
This is in the same as format 1 except the first byte, the length field, is missing.  
In this use case the 66 byte long script begins with 65 bytes of the public key followed by the CHECKSIG opcode of 0xAC.

Script[0-64]=The public key address
Script[65]=OP_CHECKSIG (0xAC)



Fomat 3 : Script is 25 bytes long or more, contains a 20 byte public key hash address.  This is the most common format of the vast majority of all output scripts.

The early blocks in the block chain will be in format #1 and format #2 but, after a while, most of the scripts will be in this form.  
hey will be 25 bytes or more long and begin with the following pattern.

Script[0] = OP_DUP (0x76)
Script[1] =OP_HASH160 (0xA9)
Script[2] =20 (The length of the public key hash address which follows)
Script[3-24] = The 20 byte public key address.



Format 4 : Script is 5 bytes long and contains no public key.

This script is in error.  It is invalid and represents an unspendable address.  It is documented here, however, because it does show up in the blockchain a number of times.

Script[0] = OP_DUP (0x76)
Script[1] = OP_HASH160 (0xA9)
Script[2] =0 (A length of zero, not valid!)
Script[3]=OP_EQUALVERIFY (0x88)
Script[4]=OP_CHECKSIG (0xAC)



Format 5 : If the script doesn't readily match any of the previous patterns, then you can search for it by scanning the output script for the following pattern.

Look for any place in the script where this pattern shows up:

Script[0] = OP_DUP (0x76)
Script[1] = OP_HASH160 (0xA9)
Script[2] =20 (A length value equal to the size of a public key hash)
Script[3-22]=The 20 byte public key address
Script[23]=OP_EQUALVERIFY (0x88)
Script[24]=OP_CHECKSIG (0xAC)

If you see this, then you have identified the public key for this output script.  In reality the vast majority of all output scripts will be in the form of format #3.

    txid : bde37839ebb507ba20e1965e6d57f6e0ef52f4d96e38d6d155c033c3810396df

    {
      "value": 11.25000000,
      "valueSat": 1125000000,
      "n": 0,
      "scriptPubKey": {
        "asm": "OP_DUP OP_HASH160 fd85adfcf0c5c6a3f671428a7bfa3944cb840305 OP_EQUALVERIFY OP_CHECKSIG",
        "hex": "76a914fd85adfcf0c5c6a3f671428a7bfa3944cb84030588ac",
        "reqSigs": 1,
        "type": "pubkeyhash",
        "addresses": [
          "yjRwwxf95GtmK41oEH9VDPdDCtV1Jczmip"
        ]
      }
    },
    {
      "value": 0.00000000,
      "valueSat": 0,
      "n": 2,
      "scriptPubKey": {
        "asm": "047559d13c3f81b1fadbd8dd03e4b5a1c73b05e2b980e00d467aa9440b29c7de23664dde6428d75cafed22ae4f0d302e26c5c5a5dd4d3e1b796d7281bdc9430f35 OP_CHECKSIG",
        "hex": "41047559d13c3f81b1fadbd8dd03e4b5a1c73b05e2b980e00d467aa9440b29c7de23664dde6428d75cafed22ae4f0d302e26c5c5a5dd4d3e1b796d7281bdc9430f35ac",
        "reqSigs": 1,
        "type": "pubkey",
        "addresses": [
          "yb21342iADyqAotjwcn4imqjvAcdYhnzeH"
        ]
      }
    }, 
    {
      "value": 0.00000000,
      "valueSat": 0,
      "n": 3,
      "scriptPubKey": {
        "asm": "OP_RETURN 1adb1bf4cef81ede4a63ad5ca5943e5288fffc210d90a861a60a96658d7f90580000000000000000",
        "hex": "6a281adb1bf4cef81ede4a63ad5ca5943e5288fffc210d90a861a60a96658d7f90580000000000000000",
        "type": "nulldata"
      }
    }


output
{
    "coinbase": {
        "addrfrom": "coinbase",
        "hashin": "0000000000000000000000000000000000000000000000000000000000000000-0"
    }
}
{
    "yWfAXGd4ZDgNxvX6tvAzg5VT6JYRCP6KMh": {
        "from": "coinbase",
        "hashin": "0000000000000000000000000000000000000000000000000000000000000000-0",
        "to": "yWfAXGd4ZDgNxvX6tvAzg5VT6JYRCP6KMh",
        "txid": "d354a114b9e60428b1be6c4d1094e183c09d47572b5a4606214929eb713f5704-1",
        "value": "11.25000000"
    },
    "yhF732jM8hA2e5svfBCa1heFbdHVNXdM8n": {
        "from": "coinbase",
        "hashin": "0000000000000000000000000000000000000000000000000000000000000000-0",
        "to": "yhF732jM8hA2e5svfBCa1heFbdHVNXdM8n",
        "txid": "d354a114b9e60428b1be6c4d1094e183c09d47572b5a4606214929eb713f5704-0",
        "value": "11.25000000"
    }
}
{
    "difficulty": 0.0026907021552222492,
    "hash": "00000091be3d7ca60f2846d9f42ae691a97e26486b875e982d066f7307ec1ae2",
    "merkleroot": "d354a114b9e60428b1be6c4d1094e183c09d47572b5a4606214929eb713f5704",
    "nonce": 1527106,
    "p_b_hash": "000001654e9926874e3079caab923ee263cafe96b83531de5169036a7248c789",
    "time": 1480698487,
    "txs": {
        "d354a114b9e60428b1be6c4d1094e183c09d47572b5a4606214929eb713f5704": "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0603acb7010101ffffffff0240230e4300000000232103717f7082f58395f02afb45b1ae871cae31293b33c64c8d9568d9cac09fa70c51ac40230e43000000001976a914716bf2ce0f307d25c580f4951cb8eaf436b08c4988ac00000000"
    },
    "version": 536870912
}



{
    "good": {
        "addrfrom": "yUafbVmjbEySWk5oDviQZLB8C2NfYBkv5u",
        "hashin": "4c027046072140ca5a25e1baf9aed14baa805e4d56fa02157f43608dbd8609f0-0"
    }
}
{
    "yPHiz6NV2zMzLSq9g2a1hBemGqVR45yY2T": {
        "from": "yUafbVmjbEySWk5oDviQZLB8C2NfYBkv5u",
        "hashin": "4c027046072140ca5a25e1baf9aed14baa805e4d56fa02157f43608dbd8609f0-0",
        "to": "yPHiz6NV2zMzLSq9g2a1hBemGqVR45yY2T",
        "txid": "7213f02c5a69ba436eed0fe9be00adfba733bbdbff795bc2b896a42c62f2bb5a-0",
        "value": "0.01473488"
    },
    "yfvtL8DkiPj8F1dmGJHd68tXiSBCxHG3E2": {
        "from": "yUafbVmjbEySWk5oDviQZLB8C2NfYBkv5u",
        "hashin": "4c027046072140ca5a25e1baf9aed14baa805e4d56fa02157f43608dbd8609f0-0",
        "to": "yfvtL8DkiPj8F1dmGJHd68tXiSBCxHG3E2",
        "txid": "7213f02c5a69ba436eed0fe9be00adfba733bbdbff795bc2b896a42c62f2bb5a-1",
        "value": "0.50000000"
    }
}

{
    "good": {
        "addrfrom": "ygLEauaZPgaw3e8p1oHD3Ujpj2V6JS6eoz",
        "hashin": "6a65379bc95bd4b2614d4b5528708db5c462ad27526a303a3b2916564df05f23-1"
    }
}
{
    "yYzEWuZGD7Ffzc1nV2GuGdPveFwFBzhybV": {
        "from": "ygLEauaZPgaw3e8p1oHD3Ujpj2V6JS6eoz",
        "hashin": "6a65379bc95bd4b2614d4b5528708db5c462ad27526a303a3b2916564df05f23-1",
        "to": "yYzEWuZGD7Ffzc1nV2GuGdPveFwFBzhybV",
        "txid": "64b8f8d168f8e536f540f0eea42c0c960c43058b8e18966f6c5e157e82f2ba2a-1",
        "value": "2.99800000"
    },
    "ycr5c8sdaLCbABqiPmSh8JvrX6pXUC1LSS": {
        "from": "ygLEauaZPgaw3e8p1oHD3Ujpj2V6JS6eoz",
        "hashin": "6a65379bc95bd4b2614d4b5528708db5c462ad27526a303a3b2916564df05f23-1",
        "to": "ycr5c8sdaLCbABqiPmSh8JvrX6pXUC1LSS",
        "txid": "64b8f8d168f8e536f540f0eea42c0c960c43058b8e18966f6c5e157e82f2ba2a-0",
        "value": "1.00000000"
    }
}


"""

import array
import binascii
import zmq
import struct
import hashlib
import io
import simplejson as json
import x11_hash
import sys
import re

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

    print(json.dumps(addrcheck, sort_keys=True, indent=4, separators=(',', ': ')))

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


#---------
port = 28332
zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtxlock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtxlock")
zmqSubSocket.connect("tcp://127.0.0.1:%i" % port)
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

        if topic == 'rawblock':
            x = decoderawblock(body)
            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))

        if topic == 'rawtxlock':
            x = decoderawblock(body)
            print(json.dumps(x, sort_keys=True, indent=4, separators=(',', ': ')))

except KeyboardInterrupt:
    zmqContext.destroy()


    