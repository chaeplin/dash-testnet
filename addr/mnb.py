#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# code from https://github.com/dashpay/electrum-dash


import sys
import hmac
import time
import hashlib
from lib.config import *
from lib.b58 import *
from lib.hashs import *
from lib.jacobian import *
from lib.keys import *
from lib.utils import *


_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))

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

def msg_magic(message):
    varint = num_to_varint(len(message)).hex()
    encoded_varint = "".join([chr(int(varint[i:i+2], 16)) for i in range(0, len(varint), 2)])
    return _b('\x19DarkCoin Signed Message:\n' + encoded_varint + message)


tx = '27c7c43cfde0943d2397b9fd5106d0a1f6927074a5fa6dfcf7fe50a2cb6b8d10'
prevout_n = 0
scriptSig = ''
sequence = 4294967295
ip = '192.168.1.101'
port = 19999
protocol_version = 70204
ipv6map = '00000000000000000000ffff'
collateral_key = '038ae57bd0fa5b45640e771614ec571c7326a2266c78bb444f1971c85188411ba1'
delegate_key   = '02526201c87c1b4630aabbd04572eec3e2545e442503e57e60880fafcc1f684dbc'

collateral_wif = 'XJqCcyfnLYK4Y7ZDVjLrgPnsrq2cWMF6MX9cyhKgfMajwqrCwZaS'
delegate_wif   = 'XCbhXBc2N9q8kxqBF41rSuLWVpVVbDm7P1oPv9GxcrS9QXYBWZkB'
#sig_time = int(time.time())
sig_time = 1461858375
block_hash ='ff'*32
last_dsq = 0


vintx  = bytes.fromhex(tx)[::-1].hex()                                                  # vds.write(hash_decode(vin['prevout_hash']))
vinno  = prevout_n.to_bytes(4, byteorder='big')[::-1].hex()                             # vds.write_uint32(vin['prevout_n'])
vinsig = num_to_varint(len(scriptSig)/2).hex() + bytes.fromhex(scriptSig)[::-1].hex()   # vds.write_string(vin['scriptSig'])
vinseq = sequence.to_bytes(4, byteorder='big')[::-1].hex()                              # vds.write_uint32(vin['sequence'])

ipdigit = map(int, ip.split('.'))
for i in ipdigit:    
    ipv6map  += i.to_bytes(1, byteorder='big')[::-1].hex()                              # vds.write_uchar(i)
ipv6map += port.to_bytes(2, byteorder='big').hex()                                      # vds._write_num('>H', self.port)

collateral_in = num_to_varint(len(collateral_key)/2).hex() + collateral_key             # vds.write_string(self.collateral_key.decode('hex'))
delegate_in = num_to_varint(len(delegate_key)/2).hex() + delegate_key                   # vds.write_string(self.delegate_key.decode('hex'))


serialize_for_sig = str(ip) + str(':') + str(port) + str(sig_time) + format_hash(Hash160(bytes.fromhex(collateral_key))) + format_hash(Hash160(bytes.fromhex(delegate_key))) + str(protocol_version)

collateral_privkey = wif_to_privkey(collateral_wif)['privkey']
print('collateral_privkey --> ', collateral_privkey)
m_magic = double_sha256(msg_magic(serialize_for_sig)).hex()
print('serialize_for_sig ', (msg_magic(serialize_for_sig)))
print('serialize_for_sig ', m_magic)


sig = '1f005462665e8b2374ab175341f94711c2b0b1eec4af62459afa5a2320314d5ad445b9b18ebcab8fe8d77ac6dd8706bff43eecb08e81f6e24c00a84788347cc342'
#print('sig ---> ', binascii.hexlify(sign_msg))
# vds.write_string(self.sig)

work_sig_time     = sig_time.to_bytes(8, byteorder='big')[::-1].hex()                       # vds.write_int64(self.sig_time)
work_protoversion = protocol_version.to_bytes(4, byteorder='big')[::-1].hex()               # vds.write_uint32(self.protocol_version)

last_ping  = bytes.fromhex(tx)[::-1].hex()                                                  # vds.write(hash_decode(vin['prevout_hash']))
last_ping += prevout_n.to_bytes(4, byteorder='big')[::-1].hex()                             # vds.write_uint32(vin['prevout_n'])
last_ping += num_to_varint(len(scriptSig)/2).hex() + bytes.fromhex(scriptSig)[::-1].hex()   # vds.write_string(vin['scriptSig'])
last_ping += sequence.to_bytes(4, byteorder='big')[::-1].hex()                              # vds.write_uint32(vin['sequence'])

last_ping += bytes.fromhex(block_hash)[::-1].hex()                                          # vds.write(hash_decode(self.block_hash))
last_ping += sig_time.to_bytes(8, byteorder='big')[::-1].hex()                              # vds.write_int64(self.sig_time)
last_dsq   = last_dsq.to_bytes(8, byteorder='big')[::-1].hex() 

last_ping_serialize_for_sig  = serialize_input_str(tx, prevout_n, sequence, scriptSig) + block_hash + str(sig_time)
delegate_privkey = wif_to_privkey(delegate_wif)['privkey']
print('delegate_privkey --> ', delegate_privkey)


print('last_ping_serialize_for_sig -->', last_ping_serialize_for_sig)

sig2 = '2042cef2f348ab6113389bce5ad6188b6136d9f58edbf85f4b48a7b5f9a36c95627c98f1bea2ef2240583b0964a0e508d715c16a3eb32deb7d7042f2f54704b08c'


work = vintx + vinno + vinsig + vinseq + ipv6map + collateral_in + delegate_in + num_to_varint(len(sig)/2).hex() + sig + work_sig_time + work_protoversion \
     + last_ping + num_to_varint(len(sig2)/2).hex() + sig2 + last_dsq


# dash-cli signmessage XahPxwmCuKjPq69hzVxP18V1eASwDWbUrn "192.168.1.101:19999146185837525913ac39695a6841b8c0e72e12f6b20add21a00bbde3f9b13d625c37da38453d8b3c082802120ea70204"
# HwBUYmZeiyN0qxdTQflHEcKwse7Er2JFmvpaIyAxTVrURbmxjryrj+jXesbdhwa/9D7ssI6B9uJMAKhHiDR8w0I=

# dash-cli signmessage Xx2nSdhaT7c9SREKBPAgzpkhu518XFgkgh "CTxIn(COutPoint(27c7c43cfde0943d2397b9fd5106d0a1f6927074a5fa6dfcf7fe50a2cb6b8d10, 0), scriptSig=)ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1461858375"
# IELO8vNIq2ETOJvOWtYYi2E22fWO2/hfS0intfmjbJVifJjxvqLvIkBYOwlkoOUI1xXBaj6zLet9cELy9UcEsIw=

#(venv2) pluto@chaeplins-MacBook-Pro:~/study/electrum-dash/lib $ python test_masternode.py 
#('s --> ', 'CTxIn(COutPoint(27c7c43cfde0943d2397b9fd5106d0a1f6927074a5fa6dfcf7fe50a2cb6b8d10, 0), scriptSig=)')
#('serialized -> ', 'CTxIn(COutPoint(27c7c43cfde0943d2397b9fd5106d0a1f6927074a5fa6dfcf7fe50a2cb6b8d10, 0), scriptSig=)ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1461858375')
#{'addr': {'ip': '192.168.1.101', 'port': 19999},
# 'alias': '',
# 'announced': False,
# 'collateral_key': '038ae57bd0fa5b45640e771614ec571c7326a2266c78bb444f1971c85188411ba1',
# 'delegate_key': '02526201c87c1b4630aabbd04572eec3e2545e442503e57e60880fafcc1f684dbc',
# 'last_dsq': 0,
# 'last_ping': {'block_hash': 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
#               'sig': 'IELO8vNIq2ETOJvOWtYYi2E22fWO2/hfS0intfmjbJVifJjxvqLvIkBYOwlkoOUI1xXBaj6zLet9cELy9UcEsIw=',
#               'sig_time': 1461858375,
#               'vin': {'prevout_hash': '27c7c43cfde0943d2397b9fd5106d0a1f6927074a5fa6dfcf7fe50a2cb6b8d10',
#                       'prevout_n': 0,
#                       'scriptSig': '',
#                       'sequence': 4294967295}},
# 'protocol_version': 70204,
# 'sig': 'HwBUYmZeiyN0qxdTQflHEcKwse7Er2JFmvpaIyAxTVrURbmxjryrj+jXesbdhwa/9D7ssI6B9uJMAKhHiDR8w0I=',
# 'sig_time': 1461858375,
# 'vin': {'prevout_hash': '27c7c43cfde0943d2397b9fd5106d0a1f6927074a5fa6dfcf7fe50a2cb6b8d10',
#         'prevout_n': 0,
#         'scriptSig': '',
#         'sequence': 4294967295}}
# - sig follows - 
#HwBUYmZeiyN0qxdTQflHEcKwse7Er2JFmvpaIyAxTVrURbmxjryrj+jXesbdhwa/9D7ssI6B9uJMAKhHiDR8w0I=
#108d6bcba250fef7fc6dfaa5747092f6a1d00651fdb997233d94e0fd3cc4c7270000000000ffffffff00000000000000000000ffffc0a801654e1f21038ae57bd0fa5b45640e771614ec571c7326a2266c78bb444f1971c85188411ba12102526201c87c1b4630aabbd04572eec3e2545e442503e57e60880fafcc1f684dbc411f005462665e8b2374ab175341f94711c2b0b1eec4af62459afa5a2320314d5ad445b9b18ebcab8fe8d77ac6dd8706bff43eecb08e81f6e24c00a84788347cc34247302257000000003c120100108d6bcba250fef7fc6dfaa5747092f6a1d00651fdb997233d94e0fd3cc4c7270000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4730225700000000412042cef2f348ab6113389bce5ad6188b6136d9f58edbf85f4b48a7b5f9a36c95627c98f1bea2ef2240583b0964a0e508d715c16a3eb32deb7d7042f2f54704b08c0000000000000000
#()
#()
#

print(work)

