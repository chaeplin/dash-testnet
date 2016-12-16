#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import binascii
import hashlib
import re
import sys
import os
import random
import time

# Elliptic curve parameters (secp256k1)

P = 2**256 - 2**32 - 977
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)

long = int
_bchr = lambda x: bytes([x])
_bord = lambda x: x

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

def private_key_to_wif(string):
    prv = binascii.unhexlify(string)
    vs = _bchr(wif_prefix) + prv                                                      # change this
    check = hashlib.sha256(hashlib.sha256(vs).digest()).digest()[0:4]
    return b58encode(vs + check)

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

def Hash160(msg):
    return hashlib.new('ripemd160', hashlib.sha256(msg).digest()).digest()

def pubkey_to_address(string):
    data = binascii.unhexlify(string)
    data_hash = Hash160(data)
    vs = _bchr(addr_frefix) + data_hash                                               # change this
    check = double_sha256(vs)[0:4]
    return b58encode(vs + check)

def decode_hexto_int(string):
    return int.from_bytes(bytes.fromhex(string), byteorder='big')

def bin_sha256(string):
    binary_data = string if isinstance(string, bytes) else bytes(string, 'utf-8')
    return hashlib.sha256(binary_data).digest()

def sha256(string):
    return bin_sha256(string).hex()

def random_string(x):
    return str(os.urandom(x))

def random_key():
    entropy = random_string(32) \
        + str(random.randrange(2**256)) \
        + str(int(time.time() * 1000000))
    return sha256(entropy)


# private to public key x, y
def inv(a, n):
    if a == 0:
        return 0
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high//low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def to_jacobian(p):
    o = (p[0], p[1], 1)
    return o

def jacobian_double(p):
    if not p[1]:
        return (0, 0, 0)
    ysq = (p[1] ** 2) % P
    S = (4 * p[0] * ysq) % P
    M = (3 * p[0] ** 2 + A * p[2] ** 4) % P
    nx = (M**2 - 2 * S) % P
    ny = (M * (S - nx) - 8 * ysq ** 2) % P
    nz = (2 * p[1] * p[2]) % P
    return (nx, ny, nz)

def jacobian_add(p, q):
    if not p[1]:
        return q
    if not q[1]:
        return p
    U1 = (p[0] * q[2] ** 2) % P
    U2 = (q[0] * p[2] ** 2) % P
    S1 = (p[1] * q[2] ** 3) % P
    S2 = (q[1] * p[2] ** 3) % P
    if U1 == U2:
        if S1 != S2:
            return (0, 0, 1)
        return jacobian_double(p)
    H = U2 - U1
    R = S2 - S1
    H2 = (H * H) % P
    H3 = (H * H2) % P
    U1H2 = (U1 * H2) % P
    nx = (R ** 2 - H3 - 2 * U1H2) % P
    ny = (R * (U1H2 - nx) - S1 * H3) % P
    nz = (H * p[2] * q[2]) % P
    return (nx, ny, nz)

def from_jacobian(p):
    z = inv(p[2], P)
    return ((p[0] * z**2) % P, (p[1] * z**3) % P)

def jacobian_multiply(a, n):
    if a[1] == 0 or n == 0:
        return (0, 0, 1)
    if n == 1:
        return a
    if n < 0 or n >= N:
        return jacobian_multiply(a, n % N)
    if (n % 2) == 0:
        return jacobian_double(jacobian_multiply(a, n//2))
    if (n % 2) == 1:
        return jacobian_add(jacobian_double(jacobian_multiply(a, n//2)), a)

def fast_multiply(a, n):
    return from_jacobian(jacobian_multiply(to_jacobian(a), n))


#-----------
# dash testnet
wif_prefix  = 239 # ef
addr_frefix = 140 # 8c

#-----------
valid_private_key = False
while not valid_private_key:    
    private_key = random_key()
    decoded_private_key = decode_hexto_int(private_key)
    valid_private_key =  0 < decoded_private_key < N    


print ("Private Key (hex) is: ", private_key)
print ("Private Key (decimal) is: ", decoded_private_key)


# wif
# bitcoin 
# https://en.bitcoin.it/wiki/List_of_address_prefixes

# https://github.com/bitcoin/bitcoin/blob/master/src/chainparams.cpp
#       main
#        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);  
#        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
#        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);    / hex 80
#       test
#        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);    / hex 6f
#        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);    / hex c4
#        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);    / hex ef

# dash
#        main
#        // Dash addresses start with 'X'
#        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,76);     / hex 4c
#        // Dash script addresses start with '7'
#        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,16);     / hex 10
#        // Dash private keys start with '7' or 'X'
#        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,204);    / hex cc
#
#        test
#        // Testnet Dash addresses start with 'y'
#        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,140);    / hex 8c
#        // Testnet Dash script addresses start with '8' or '9'
#        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,19);     / hex 13
#        // Testnet private keys start with '9' or 'c' (Bitcoin defaults)
#        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);    / hex ef

# https://en.bitcoin.it/wiki/Wallet_import_format
#Private key to WIF
#1 - Take a private key
#
#   0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
#   
#2 - Add a 0x80 byte in front of it for mainnet addresses or 0xef for testnet addresses. Also add a 0x01 byte at the end if the private key will correspond to a compressed public key
#
#   800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
#
#3 - Perform SHA-256 hash on the extended key
#
#   8147786C4D15106333BF278D71DADAF1079EF2D2440A4DDE37D747DED5403592
#
#4 - Perform SHA-256 hash on result of SHA-256 hash
#
#   507A5B8DFED0FC6FE8801743720CEDEC06AA5C6FCA72B07C49964492FB98A714
#
#5 - Take the first 4 bytes of the second SHA-256 hash, this is the checksum
#
#   507A5B8D
#
#6 - Add the 4 checksum bytes from point 5 at the end of the extended key from point 2
#
#   800C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D507A5B8D
#
#7 - Convert the result from a byte string into a base58 string using Base58Check encoding. This is the Wallet Import Format
#
#   5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ


# Convert private key to WIF format
wif_encoded_private_key = private_key_to_wif(private_key)
print ("Private Key (WIF) is: ", wif_encoded_private_key)

# Add suffix "01" to indicate a compressed private key
compressed_private_key = private_key + '01'
print ("Private Key Compressed (hex) is: ", compressed_private_key)

# Generate a WIF format from the compressed private key (WIF-compressed)
wif_compressed_private_key = private_key_to_wif(compressed_private_key)
print ("Private Key (WIF-Compressed) is: ", wif_compressed_private_key)


# Multiply the EC generator point G with the private key to get a public key point
public_key = fast_multiply(G, decoded_private_key)
print ("Public Key (x,y) coordinates is:", public_key)

hex_encoded_public_key = str('04') + public_key[0].to_bytes(32, byteorder='big').hex() + public_key[1].to_bytes(32, byteorder='big').hex()
print ("Public Key (hex) is:", hex_encoded_public_key)

# Compress public key, adjust prefix depending on whether y is even or odd
(public_key_x, public_key_y) = public_key
if (public_key_y % 2) == 0:
    compressed_prefix = '02'
else:
    compressed_prefix = '03'

hex_compressed_public_key = compressed_prefix + public_key_x.to_bytes(32, byteorder='big').hex()
print ("Compressed Public Key (hex) is:", hex_compressed_public_key)

# Generate tDASH address from public key
print ("tDASH Address (b58check) is:", pubkey_to_address(hex_encoded_public_key))

# Generate compressed tDASH address from compressed public key
print ("Compressed tDASH Address (b58check) is:", pubkey_to_address(hex_compressed_public_key))

#	
#	Private Key (hex) is:  62e152a6ffe0b4623c4a0fe097859f6d0d50f61270907fe961c3b9e1909f2ec4
#	Private Key (decimal) is:  44724770196233898604153081485000244941381175354297438699147428606281768709828
#	Private Key (WIF) is:  92LTvZqBcKhjSiK6w3fCjhSHMX9fAczah4X5gJNxrdY9SkZUXg3
#	Private Key Compressed (hex) is:  62e152a6ffe0b4623c4a0fe097859f6d0d50f61270907fe961c3b9e1909f2ec401
#	Private Key (WIF-Compressed) is:  cQtuqRufpuYnLVLuBYjcoTUbBa5DTTs9hpXmeThwY4GUGTxHbPnS
#	Public Key (x,y) coordinates is: (96974679951959421656962823309243205475551126146257011380254819152693633063336, 50666834470836710413443421124703001996138841159257764920179902198473153950113)
#	Public Key (hex) is: 04d665b94963348cd992adbab123f2445dbf42a64cbf1994eb22b0c7cec68599a87004697c8d071e6bb38e1a28bd39af0e6da9d07f2661eb5e367936ba7329b1a1
#	Compressed Public Key (hex) is: 03d665b94963348cd992adbab123f2445dbf42a64cbf1994eb22b0c7cec68599a8
#	Bitcoin Address (b58check) is: yNhTMTwym3q9Djq2SrdSCZQQFr79FUAMnR
#	Compressed Bitcoin Address (b58check) is: yMjYHX4RuudHZ1rvd7eg2eH4EMY6Hbb3E1
#	
#	# using ku
#	(venv3) $ ku --override-network tDASH 92LTvZqBcKhjSiK6w3fCjhSHMX9fAczah4X5gJNxrdY9SkZUXg3
#	input                     : 92LTvZqBcKhjSiK6w3fCjhSHMX9fAczah4X5gJNxrdY9SkZUXg3
#	network                   : Dash testnet
#	netcode                   : tDASH
#	secret exponent           : 44724770196233898604153081485000244941381175354297438699147428606281768709828
#	 hex                      : 62e152a6ffe0b4623c4a0fe097859f6d0d50f61270907fe961c3b9e1909f2ec4
#	wif                       : cQtuqRufpuYnLVLuBYjcoTUbBa5DTTs9hpXmeThwY4GUGTxHbPnS
#	 uncompressed             : 92LTvZqBcKhjSiK6w3fCjhSHMX9fAczah4X5gJNxrdY9SkZUXg3
#	public pair x             : 96974679951959421656962823309243205475551126146257011380254819152693633063336
#	public pair y             : 50666834470836710413443421124703001996138841159257764920179902198473153950113
#	 x as hex                 : d665b94963348cd992adbab123f2445dbf42a64cbf1994eb22b0c7cec68599a8
#	 y as hex                 : 7004697c8d071e6bb38e1a28bd39af0e6da9d07f2661eb5e367936ba7329b1a1
#	y parity                  : odd
#	key pair as sec           : 03d665b94963348cd992adbab123f2445dbf42a64cbf1994eb22b0c7cec68599a8
#	 uncompressed             : 04d665b94963348cd992adbab123f2445dbf42a64cbf1994eb22b0c7cec68599a8\
#	                              7004697c8d071e6bb38e1a28bd39af0e6da9d07f2661eb5e367936ba7329b1a1
#	hash160                   : 0f86a5a2ba85580fb3499507e208191b92781f2b
#	 uncompressed             : 1a19d2e9f101b4bdc888baf29f597bbe416086b1
#	Dash address              : yMjYHX4RuudHZ1rvd7eg2eH4EMY6Hbb3E1
#	Dash address uncompressed : yNhTMTwym3q9Djq2SrdSCZQQFr79FUAMnR
#	
