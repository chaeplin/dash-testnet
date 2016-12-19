#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.config import *
from lib.b58 import *
from lib.hashs import *
from lib.jacobian import *
from lib.keys import *
from lib.utils import *

pkey = get_random_key()
#private_key = pkey['privkey']
#decoded_private_key = pkey['privkey_decoded']
private_key = pkey.get('privkey')
decoded_private_key = pkey.get('privkey_decoded')


print ("Private Key (hex) is            : ", private_key)
print ("Private Key (decimal) is        : ", decoded_private_key)

wif_encoded_private_key = private_key_to_wif(private_key)
print ("Private Key (WIF) is            : ", wif_encoded_private_key)

wif_compressed_private_key = private_key_to_wif(private_key, True)
print ("Private Key (WIF-Compressed) is : ", wif_compressed_private_key)

pubkeyhex = get_public_key(private_key)
pubkey_hexencode     = pubkeyhex.get('pubkeyhex')
pubkey_hexcompressed = pubkeyhex.get('pubkeyhex_compressed')

print ("Public Key (hex) is             : ", pubkey_hexencode)
print ("Compressed Public Key (hex) is  : ", pubkey_hexcompressed)

print ("(t)DASH Address is              : ", pubkey_to_address(pubkey_hexencode))
print ("Compressed (t)DASH Address is   : ", pubkey_to_address(pubkey_hexcompressed))

print(wif_to_privkey(wif_encoded_private_key))
print(wif_to_privkey(wif_compressed_private_key))
