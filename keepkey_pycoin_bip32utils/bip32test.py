#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# https://github.com/chaeplin/bip32utils

from bip32utils import BIP32Key

def process_address(desc, address):
    print(desc, address)
    return None

def process_chain(desc, chain_node):
    i = 0
    g = 0
    while True:
        desci = '%s%d' % (desc, i)
        addr_node = chain_node.ChildKey(i)
        address = addr_node.Address()
        if process_address(desci, address):
            g = 0
        else:
            g += 1
        if g > gap:
            break
        i += 1

xpub = 'tpubDF8GkupYdvTQrsuL6HkCmpSJ7oENkKk9k7cRFuHQWrxca25pSBTq594ZebPxvwzQAdspYh5rd1nKz94TBhP4F2N1SqxqREk4ojXEQYCaYem'

addresses = []
gap = 10
acc_node = BIP32Key.fromExtendedKey(xpub)
process_chain('m/', acc_node)

#	./bip32test.py 
#	m/0 yVUfEs2mdTrVsVRLZg9LoCp8sNBGc3p4FV
#	m/1 yfj8WoDP8sJNFSH8vr5pEEsQ8vZ2hCHped
#	m/2 yNXtJuijSCNPCbLZbcLHwZoUaD4RzMo19P
#	m/3 yQNVQdYosUHkk4wUjxzbLFEXfGqyGJXzXC
#	m/4 yTH5axsQ3X8YBiiEKPVY66n9choyEodcKC
#	m/5 yNAihSEJQH2hSbnUKRGWcn7LYij56VKPCP
#	m/6 yicVWrfJYDFAxUwTbdQnWjTjhre5dx4HBg
#	m/7 ySD94FvVzTtYNFmwirK4qE4jhtxjrVsoJ9
#	m/8 yRkY4zL4kJr7H7QqMtfDhNtxCeqU2uTqth
#	m/9 yQNwssFrbo2CtBrBCHt9D3ttaNLK6xDf7C
#	m/10 yPEuaemjx5TBnvQrpEKavrcb8MnL4XGRCA


#	
#	
#	ku -s0-10 -a --override-network tDASH tpubDF8GkupYdvTQrsuL6HkCmpSJ7oENkKk9k7cRFuHQWrxca25pSBTq594ZebPxvwzQAdspYh5rd1nKz94TBhP4F2N1SqxqREk4ojXEQYCaYem
#	yVUfEs2mdTrVsVRLZg9LoCp8sNBGc3p4FV
#	yfj8WoDP8sJNFSH8vr5pEEsQ8vZ2hCHped
#	yNXtJuijSCNPCbLZbcLHwZoUaD4RzMo19P 
#	yQNVQdYosUHkk4wUjxzbLFEXfGqyGJXzXC
#	yTH5axsQ3X8YBiiEKPVY66n9choyEodcKC
#	yNAihSEJQH2hSbnUKRGWcn7LYij56VKPCP
#	yicVWrfJYDFAxUwTbdQnWjTjhre5dx4HBg
#	ySD94FvVzTtYNFmwirK4qE4jhtxjrVsoJ9
#	yRkY4zL4kJr7H7QqMtfDhNtxCeqU2uTqth
#	yQNwssFrbo2CtBrBCHt9D3ttaNLK6xDf7C
#	yPEuaemjx5TBnvQrpEKavrcb8MnL4XGRCA
#	
#	
