#!/usr/bin/env python2

from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_hid import HidTransport
import keepkeylib.ckd_public as bip32


def main():
    # List all connected KeepKeys on USB
    devices = HidTransport.enumerate()

    # Check whether we found any
    if len(devices) == 0:
        print('No KeepKey found')
        return

    # Use first connected device
    transport = HidTransport(devices[0])

    # Creates object for manipulating KeepKey
    client = KeepKeyClient(transport)

    # Print out KeepKey's features and settings
    print(client.features)

    # Get the first address of first BIP44 account
    # (should be the same address as shown in KeepKey wallet Chrome extension)
    mpath = "44'/0'/0'/0"
    bip32_path = client.expand_path(mpath)

    print bip32.serialize(client.get_public_node(bip32_path).node, 0x043587CF)

    for i in range(11):
        child_path = '%s%s' % ("44'/0'/0'/0/", str(i))
        address = client.get_address('tDash', client.expand_path(child_path))
        print 'tDASH address:', child_path, address

    client.close()

if __name__ == '__main__':
    main()


#	tpubDF8GkupYdvTQrsuL6HkCmpSJ7oENkKk9k7cRFuHQWrxca25pSBTq594ZebPxvwzQAdspYh5rd1nKz94TBhP4F2N1SqxqREk4ojXEQYCaYem
#	tDASH address: 44'/0'/0'/0/0 yVUfEs2mdTrVsVRLZg9LoCp8sNBGc3p4FV
#	tDASH address: 44'/0'/0'/0/1 yfj8WoDP8sJNFSH8vr5pEEsQ8vZ2hCHped
#	tDASH address: 44'/0'/0'/0/2 yNXtJuijSCNPCbLZbcLHwZoUaD4RzMo19P
#	tDASH address: 44'/0'/0'/0/3 yQNVQdYosUHkk4wUjxzbLFEXfGqyGJXzXC
#	tDASH address: 44'/0'/0'/0/4 yTH5axsQ3X8YBiiEKPVY66n9choyEodcKC
#	tDASH address: 44'/0'/0'/0/5 yNAihSEJQH2hSbnUKRGWcn7LYij56VKPCP
#	tDASH address: 44'/0'/0'/0/6 yicVWrfJYDFAxUwTbdQnWjTjhre5dx4HBg
#	tDASH address: 44'/0'/0'/0/7 ySD94FvVzTtYNFmwirK4qE4jhtxjrVsoJ9
#	tDASH address: 44'/0'/0'/0/8 yRkY4zL4kJr7H7QqMtfDhNtxCeqU2uTqth
#	tDASH address: 44'/0'/0'/0/9 yQNwssFrbo2CtBrBCHt9D3ttaNLK6xDf7C
#	tDASH address: 44'/0'/0'/0/10 yPEuaemjx5TBnvQrpEKavrcb8MnL4XGRCA
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
