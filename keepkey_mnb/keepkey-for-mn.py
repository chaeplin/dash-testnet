#!/usr/bin/env python3

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
    # mpath = "44'/0'/0'/0"
    # default tDash path
    # mpath = "44'/165'/0'/0"
    # 1990 is seleted randomly
    mpath = "44'/165'/1990'/0"
    bip32_path = client.expand_path(mpath)

    # tpub to use 
    print('tpub --> ',bip32.serialize(client.get_public_node(bip32_path).node, 0x043587CF))

    for i in range(11):
        child_path = '%s%s' % (mpath + '/', str(i))
        address = client.get_address('tDash', client.expand_path(child_path))
        print ('tDASH address:', child_path, address)

   # client.close()
   # path test
    m2 = "44'/165'/1990'/0/0"
    m_path = client.expand_path(m2) 
    print(bip32.serialize(client.get_public_node(m_path).node, 0x043587CF))

    client.close()

if __name__ == '__main__':
    main()

#	
#	tpub -->  tpubDEiBemN1QNqgAMu41t2ojcbeib5YUrJ4Vtx4dUToo1Q6R5gseuY6acV3Y2Sh6xUBpbB982ehrJAUuActSwpq8VVG7xZjtcyjTCLawuLKhU4
#	tDASH address: 44'/165'/1990'/0/0 ydWWT8kCMij5LhMMGVzBDyXZ9j3ZPkkuiN
#	tDASH address: 44'/165'/1990'/0/1 yX1MJBGdmLWNkyh3bcSQLPj3a4aKbyPXs1
#	tDASH address: 44'/165'/1990'/0/2 yNEPZQQZdGeJYdqMjF2wL7SmRevFfJA3zC
#	tDASH address: 44'/165'/1990'/0/3 yamNx8kKSmgDfHKTapsRYWRJsJ952Hmocb
#	tDASH address: 44'/165'/1990'/0/4 yN2onpkv4LbDdUJ3LZNoX3t6GLFDnou92q
#	tDASH address: 44'/165'/1990'/0/5 yTm1GAf6fGNZ9nz1ribSSgSxiHEDQiFpCF
#	tDASH address: 44'/165'/1990'/0/6 yZEKBbMNz1P6KCuNnz5fVzCKuq679Cs73R
#	tDASH address: 44'/165'/1990'/0/7 yRCTeucwpnVaCiMBBL34fy5z6JZwanLu3x
#	tDASH address: 44'/165'/1990'/0/8 yLcRvYVmS5Jr2SDpsUpjsMViZ8R6LfeKMg
#	tDASH address: 44'/165'/1990'/0/9 ySvqywhEkr2rPhmWX48njZwjF9p9NBh17V
#	tDASH address: 44'/165'/1990'/0/10 yNbZz5nmqAxeWQYdHunPcwf2AuzeGPoYi1
#	tpubDFvJniKPdosnti9GmYP2EmqPKAyDYrTW71U38EquSGAGs7JU2SD9LVgHPtH8sVPXSZr2Bj1tYdhfk2EgLS5D11DGAGzBfvxMw6PzvBNwQjr
#	
