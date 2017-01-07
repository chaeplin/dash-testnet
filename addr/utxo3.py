import sys
import binascii
import itertools
from keepkeylib.client import KeepKeyClient
from keepkeylib.transport_hid import HidTransport
import keepkeylib.types_pb2 as proto_types
from keepkeylib import tx_api
from keepkeylib.tx_api import TXAPIDashTestnet

tx_api.rpcuser = 'rpcuser'
tx_api.rpcpassword = 'rpc_password'

devices = HidTransport.enumerate()

if len(devices) == 0:
    print('No KeepKey found')
    sys.exit()

transport = HidTransport(devices[0])
client = KeepKeyClient(transport)
client.set_tx_api(TXAPIDashTestnet())


inp1 = proto_types.TxInputType(address_n=[44 | 0x80000000, 165 | 0x80000000, 0 | 0x80000000, 0, 0],  # ycAUjobjH3qGQd1kD5pvxdUxiUjjxM4Cg6
                     # amount=500000000
                     prev_hash=binascii.unhexlify('0b97b6cf11ce5fe4b4ae5d1ef4b65c3f393cf2434a11cc81edc2159fc4e941a7'),
                     prev_index=1,
                     )

out1 = proto_types.TxOutputType(address='yc968WwD8hTGWQK64CLPhf4CRTJXX2TqBK',
                      amount=500000000 - 10000,
                      script_type=proto_types.PAYTOADDRESS,
                      )

(signatures, serialized_tx) = client.sign_tx('tDash', [inp1, ], [out1, ])
#(signatures, serialized_tx) = client.sign_tx('tDash', [inp1, ], [out1, ], None, True)

print(binascii.hexlify(signatures[0]))
print(binascii.hexlify(serialized_tx))

# 304402203c314418ef991ddc7664d7d009c03af016c42d8b5c32c9ec589e85145eea817102205f6b4011c7200daf85b079b43f7ab943ab7d618673c28392bc6a19ddae554f0b

# 0100000001a741e9c49f15c2ed81cc114a43f23c393f5cb6f41e5daeb4e45fce11cfb6970b010000006a47304402203c314418ef991ddc7664d7d009c03af016c42d8b5c32c9ec589e85145eea817102205f6b4011c7200daf85b079b43f7ab943ab7d618673c28392bc6a19ddae554f0b012102e8c23f2f00d463153e2f7b10b00299feedefc7f3d7965cb0f4455621ef6226c8ffffffff01f03dcd1d000000001976a914ad8c8ecc08b7346be68e00874cfb68f2c9ba37fb88ac00000000

#	tpubDEyjRjHcwQcfgDFZVnPwxjKxw5umMLRC8CPKy5evuQxCNjkiJUir27J9pbsJBaATmxCz7yhfTRCFT7frhRDbDeY3WiCYzyvFEFa3NFybVEr
#	tDASH address: 44'/165'/0'/0/0 yWvgAEPSNZoieH4AdYQVuntfJom8YR2zZF
#	tDASH address: 44'/165'/0'/0/1 ycAUjobjH3qGQd1kD5pvxdUxiUjjxM4Cg6
#	tDASH address: 44'/165'/0'/0/2 yXhUBeFqcYgBKKYKWynBELVZiAXmBw1THY
#	tDASH address: 44'/165'/0'/0/3 ydH77YLFD5nrk81aZo6qq9rvjEWNttqhVY
#	tDASH address: 44'/165'/0'/0/4 ydUuyDx3vkgsWcSRJnDVvz7N5NUBWcALbW
#	tDASH address: 44'/165'/0'/0/5 yYvzA8Ka36rHRkD4xzTZsdcP3i69bAxSTB
#	tDASH address: 44'/165'/0'/0/6 yQpNjDysicbsVCsxb6xt75cPZA1Wdaj7Ax
#	tDASH address: 44'/165'/0'/0/7 yaxauoRgkUDU2wHbgnZDFQTtVcQsJpp2YM
#	tDASH address: 44'/165'/0'/0/8 yfWuCuW9v3HTY5aVNF5RGgzVj3Dy6U4KXq
#	tDASH address: 44'/165'/0'/0/9 ygcxYS19rZv3gCqW8mCud5nzsoAQBMgoDG
#	tDASH address: 44'/165'/0'/0/10 yX9Kqsv2m3jgqWXC2gH2uQ6RbBx6BtKH7m
