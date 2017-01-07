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


inp1 = proto_types.TxInputType(address_n=[44 | 0x80000000, 165 | 0x80000000, 0 | 0x80000000, 0, 0],  # yjJUQ42u8Z86s9LiUmNgvS9dSzhunWbuQR
                     # amount=500000000
                     prev_hash=binascii.unhexlify('128155b0b044b8a7797a7dbe7e5f7f5ceb41134bae7ccf420fee61bbd7fc6b93'),
                     prev_index=0,
                     )

out1 = proto_types.TxOutputType(address='yc968WwD8hTGWQK64CLPhf4CRTJXX2TqBK',
                      amount=500000000 - 10000,
                      script_type=proto_types.PAYTOADDRESS,
                      )

(signatures, serialized_tx) = client.sign_tx('tDash', [inp1, ], [out1, ])
#(signatures, serialized_tx) = client.sign_tx('tDash', [inp1, ], [out1, ], None, True)

print(binascii.hexlify(signatures[0]))
print(binascii.hexlify(serialized_tx))



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
