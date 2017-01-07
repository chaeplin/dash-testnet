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
                     prev_hash=binascii.unhexlify('4a1f3f89d95dd162e30399386dd7748c7fa02ec958320f4542923cf3a63fde48'),
                     prev_index=1,
                     )

out1 = proto_types.TxOutputType(address='yV7G6wcfkqfjw3SyykJzYnsL3fqJByqXYG',
                      amount=500000000 - 10000,
                      script_type=proto_types.PAYTOADDRESS,
                      )

(signatures, serialized_tx) = client.sign_tx('tDash', [inp1, ], [out1, ])
#(signatures, serialized_tx) = client.sign_tx('tDash', [inp1, ], [out1, ], None, True)

print(binascii.hexlify(signatures[0]))
print(binascii.hexlify(serialized_tx))







#   tpubDEfQ9V3njDmFrTrfzc5tNV3nGJcXh2zAfQk6fWMjSkmx2TAjAa8wNDx8MHnRpvSkAvgdySmi4PLiCdRGJaitwbWtEFHQik7yWHR88tWoJz2
#   tDASH address: 44'/165'/0'/0/0 yjJUQ42u8Z86s9LiUmNgvS9dSzhunWbuQR
#   tDASH address: 44'/165'/0'/0/1 yPuuLxGRtpa5R7xuEyagEXysUN6RmKtR89
#   tDASH address: 44'/165'/0'/0/2 yhQDFkFyoJZYEGAJ7nkC4KC8u9nRMS5i6h
#   tDASH address: 44'/165'/0'/0/3 yhQGvsHmezeyTBYsSj4JrD5F7hthiK8Day
#   tDASH address: 44'/165'/0'/0/4 yV7G6wcfkqfjw3SyykJzYnsL3fqJByqXYG
#   tDASH address: 44'/165'/0'/0/5 yehyqx9xJhkC2vh976E9pJoP2xpCYpPKNw
#   tDASH address: 44'/165'/0'/0/6 yXL8Nj6QEjBUiFc5W6FdBfruX4MWkbSkGE
#   tDASH address: 44'/165'/0'/0/7 yaG5hbz8zUimrsC6oFqwxJHjTMNo7Lyrsx


#   yjJUQ42u8Z86s9LiUmNgvS9dSzhunWbuQR 5 4a1f3f89d95dd162e30399386dd7748c7fa02ec958320f4542923cf3a63fde48
#   yPuuLxGRtpa5R7xuEyagEXysUN6RmKtR89 5 7ff42dac4218c45b9f433d1c821486461da0699e71ea489d7aaef0aea9d616f0
#   yhQDFkFyoJZYEGAJ7nkC4KC8u9nRMS5i6h 5 a352ec5f8c8842990d088874fa7b56f468ebde7f0d8ad8b0d6cf362b6bd14dd0


