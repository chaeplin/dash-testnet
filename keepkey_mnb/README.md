Using Keepkey to start Masternode
==================================

#### requirement
- Dash-QT or dashd
- Keepkey 
- keepkey-firmware
- rpc conn to Dash-QT or dashd
- python-keepkey
- python-bitcoinrpc
- python-progress
- python-pyfiglet
- python-bip32utils

#### Keepkey firmware
- Build your own firmware
- https://github.com/chaeplin/dash-testnet/tree/master/keepkey_firmware

### python lib
- https://github.com/chaeplin/python-keepkey
- https://github.com/jgarzik/python-bitcoinrpc
- https://github.com/verigak/progress
- https://github.com/pwaller/pyfiglet
- https://github.com/chaeplin/bip32utils

### How to
- use keepkey-for-mn.py to gen a list of address (change key path = mpath)
- send 1k tDash to Address
- set up remote masternode
- change config of mnb_keepkey.py(rpc, mpath, mn list, line 87)
- run Dash-QT or dashd
- run mnb_keepkey.py
