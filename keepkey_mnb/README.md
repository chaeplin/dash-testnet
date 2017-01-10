Using Keepkey to start Masternode
==================================

#### requirement
- Dash-QT or dashd
- Keepkey 
- keepkey-firmware
- rpc conn to Dash-QT or dashd
- python3
- python-keepkey
- python-bitcoinrpc
- python-progress
- python-pyfiglet
- python-bip32utils

#### Keepkey firmware
- Build your own firmware
- https://github.com/chaeplin/dash-testnet/tree/master/keepkey_firmware

### python lib
- use python-virtualenv3
- https://github.com/chaeplin/python-keepkey
- https://github.com/chaeplin/python-bitcoinrpc
- https://github.com/verigak/progress
- https://github.com/pwaller/pyfiglet
- https://github.com/chaeplin/bip32utils
- lib (sub dir)
```
virtualenv -p python3 venv3
source venv3/bin/activate
python "pg to run"
```


### How to
- use keepkey-for-mn.py to gen a list of address (change key path = mpath)
- send 1k tDash to Address
- set up remote masternode
- change config of mnb_keepkey.py(rpc, mpath, mn list, line 87)
- run Dash-QT or dashd
- run mnb_keepkey.py


### Use remote dashd
- ssh tunnel
- ssh -L 19998:localhost:19998 -N username@192.168.10.10 (-N(keep tunnel, not loggn in) -L local_port:dest_ip:dest_port )