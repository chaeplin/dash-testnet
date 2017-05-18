* p2pool-dash
- https://github.com/dashpay/p2pool-dash

* unomp
- https://github.com/UNOMP/unified-node-open-mining-portal

* p2pool start.sh 
```
#!/bin/sh
sleep 120
cd ~/p2pool-dash
python run_p2pool.py --testnet
```

* unomp start.sh
```
#!/bin/sh
sleep 120
cd ~/unomp
node init.js
```

* /etc/rc.local
```
#!/bin/sh -e
#
# rc.local
#
# This script is executed at the end of each multiuser runlevel.
# Make sure that the script will "exit 0" on success or any other
# value on error.
#
# In order to enable or disable this script just change the execution
# bits.
#
# By default this script does nothing.

iptables-restore < /etc/default/iptables

su - coind -c dashd
su - coind -c "screen -dm -S p2pool ~/p2pool-dash/start.sh"
su - coind -c "screen -dm -S unomp ~/unomp/start.sh"

exit 0
```


* miner start1.sh 
```
#!/bin/sh
./cgminer --x11 \
-o stratum+tcp://163.44.165.237:17903 -u yiG3RcDLpJ2y6pGnb9MpbU3VFA5z9fb1KK -p 1 \
-o stratum+tcp://163.44.165.237:3008 -u yiG3RcDLpJ2y6pGnb9MpbU3VFA5z9fb1KK -p 1 \
-o stratum+tcp://test.stratum.dash.org:5032 -u yiG3RcDLpJ2y6pGnb9MpbU3VFA5z9fb1KK -p 1 \
--failover-only \
--dr1-clk 400 \
--dr1-fan LV3 \
-S /dev/ttyACM0 --du1 \
-S /dev/ttyACM1 --du1
```


* miner start2.sh
```
#!/bin/sh
./cgminer --x11 \
-o stratum+tcp://163.44.165.237:3008 -u yiG3RcDLpJ2y6pGnb9MpbU3VFA5z9fb1KK -p 1 \
-o stratum+tcp://163.44.165.237:17903 -u yiG3RcDLpJ2y6pGnb9MpbU3VFA5z9fb1KK -p 1 \
-o stratum+tcp://test.stratum.dash.org:5032 -u yiG3RcDLpJ2y6pGnb9MpbU3VFA5z9fb1KK -p 1 \
--failover-only \
--dr1-clk 400 \
--dr1-fan LV3 \
-S /dev/ttyACM2 --du1 \
-S /dev/ttyACM3 --du1
```