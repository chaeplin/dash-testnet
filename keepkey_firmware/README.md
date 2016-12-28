```
apt-get update
apt-get remove gdb
apt-get install -yq build-essential git scons gcc-arm-none-eabi python-protobuf python-ecdsa protobuf-compiler fabric exuberant-ctags wget
cd ~
git clone --branch nanopb-0.2.9.2 https://github.com/nanopb/nanopb/
cd nanopb/generator/proto
make
export PATH=/root/nanopb/generator:$PATH
cd ~
git clone https://github.com/chaeplin/keepkey-firmware.git
cd keepkey-firmware/libopencm3/
make
cd ..
./b -mp

ls -la build/arm-none-gnu-eabi/release/bin/*.bin

https://raw.githubusercontent.com/dashpay/keepkey-firmware/master/bootloader/firmware_sign.py
chmod 755 firmware_sign.py
./firmware_sign.py -f build/arm-none-gnu-eabi/release/bin/keepkey_main.bin

cp root@x.x.x.x:/root/keepkey-firmware/build/arm-none-gnu-eabi/release/bin/keepkey_main.bin


pip install --upgrade git+https://github.com/keepkey/python-keepkey.git

keepkeyctl firmware_update --help

keepkeyctl firmware_update -f keepkey_main.bin

keepkeyctl wipe_device
keepkeyctl recovery_device
```