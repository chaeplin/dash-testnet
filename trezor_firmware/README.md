**Note**: If you are using Fedora then also install `arm-none-eabi-newlib` in order for the compilation to work. Otherwise the installation below should be the same.

```
!
apt-get update

apt-get remove gdb

apt-get install -yq build-essential git scons gcc-arm-none-eabi python-protobuf python-ecdsa protobuf-compiler fabric exuberant-ctags wget

cd ~

git clone https://github.com/chaeplin/trezor-mcu.git
cd trezor-mcu
git checkout
git submodule update --init
make -C vendor/libopencm3
make
make -C firmware
make -C firmware sign

firmware/trezor.bin

scp root@xxxxx:/root/trezor-mcu/firmware/trezor.bin .

pip install --upgrade git+https://github.com/chaeplin/python-trezor.git

#pip uninstall trezor



* both button very shotly *
so basically don't keep buttons pressed for longer than necessary after inserting trezor into computer
*

trezorctl firmware_update --help
trezorctl firmware_update -f trezor.bin
trezorctl wipe_device
trezorctl recovery_device -w 24 -p -r

```
