#!/usr/bin/env bash

[[ -f /.dockerenv || ! -z $VIRTUAL_ENV ]] || { echo "[ERROR] You want to be installing this in a virtual environment. Did you call this script standalone?"; exit 1; }

./get_afl.sh
make -C AFLplusplus clean all || {
    echo "[-] Failed building AFLplusplus"
    exit 1
}

echo "[*] Building afl and Unicorn"
UNICORN_QEMU_FLAGS="--python=/usr/bin/python3" make -C afl clean all || exit 1
pushd unicorn; USERNAME=`whoami` ./build_unicorn.sh || { popd; exit 1; }; popd

echo "[*] Building native harness module"
make -C harness/fuzzware_harness/native clean all || exit 1

echo "[*] Installing harness"
pip3 install -U cython || exit 1
pip3 install -U -r requirements.txt || exit 1

pushd harness; pip3 install -e . || { popd; exit 1; }; popd
exit 0