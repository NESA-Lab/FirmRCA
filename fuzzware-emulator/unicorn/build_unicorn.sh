#!/usr/bin/env bash
UC_DIR=fuzzware-unicorn

echo "[*] Cleaning Unicorn / QEMU..."
pushd "$UC_DIR" && rm -f qemu/config-host.mak; make -C qemu distclean clean; make clean; popd

echo "[*] Building Unicorn..."

UNICORN_ARCHS="arm" make -C "$UC_DIR" all || exit 1

echo "[+] Unicorn built successfully!"

echo "[*] Installing Unicorn python bindings..."

# install locally when inside a venv and globally otherwise
[[ -z "$VIRTUAL_ENV" ]] && WRAP="sudo -E python3" || WRAP="python3"
pushd "$UC_DIR"/bindings/python && UNICORN_ARCHS="arm" $WRAP setup.py install || { popd; exit 1; }; popd

echo "[+] Unicorn Python bindings installed successfully"

exit
