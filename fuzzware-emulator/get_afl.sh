#!/usr/bin/env bash

if [ ! -e afl ]; then
    AFL_COMMIT=c49750c9e27e29100d055292453551d560e594ce
    AFL_URL=https://github.com/Fuzzers-Archive/afl-2.52b/archive/$AFL_COMMIT.zip
    AFL_SHA384=16bd4427d99ba5cb98d3dc132d830d971217f0b12e0b64bc6f7239696ebfd19251559b33477ba023ce9b382dd2036df3
    AFL_EXTRACT_DIR=afl-2.52b-$AFL_COMMIT

    ARCHIVE="`basename -- "$AFL_URL"`"
    rm -f "$ARCHIVE"
    rm -rf "$AFL_EXTRACT_DIR"

    echo "[*] Downloading afl"
    wget $AFL_URL || exit 1

    CKSUM=`sha384sum -- "$ARCHIVE" 2>/dev/null | cut -d' ' -f1`

    if [ ! "$CKSUM" = "$AFL_SHA384" ]; then
        echo "[-] AFL archive checksum mismatch"
        exit 1
    else
        echo "[+] AFL archive checksum matches"
    fi

    unzip $ARCHIVE || exit 1
    mv "$AFL_EXTRACT_DIR" afl

    patch -p0 < afl.patch || {
        echo "Failed to apply AFL patch"
        exit 1
    }

    rm -f "$ARCHIVE"
    rm -rf "$AFL_EXTRACT_DIR"
fi

if [ ! -e AFLplusplus ]; then
    git clone https://github.com/AFLplusplus/AFLplusplus
    git -C AFLplusplus checkout 3.14c
fi
