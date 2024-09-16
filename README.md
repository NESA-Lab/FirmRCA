# FirmRCA

Embedded Firmware Root Cause Analysis.

This repo contains the source code of the paper "FirmRCA: Towards Post-Fuzzing Analysis on ARM Embedded Firmware with Efficient Event-based Fault Localization"

## Note

**This is a preview version before camera-ready.**

## How to Install

Step 1. Clone the repo.

```shell
git clone https://github.com/NESA-Lab/FirmRCA
cd ./FirmRCA
```

Step 2. Install the dependencies.

Install the capstone.

```shell
git clone https://github.com/capstone-engine/capstone.git
cd ./capstone
git reset --hard 622059530f172b1570a424e3f7ef5fda8c00dab0 # not sure if new features in the latest commit affect our code
```

Then you should compile and install capstone as system library, following the instructions in capstone.
For example, on *nix:

```shell
sudo ./make.sh
sudo ./make.sh install
```

Some python packages:

```shell
pip3 install matplotlib pandas pyyaml openpyxl 
```

Step 3. Compile the capnproto library.

(Option) Configure c-capnproto, if you want to modify tracing data.

```shell
curl -O https://capnproto.org/capnproto-c++-1.0.1.tar.gz
tar zxf capnproto-c++-1.0.1.tar.gz
cd ./capnproto-c++-1.0.1
./configure
make -j4 check
sudo make install
```

```shell
git clone https://gitlab.com/dkml/ext/c-capnproto.git
cd ./c-capnproto
sudo apt install ninja-build
cmake --preset=ci-linux_x86_64
cmake --build --preset=ci-tests
```

Compile the library.

```shell
cd ./test_c_capnproto
# before capnp compile, you can modify bintrace.capnp if need
capnp compile -o ./c-capnproto/build/capnpc-c bintrace.capnp 
gcc *.c -I./ -shared -fPIC -o libcapnproto.so
cp ./libcapnproto.so ../src/lib
```

Step 4. Compile the project binary

Note that you should comment/uncomment the settings in Makefile.am.

```shell
cd ./src
./autogen.sh
./configure
cd src
make
```

## Dataset 

Currently, we prepare 3 testsuites as a demo. You can unzip testsuites-demo.zip as a `testsuites` directory.

We will further release all testsuites.