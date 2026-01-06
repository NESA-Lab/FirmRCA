[![DOI](https://zenodo.org/badge/DOI/10.5281/zenodo.15623400.svg)](https://doi.org/10.5281/zenodo.15623400) [![DOI](https://img.shields.io/github/license/NESA-Lab/FirmRCA.svg)](https://github.com/NESA-Lab/FirmRCA?tab=GPL-3.0-1-ov-file) [![Static Badge](https://img.shields.io/badge/IEEE%20S%26P-10.1109%2FSP61157.2025.00002-green)](https://www.computer.org/csdl/proceedings-article/sp/2025/223600a002/21B7PVDny6I)

# FirmRCA

Embedded Firmware Root Cause Analysis.

This repo contains the source code of the paper "FirmRCA: Towards Post-Fuzzing Analysis on ARM Embedded Firmware with Efficient Event-based Fault Localization"

## NOTE

*During the development of FirmRCA, footprint collection and root cause analysis were carried out sequentially on two separate servers. However, the server responsible for footprint collection suffered a hard drive failure. As a result, the version of fuzzware used by the current repository’s fuzzware-emulator is uncertain, which may introduce potential instability in the experimental results.*

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
#Then you should compile and install capstone as system library, following the instructions in capstone.
#For example, on *nix:
sudo ./make.sh
sudo ./make.sh install
```

Setup python enviroment. We use `uv` to manage the environment. Were it not installed, please run `wget -qO- https://astral.sh/uv/install.sh | sh` first.

```shell
cd /FirmRCA
uv sync
```

Step 3. (Optional) Compile the capnproto library, if you want to modify tracing data.

```shell
curl -O https://capnproto.org/capnproto-c++-1.0.1.tar.gz
tar zxf capnproto-c++-1.0.1.tar.gz
cd ./capnproto-c++-1.0.1
./configure
make -j$(nproc) check
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

You can modify the `bin_PROGRAMS` variable in `src/src/Makefile.am` for differet settings. 

* reversenolog: Perform full FirmRCA without extra logging information.
* reverselog: Perform full FirmRCA with extra logging information. This will generate a huge log file (maybe hundreds of MBs)
* ablation1: Perform FirmRCA without the redundant loop taint suppression strategy.
* ablation2: Perform FirmRCA without the history write taint prioritization strategy.
* ablation3: Perform FirmRCA without any heuristic suspicious score assignment strategies.

```shell
cd ./src
chmod +x ./autogen.sh
./autogen.sh
./configure
cd src
make
```

If something wrong occurs when running `./configure`, please make sure these compilation files use LF instead of CRLF. You can also check [POMP](https://github.com/junxzm1990/pomp) for installation reference.

Step 5. Run FirmRCA.

We use the `main.py` script to manage FirmRCA's execution. After setup the dataset (in the following section), you can simply run `uv run main.py` for an example or `uv run main.py --name=<testcase name>` to test the specific test case.

The result will be saved in `testsuites/<testcase name>/execution-<setting>-<depth>.log`

For advanced usage, you can check the source code.

## Dataset 

We prepare 3 testsuites as a demo in the `testsuites/testsuites-demo.zip` file. You can directly unzip this file under `testsuites/` with `cd testsuites && unzip testsuites-demo.zip`. Besides, the full dataset can be downloaded from [10.5281/zenodo.15623399](https://doi.org/10.5281/zenodo.15623399). 

If you want to generate more testcases, you can prepare your files like this:

```
FirmRCA/
├── testsuites
│   ├── <something-your-bin-name1>
│   │   ├── firmware.bin
│   ├── <something-your-bin-name2>
│   │   ├── firmware.bin
│   ├── <something-your-bin-name3>
│   │   ├── firmware.bin

```

`<something-your-bin-name1>` should be the same value with the `name` key in `config.yml`. You should also specify `bin_load_addr` that loads the binary.

Then please refer to [fuzzware-fuzzer](https://github.com/fuzzware-fuzzer/fuzzware-emulator) to setup the environment. Please do not clone the their repository because the unicorn version may be different. Use the fuzzware-emulator in this repository, instead.

Then, run `uv run dataset.py` to generate your own dataset.