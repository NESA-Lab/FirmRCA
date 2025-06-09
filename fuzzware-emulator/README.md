# Fuzzware Emulation Component
Note: This is a subcomponent of Fuzzware. You will not want to manually try to install this component. The place to start is the [fuzzware parent repo](https://github.com/fuzzware-fuzzer/fuzzware). Please refer to the documentation and scripts provided there for installing Fuzzware and learning about how to use it.

The emulation component of Fuzzware allows to generically emulate (currently ARM CortexM-based) firmware images by fuzzing the input for MMIO accesses. At its core, Fuzzware serves MMIO accesses from a linear stream of input bytes and makes the firmware run this way.

This project has a relative in [HAL-fuzz](https://github.com/ucsb-seclab/hal-fuzz), which uses a high-level emulation approach to emulate firmware images. Fuzzware inherits a lot of the high-level emulation functionality introduced by hal-fuzz. While they are not used by default, they may help you in analyzing a specific firmware binary. The referenced repo may give you ideas about how to manually handle different pieces of functionality within the firmware image.

## AFL Patches
The [afl patch](afl.patch) is originally based on work by Nathan Voss and the following repository: https://github.com/Battelle/afl-unicorn.

For a stable reference, we install by starting from an archived version of the original AFL on GitHub (https://github.com/Fuzzers-Archive/afl-2.52b) and applying patches.
