@0xdb76bbef1c3d61b6;

struct TraceEvent {
  union {
    instruction @0 :Instruction;
    access @1 :Access;
    crash @2 :Crash;
  }
}

struct Crash {
    union {
        mem @0 :Access;
        exe @1 :Instruction;
    }
}

struct Instruction {
    pc @0 :UInt32;
    lr @1 :UInt32;
}

struct Access {
    target @0 :AccessTarget;
    type @1 :UInt32;
    size @2 :UInt8;
    pc @3 :UInt32;
    address @4 :UInt32;
    value @5 :UInt32;
}

enum AccessTarget {
    ram @0;
    mmio @1;
    stack @2;
}
