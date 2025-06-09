@0xdb76bbef1c3d61b6;

struct TraceEvent {
  union {
    instruction @0 :Instruction;
    access @1 :Access;
    dump @2 :Registers;
    crash @3 :Crash;
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

struct Registers {
    r0 @0 : UInt32;
    r1 @1 : UInt32;
    r2 @2 : UInt32;
    r3 @3 : UInt32;
    r4 @4 : UInt32;
    r5 @5 : UInt32;
    r6 @6 : UInt32;
    r7 @7 : UInt32;
    r8 @8 : UInt32;
    r9 @9 : UInt32;
    r10 @10 : UInt32;
    r11 @11 : UInt32;
    r12 @12 : UInt32;
    lr @13 : UInt32;
    pc @14 : UInt32;
    sp @15 : UInt32;
    xpsr @16 : UInt32;
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
