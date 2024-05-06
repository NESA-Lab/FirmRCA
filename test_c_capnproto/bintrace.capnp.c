#include "bintrace.capnp.h"
/* AUTO GENERATED - DO NOT EDIT */
#ifdef __GNUC__
# define capnp_unused __attribute__((unused))
# define capnp_use(x) (void) (x);
#else
# define capnp_unused
# define capnp_use(x)
#endif


TraceEvent_ptr new_TraceEvent(struct capn_segment *s) {
	TraceEvent_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
TraceEvent_list new_TraceEvent_list(struct capn_segment *s, int len) {
	TraceEvent_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_TraceEvent(struct TraceEvent *s capnp_unused, TraceEvent_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->which = (enum TraceEvent_which)(int) capn_read16(p.p, 0);
	switch (s->which) {
	case TraceEvent_basicBlock:
	case TraceEvent_access:
	case TraceEvent_dump:
	case TraceEvent_crash:
		s->crash.p = capn_getp(p.p, 0, 0);
		break;
	default:
		break;
	}
}
void write_TraceEvent(const struct TraceEvent *s capnp_unused, TraceEvent_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write16(p.p, 0, s->which);
	switch (s->which) {
	case TraceEvent_basicBlock:
	case TraceEvent_access:
	case TraceEvent_dump:
	case TraceEvent_crash:
		capn_setp(p.p, 0, s->crash.p);
		break;
	default:
		break;
	}
}
void get_TraceEvent(struct TraceEvent *s, TraceEvent_list l, int i) {
	TraceEvent_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_TraceEvent(s, p);
}
void set_TraceEvent(const struct TraceEvent *s, TraceEvent_list l, int i) {
	TraceEvent_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_TraceEvent(s, p);
}

Crash_ptr new_Crash(struct capn_segment *s) {
	Crash_ptr p;
	p.p = capn_new_struct(s, 8, 1);
	return p;
}
Crash_list new_Crash_list(struct capn_segment *s, int len) {
	Crash_list p;
	p.p = capn_new_list(s, len, 8, 1);
	return p;
}
void read_Crash(struct Crash *s capnp_unused, Crash_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->which = (enum Crash_which)(int) capn_read16(p.p, 0);
	switch (s->which) {
	case Crash_mem:
	case Crash_exe:
		s->exe.p = capn_getp(p.p, 0, 0);
		break;
	default:
		break;
	}
}
void write_Crash(const struct Crash *s capnp_unused, Crash_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write16(p.p, 0, s->which);
	switch (s->which) {
	case Crash_mem:
	case Crash_exe:
		capn_setp(p.p, 0, s->exe.p);
		break;
	default:
		break;
	}
}
void get_Crash(struct Crash *s, Crash_list l, int i) {
	Crash_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_Crash(s, p);
}
void set_Crash(const struct Crash *s, Crash_list l, int i) {
	Crash_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_Crash(s, p);
}

BasicBlock_ptr new_BasicBlock(struct capn_segment *s) {
	BasicBlock_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
BasicBlock_list new_BasicBlock_list(struct capn_segment *s, int len) {
	BasicBlock_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_BasicBlock(struct BasicBlock *s capnp_unused, BasicBlock_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->pc = capn_read32(p.p, 0);
	s->lr = capn_read32(p.p, 4);
}
void write_BasicBlock(const struct BasicBlock *s capnp_unused, BasicBlock_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->pc);
	capn_write32(p.p, 4, s->lr);
}
void get_BasicBlock(struct BasicBlock *s, BasicBlock_list l, int i) {
	BasicBlock_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_BasicBlock(s, p);
}
void set_BasicBlock(const struct BasicBlock *s, BasicBlock_list l, int i) {
	BasicBlock_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_BasicBlock(s, p);
}

Registers_ptr new_Registers(struct capn_segment *s) {
	Registers_ptr p;
	p.p = capn_new_struct(s, 72, 0);
	return p;
}
Registers_list new_Registers_list(struct capn_segment *s, int len) {
	Registers_list p;
	p.p = capn_new_list(s, len, 72, 0);
	return p;
}
void read_Registers(struct Registers *s capnp_unused, Registers_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->r0 = capn_read32(p.p, 0);
	s->r1 = capn_read32(p.p, 4);
	s->r2 = capn_read32(p.p, 8);
	s->r3 = capn_read32(p.p, 12);
	s->r4 = capn_read32(p.p, 16);
	s->r5 = capn_read32(p.p, 20);
	s->r6 = capn_read32(p.p, 24);
	s->r7 = capn_read32(p.p, 28);
	s->r8 = capn_read32(p.p, 32);
	s->r9 = capn_read32(p.p, 36);
	s->r10 = capn_read32(p.p, 40);
	s->r11 = capn_read32(p.p, 44);
	s->r12 = capn_read32(p.p, 48);
	s->lr = capn_read32(p.p, 52);
	s->pc = capn_read32(p.p, 56);
	s->sp = capn_read32(p.p, 60);
	s->xpsr = capn_read32(p.p, 64);
}
void write_Registers(const struct Registers *s capnp_unused, Registers_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->r0);
	capn_write32(p.p, 4, s->r1);
	capn_write32(p.p, 8, s->r2);
	capn_write32(p.p, 12, s->r3);
	capn_write32(p.p, 16, s->r4);
	capn_write32(p.p, 20, s->r5);
	capn_write32(p.p, 24, s->r6);
	capn_write32(p.p, 28, s->r7);
	capn_write32(p.p, 32, s->r8);
	capn_write32(p.p, 36, s->r9);
	capn_write32(p.p, 40, s->r10);
	capn_write32(p.p, 44, s->r11);
	capn_write32(p.p, 48, s->r12);
	capn_write32(p.p, 52, s->lr);
	capn_write32(p.p, 56, s->pc);
	capn_write32(p.p, 60, s->sp);
	capn_write32(p.p, 64, s->xpsr);
}
void get_Registers(struct Registers *s, Registers_list l, int i) {
	Registers_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_Registers(s, p);
}
void set_Registers(const struct Registers *s, Registers_list l, int i) {
	Registers_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_Registers(s, p);
}

Access_ptr new_Access(struct capn_segment *s) {
	Access_ptr p;
	p.p = capn_new_struct(s, 24, 0);
	return p;
}
Access_list new_Access_list(struct capn_segment *s, int len) {
	Access_list p;
	p.p = capn_new_list(s, len, 24, 0);
	return p;
}
void read_Access(struct Access *s capnp_unused, Access_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->target = (enum AccessTarget)(int) capn_read16(p.p, 0);
	s->type = capn_read32(p.p, 4);
	s->size = capn_read8(p.p, 2);
	s->pc = capn_read32(p.p, 8);
	s->address = capn_read32(p.p, 12);
	s->value = capn_read32(p.p, 16);
}
void write_Access(const struct Access *s capnp_unused, Access_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write16(p.p, 0, (uint16_t) (s->target));
	capn_write32(p.p, 4, s->type);
	capn_write8(p.p, 2, s->size);
	capn_write32(p.p, 8, s->pc);
	capn_write32(p.p, 12, s->address);
	capn_write32(p.p, 16, s->value);
}
void get_Access(struct Access *s, Access_list l, int i) {
	Access_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_Access(s, p);
}
void set_Access(const struct Access *s, Access_list l, int i) {
	Access_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_Access(s, p);
}
