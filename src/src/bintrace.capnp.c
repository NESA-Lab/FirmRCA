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
	case TraceEvent_instruction:
	case TraceEvent_access:
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
	case TraceEvent_instruction:
	case TraceEvent_access:
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

Instruction_ptr new_Instruction(struct capn_segment *s) {
	Instruction_ptr p;
	p.p = capn_new_struct(s, 8, 0);
	return p;
}
Instruction_list new_Instruction_list(struct capn_segment *s, int len) {
	Instruction_list p;
	p.p = capn_new_list(s, len, 8, 0);
	return p;
}
void read_Instruction(struct Instruction *s capnp_unused, Instruction_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	s->pc = capn_read32(p.p, 0);
	s->lr = capn_read32(p.p, 4);
}
void write_Instruction(const struct Instruction *s capnp_unused, Instruction_ptr p) {
	capn_resolve(&p.p);
	capnp_use(s);
	capn_write32(p.p, 0, s->pc);
	capn_write32(p.p, 4, s->lr);
}
void get_Instruction(struct Instruction *s, Instruction_list l, int i) {
	Instruction_ptr p;
	p.p = capn_getp(l.p, i, 0);
	read_Instruction(s, p);
}
void set_Instruction(const struct Instruction *s, Instruction_list l, int i) {
	Instruction_ptr p;
	p.p = capn_getp(l.p, i, 0);
	write_Instruction(s, p);
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
