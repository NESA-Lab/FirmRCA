#ifndef CAPN_DB76BBEF1C3D61B6
#define CAPN_DB76BBEF1C3D61B6
/* AUTO GENERATED - DO NOT EDIT */
#include <capnp_c.h>

#if CAPN_VERSION != 1
#error "version mismatch between capnp_c.h and generated code"
#endif

#ifndef capnp_nowarn
# ifdef __GNUC__
#  define capnp_nowarn __extension__
# else
#  define capnp_nowarn
# endif
#endif


#ifdef __cplusplus
extern "C" {
#endif

struct TraceEvent;
struct Crash;
struct BasicBlock;
struct Registers;
struct Access;

typedef struct {capn_ptr p;} TraceEvent_ptr;
typedef struct {capn_ptr p;} Crash_ptr;
typedef struct {capn_ptr p;} BasicBlock_ptr;
typedef struct {capn_ptr p;} Registers_ptr;
typedef struct {capn_ptr p;} Access_ptr;

typedef struct {capn_ptr p;} TraceEvent_list;
typedef struct {capn_ptr p;} Crash_list;
typedef struct {capn_ptr p;} BasicBlock_list;
typedef struct {capn_ptr p;} Registers_list;
typedef struct {capn_ptr p;} Access_list;

enum AccessTarget {
	AccessTarget_ram = 0,
	AccessTarget_mmio = 1,
	AccessTarget_stack = 2
};
enum TraceEvent_which {
	TraceEvent_basicBlock = 0,
	TraceEvent_access = 1,
	TraceEvent_dump = 2,
	TraceEvent_crash = 3
};

struct TraceEvent {
	enum TraceEvent_which which;
	capnp_nowarn union {
		BasicBlock_ptr basicBlock;
		Access_ptr access;
		Registers_ptr dump;
		Crash_ptr crash;
	};
};

static const size_t TraceEvent_word_count = 1;

static const size_t TraceEvent_pointer_count = 1;

static const size_t TraceEvent_struct_bytes_count = 16;

enum Crash_which {
	Crash_mem = 0,
	Crash_exe = 1
};

struct Crash {
	enum Crash_which which;
	capnp_nowarn union {
		Access_ptr mem;
		BasicBlock_ptr exe;
	};
};

static const size_t Crash_word_count = 1;

static const size_t Crash_pointer_count = 1;

static const size_t Crash_struct_bytes_count = 16;


struct BasicBlock {
	uint32_t pc;
	uint32_t lr;
};

static const size_t BasicBlock_word_count = 1;

static const size_t BasicBlock_pointer_count = 0;

static const size_t BasicBlock_struct_bytes_count = 8;


struct Registers {
	uint32_t r0;
	uint32_t r1;
	uint32_t r2;
	uint32_t r3;
	uint32_t r4;
	uint32_t r5;
	uint32_t r6;
	uint32_t r7;
	uint32_t r8;
	uint32_t r9;
	uint32_t r10;
	uint32_t r11;
	uint32_t r12;
	uint32_t lr;
	uint32_t pc;
	uint32_t sp;
	uint32_t xpsr;
};

static const size_t Registers_word_count = 9;

static const size_t Registers_pointer_count = 0;

static const size_t Registers_struct_bytes_count = 72;


struct Access {
	enum AccessTarget target;
	uint32_t type;
	uint8_t size;
	uint32_t pc;
	uint32_t address;
	uint32_t value;
};

static const size_t Access_word_count = 3;

static const size_t Access_pointer_count = 0;

static const size_t Access_struct_bytes_count = 24;


TraceEvent_ptr new_TraceEvent(struct capn_segment*);
Crash_ptr new_Crash(struct capn_segment*);
BasicBlock_ptr new_BasicBlock(struct capn_segment*);
Registers_ptr new_Registers(struct capn_segment*);
Access_ptr new_Access(struct capn_segment*);

TraceEvent_list new_TraceEvent_list(struct capn_segment*, int len);
Crash_list new_Crash_list(struct capn_segment*, int len);
BasicBlock_list new_BasicBlock_list(struct capn_segment*, int len);
Registers_list new_Registers_list(struct capn_segment*, int len);
Access_list new_Access_list(struct capn_segment*, int len);

void read_TraceEvent(struct TraceEvent*, TraceEvent_ptr);
void read_Crash(struct Crash*, Crash_ptr);
void read_BasicBlock(struct BasicBlock*, BasicBlock_ptr);
void read_Registers(struct Registers*, Registers_ptr);
void read_Access(struct Access*, Access_ptr);

void write_TraceEvent(const struct TraceEvent*, TraceEvent_ptr);
void write_Crash(const struct Crash*, Crash_ptr);
void write_BasicBlock(const struct BasicBlock*, BasicBlock_ptr);
void write_Registers(const struct Registers*, Registers_ptr);
void write_Access(const struct Access*, Access_ptr);

void get_TraceEvent(struct TraceEvent*, TraceEvent_list, int i);
void get_Crash(struct Crash*, Crash_list, int i);
void get_BasicBlock(struct BasicBlock*, BasicBlock_list, int i);
void get_Registers(struct Registers*, Registers_list, int i);
void get_Access(struct Access*, Access_list, int i);

void set_TraceEvent(const struct TraceEvent*, TraceEvent_list, int i);
void set_Crash(const struct Crash*, Crash_list, int i);
void set_BasicBlock(const struct BasicBlock*, BasicBlock_list, int i);
void set_Registers(const struct Registers*, Registers_list, int i);
void set_Access(const struct Access*, Access_list, int i);

#ifdef __cplusplus
}
#endif
#endif
