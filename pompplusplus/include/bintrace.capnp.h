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
struct Instruction;
struct Access;

typedef struct {capn_ptr p;} TraceEvent_ptr;
typedef struct {capn_ptr p;} Crash_ptr;
typedef struct {capn_ptr p;} Instruction_ptr;
typedef struct {capn_ptr p;} Access_ptr;

typedef struct {capn_ptr p;} TraceEvent_list;
typedef struct {capn_ptr p;} Crash_list;
typedef struct {capn_ptr p;} Instruction_list;
typedef struct {capn_ptr p;} Access_list;

enum AccessTarget {
	AccessTarget_ram = 0,
	AccessTarget_mmio = 1,
	AccessTarget_stack = 2
};
enum TraceEvent_which {
	TraceEvent_instruction = 0,
	TraceEvent_access = 1,
	TraceEvent_crash = 2
};

struct TraceEvent {
	enum TraceEvent_which which;
	capnp_nowarn union {
		Instruction_ptr instruction;
		Access_ptr access;
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
		Instruction_ptr exe;
	};
};

static const size_t Crash_word_count = 1;

static const size_t Crash_pointer_count = 1;

static const size_t Crash_struct_bytes_count = 16;


struct Instruction {
	uint32_t pc;
	uint32_t lr;
};

static const size_t Instruction_word_count = 1;

static const size_t Instruction_pointer_count = 0;

static const size_t Instruction_struct_bytes_count = 8;


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
Instruction_ptr new_Instruction(struct capn_segment*);
Access_ptr new_Access(struct capn_segment*);

TraceEvent_list new_TraceEvent_list(struct capn_segment*, int len);
Crash_list new_Crash_list(struct capn_segment*, int len);
Instruction_list new_Instruction_list(struct capn_segment*, int len);
Access_list new_Access_list(struct capn_segment*, int len);

void read_TraceEvent(struct TraceEvent*, TraceEvent_ptr);
void read_Crash(struct Crash*, Crash_ptr);
void read_Instruction(struct Instruction*, Instruction_ptr);
void read_Access(struct Access*, Access_ptr);

void write_TraceEvent(const struct TraceEvent*, TraceEvent_ptr);
void write_Crash(const struct Crash*, Crash_ptr);
void write_Instruction(const struct Instruction*, Instruction_ptr);
void write_Access(const struct Access*, Access_ptr);

void get_TraceEvent(struct TraceEvent*, TraceEvent_list, int i);
void get_Crash(struct Crash*, Crash_list, int i);
void get_Instruction(struct Instruction*, Instruction_list, int i);
void get_Access(struct Access*, Access_list, int i);

void set_TraceEvent(const struct TraceEvent*, TraceEvent_list, int i);
void set_Crash(const struct Crash*, Crash_list, int i);
void set_Instruction(const struct Instruction*, Instruction_list, int i);
void set_Access(const struct Access*, Access_list, int i);

#ifdef __cplusplus
}
#endif
#endif
