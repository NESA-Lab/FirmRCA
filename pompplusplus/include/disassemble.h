#ifndef __DISASSEMBLE__
#define __DISASSEMBLE__

// #include <libdis.h>
#include <capstone/capstone.h>

// int disasm_one_inst(char *buf, size_t buf_size, int pos, x86_insn_t *inst);
typedef enum arm_datatype_enum{
    op_byte = 1,
    op_word = 2,
    op_dword = 4,
    op_qword = 8
} arm_datatype;

typedef enum mem_access_type_enum{
    mem_read,
    mem_write,
    mem_none,
}mem_access_type;

typedef enum arm_op_usage_enum{
    op_src = 1,
    op_dst = 2,
    op_writeback = 4,
}arm_op_usage;

typedef struct arm_ops_parser_struct{
    uint8_t op_num;
    arm_op_usage op_usage[36];
    cs_arm_op* op[36];
}arm_ops_parser;


uint8_t arm_get_dst_operand(cs_insn* insn, cs_arm_op** dst);

uint8_t arm_get_src_operand(cs_insn* insn, cs_arm_op** src);

void arm_parse_ops(cs_insn* insn, arm_ops_parser* parser, uint8_t* nsrc, uint8_t* ndst);

arm_datatype arm_get_datatype(cs_insn* insn);
#endif
