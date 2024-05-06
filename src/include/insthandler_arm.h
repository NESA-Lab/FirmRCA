#ifndef __INSTHANDLER_ARM__
#define __INSTHANDLER_ARM__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <libdis.h>
#include <assert.h>
#include <capstone/capstone.h>
#include "disassemble.h"
#include "global.h"
#include "access_memory.h"
#include "reverse_log.h"
#include "reverse_exe.h"
#include "inst_opd.h"
#include "re_alias.h"
#include "heuristics.h"
typedef struct op_index_pair{
	arm_insn  type;
	int index; 
}op_index_pair_t;

extern op_index_pair_t opcode_index_tab[];

extern const int ninst;

typedef void (*resolver_func)(re_list_t* instnode, re_list_t *re_deflist, re_list_t *re_uselist);
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
typedef void (*vs_handler_func)(re_list_t * instnode);
#endif

typedef void (*handler_func)(re_list_t * instnode);

typedef int (*esp_resolve_func)(re_list_t *instnode, int *disp);

#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
extern vs_handler_func vs_handler[];
#endif
typedef int (*post_resolve_heuristic_func)(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

extern resolver_func inst_resolver[]; 

extern esp_resolve_func esp_resolver[];

extern post_resolve_heuristic_func post_resolve_heuristics[];

int translate_datatype_to_byte(cs_insn* insn);

#define INIT_MEM(mem, op_type, op_datatype, op_access, base_reg, index_reg) \
	memset((mem), 0, sizeof(cs_arm_op)); \
	(mem)->type = op_type; \
	(mem)->datatype = op_datatype; \
	(mem)->access = op_access; \
	(mem)->mem.base = base_reg; \
	(mem)->mem.index = index_reg;
#define INIT_SPMEM(espmem, op_type, op_datatype, op_access, espreg) \
	memset((espmem), 0, sizeof(cs_arm_op)); \
	(espmem)->type = op_type; \
	(espmem)->datatype = op_datatype; \
	(espmem)->access = op_access; \
	(espmem)->mem.base = espreg->reg;

#define INIT_REGOPD(regopd,op_type, op_access, oreg) \
	memset((regopd), 0, sizeof(cs_arm_op)); \
	(regopd)->type = op_type; \
	(regopd)->access = op_access; \
	(regopd)->reg = oreg;
    
// convert all the offset to expression
#define x86_opd_is_register(opd) \
    ((opd)->type == ARM_OP_REG)
#define x86_opd_is_mem(opd) \
    ((opd)->type == ARM_OP_MEM)

// note this is to check return value
#define x86_opd_is_eax(opd) \
    (((opd)->type == ARM_OP_REG) && ((opd)->reg == ARM_REG_R0))

#define x86_opd_is_esp(opd) \
    (((opd)->type == ARM_OP_REG) && ((opd)->reg == ARM_REG_SP))

#define x86_base_is_esp(opd) \
    (((opd)->type == ARM_OP_MEM) && ((opd)->mem.base == ARM_REG_SP))

// maybe impossible, just list it here
#define x86_index_is_esp(opd) \
    (((opd)->type == ARM_OP_MEM) && ((opd)->mem.index == ARM_REG_SP))

#define x86_opd_is_ebp(opd) \
    (((opd)->type == ARM_OP_REG) && ((opd)->reg == ARM_REG_FP))
#define arm_opd_is_register(opd) \
    ((opd)->type == ARM_OP_REG)

#define exact_same_regs(reg1, reg2) \
    (reg1 == reg2)

#define reg1_alias_reg2(reg1, reg2) \
    (reg1 == reg2)

#define same_alias(reg1, reg2) \
    ((reg1 == reg2) && (reg1 != 0))

#define exact_same_mem(address1, size1, address2, size2) \
	((address1 == address2) && (size1 == size2))

#define subset_mem(address1, size1, address2, size2) \
	((address1 >= address2) && (address1+size1 <= address2+size2) && (address1 < address1+size1))

#define superset_mem(address1, size1, address2, size2) \
	((address1 <= address2) && (address1+size1 >= address2+size2) && (address2 < address2+size2))

#define overlap_mem(address1, size1, address2, size2) \
	(((address1+size1 > address2) && (address1+size1 <= address2+size2)) || ((address2+size2 > address1) && (address2+size2 <= address1+size1)))
#define nooverlap_mem(address1, size1, address2, size2) \
	((address1 >= address2 + size2) || (address2 >= address1 + size1))
#define reg1_reg2(dest, src) \
    (arm_opd_is_register(dest) && arm_opd_is_register(src))

#define reg1_exp2(dest, src) \
    (arm_opd_is_register(dest) && (src->type == ARM_OP_MEM))

#define exp1_reg2(dest, src) \
    (arm_opd_is_register(src) && (dest->type == ARM_OP_MEM))

#define off1_reg2(dest, src) \
    ((dest->type == op_offset) && (src->type == ARM_OP_REG))

#define reg1_off2(dest, src) \
    ((dest->type == ARM_OP_REG) && (src->type == op_offset))

#define exp1_imm2(dest, src) \
    ((dest->type ==ARM_OP_MEM) && (src->type == ARM_OP_IMM))	

#define reg1_imm2(dest, src) \
    ((dest->type ==ARM_OP_REG) && (src->type == ARM_OP_IMM))	

#define same_reg(dest, src) \
    (reg1_reg2(dest, src) && exact_same_regs(dest->data.reg,src->data.reg))

#define diff_regs(dest, src) \
    (reg1_reg2(dest, src) && (!exact_same_regs(dest->data.reg,src->data.reg)))

#define op_with_gs_seg(opd) \
	(((opd)->flags & op_gs_seg) >> 8 == 6)


/*
#define defreg_useexp(define, use) \
    ((define->opd.type == ARM_OP_REG) && (use->opd.type == ARM_OP_MEM))

#define defreg_usereg(define, use) \
    ((define->opd.type == ARM_OP_REG) && (use->opd.type == ARM_OP_REG))

#define defexp_useexp(define, use) \
    ((define->opd.type == ARM_OP_MEM) && (use->opd.type == ARM_OP_MEM))
*/

enum expreg_status {
	No_Reg = 0x0,
	Base_Reg,
	Index_Reg,
	Base_Index_Reg
};

static inline enum expreg_status get_expreg_status(arm_op_mem exp){
	if ((exp.base != 0) && (exp.index != 0)) {
		return Base_Index_Reg;
	}
	if ((exp.base != 0) && (exp.index == 0)) {
		return Base_Reg;
	}
	if ((exp.base == 0) && (exp.index != 0)) {
		return Index_Reg;
	}
	if ((exp.base == 0) && (exp.index == 0)) {
		return No_Reg;
	}
}


enum operand_status {
    dest_register_src_register = 1,
    dest_register_src_expression,
    dest_register_src_offset,
    dest_expression_src_register,
    dest_offset_src_register,
    dest_expression_src_imm,
    dest_register_src_imm
};


static inline enum operand_status get_operand_combine(cs_insn *inst) {

    cs_arm_op *dst[MOPD], *src[MOPD];
    uint8_t ndst, nsrc;
    ndst = arm_get_dst_operand(inst, dst);
    nsrc = arm_get_src_operand(inst, src);
    if (reg1_reg2(dst[0], src[0])) return dest_register_src_register;
    if (reg1_exp2(dst[0], src[0])) return dest_register_src_expression;
    // if (reg1_off2(dst, src)) return dest_register_src_offset;
    if (exp1_reg2(dst[0], src[0])) return dest_expression_src_register;
    // if (off1_reg2(dst, src)) return dest_offset_src_register;
    // if (reg1_off2(dst, src)) return dest_register_src_offset;
    if (exp1_imm2(dst[0], src[0])) return dest_expression_src_imm;
    if (reg1_imm2(dst[0], src[0])) return dest_register_src_imm;
    LOG(stderr, "ERROR: get_operand_combine error 0x%lx %s %s\n",inst->address, inst->mnemonic, inst->op_str);		
    assert(0);
}
#ifdef VSA
#if defined (ALIAS_MODULE) && (ALIAS_MODULE == VSA_MODULE)
// vsa handlers
void invalid_vs_handler(re_list_t *instnode);

void general_vs_handler(re_list_t *instnode);

void asr_vs_handler(re_list_t *instnode);

void it_vs_handler(re_list_t *instnode);

void ldrbt_vs_handler(re_list_t *instnode);

void ldr_vs_handler(re_list_t *instnode);

void ldrht_vs_handler(re_list_t *instnode);

void ldrsbt_vs_handler(re_list_t *instnode);

void ldrsht_vs_handler(re_list_t *instnode);

void ldrt_vs_handler(re_list_t *instnode);

void lsl_vs_handler(re_list_t *instnode);

void lsr_vs_handler(re_list_t *instnode);

void ror_vs_handler(re_list_t *instnode);

void rrx_vs_handler(re_list_t *instnode);

void strbt_vs_handler(re_list_t *instnode);

void strt_vs_handler(re_list_t *instnode);

void vld1_vs_handler(re_list_t *instnode);

void vld2_vs_handler(re_list_t *instnode);

void vld3_vs_handler(re_list_t *instnode);

void vld4_vs_handler(re_list_t *instnode);

void vst1_vs_handler(re_list_t *instnode);

void vst2_vs_handler(re_list_t *instnode);

void vst3_vs_handler(re_list_t *instnode);

void vst4_vs_handler(re_list_t *instnode);

void ldrb_vs_handler(re_list_t *instnode);

void ldrh_vs_handler(re_list_t *instnode);

void ldrsb_vs_handler(re_list_t *instnode);

void ldrsh_vs_handler(re_list_t *instnode);

void movs_vs_handler(re_list_t *instnode);

void mov_vs_handler(re_list_t *instnode);

void str_vs_handler(re_list_t *instnode);

void adc_vs_handler(re_list_t *instnode);

void add_vs_handler(re_list_t *instnode);

void adr_vs_handler(re_list_t *instnode);

void aesd_vs_handler(re_list_t *instnode);

void aese_vs_handler(re_list_t *instnode);

void aesimc_vs_handler(re_list_t *instnode);

void aesmc_vs_handler(re_list_t *instnode);

void and_vs_handler(re_list_t *instnode);

void vdot_vs_handler(re_list_t *instnode);

void vcvt_vs_handler(re_list_t *instnode);

void vcvtb_vs_handler(re_list_t *instnode);

void vcvtt_vs_handler(re_list_t *instnode);

void bfc_vs_handler(re_list_t *instnode);

void bfi_vs_handler(re_list_t *instnode);

void bic_vs_handler(re_list_t *instnode);

void bkpt_vs_handler(re_list_t *instnode);

void bl_vs_handler(re_list_t *instnode);

void blx_vs_handler(re_list_t *instnode);

void bx_vs_handler(re_list_t *instnode);

void bxj_vs_handler(re_list_t *instnode);

void b_vs_handler(re_list_t *instnode);

void cx1_vs_handler(re_list_t *instnode);

void cx1a_vs_handler(re_list_t *instnode);

void cx1d_vs_handler(re_list_t *instnode);

void cx1da_vs_handler(re_list_t *instnode);

void cx2_vs_handler(re_list_t *instnode);

void cx2a_vs_handler(re_list_t *instnode);

void cx2d_vs_handler(re_list_t *instnode);

void cx2da_vs_handler(re_list_t *instnode);

void cx3_vs_handler(re_list_t *instnode);

void cx3a_vs_handler(re_list_t *instnode);

void cx3d_vs_handler(re_list_t *instnode);

void cx3da_vs_handler(re_list_t *instnode);

void vcx1a_vs_handler(re_list_t *instnode);

void vcx1_vs_handler(re_list_t *instnode);

void vcx2a_vs_handler(re_list_t *instnode);

void vcx2_vs_handler(re_list_t *instnode);

void vcx3a_vs_handler(re_list_t *instnode);

void vcx3_vs_handler(re_list_t *instnode);

void cdp_vs_handler(re_list_t *instnode);

void cdp2_vs_handler(re_list_t *instnode);

void clrex_vs_handler(re_list_t *instnode);

void clz_vs_handler(re_list_t *instnode);

void cmn_vs_handler(re_list_t *instnode);

void cmp_vs_handler(re_list_t *instnode);

void cps_vs_handler(re_list_t *instnode);

void crc32b_vs_handler(re_list_t *instnode);

void crc32cb_vs_handler(re_list_t *instnode);

void crc32ch_vs_handler(re_list_t *instnode);

void crc32cw_vs_handler(re_list_t *instnode);

void crc32h_vs_handler(re_list_t *instnode);

void crc32w_vs_handler(re_list_t *instnode);

void dbg_vs_handler(re_list_t *instnode);

void dmb_vs_handler(re_list_t *instnode);

void dsb_vs_handler(re_list_t *instnode);

void eor_vs_handler(re_list_t *instnode);

void eret_vs_handler(re_list_t *instnode);

void vmov_vs_handler(re_list_t *instnode);

void fldmdbx_vs_handler(re_list_t *instnode);

void fldmiax_vs_handler(re_list_t *instnode);

void vmrs_vs_handler(re_list_t *instnode);

void fstmdbx_vs_handler(re_list_t *instnode);

void fstmiax_vs_handler(re_list_t *instnode);

void hint_vs_handler(re_list_t *instnode);

void hlt_vs_handler(re_list_t *instnode);

void hvc_vs_handler(re_list_t *instnode);

void isb_vs_handler(re_list_t *instnode);

void lda_vs_handler(re_list_t *instnode);

void ldab_vs_handler(re_list_t *instnode);

void ldaex_vs_handler(re_list_t *instnode);

void ldaexb_vs_handler(re_list_t *instnode);

void ldaexd_vs_handler(re_list_t *instnode);

void ldaexh_vs_handler(re_list_t *instnode);

void ldah_vs_handler(re_list_t *instnode);

void ldc2l_vs_handler(re_list_t *instnode);

void ldc2_vs_handler(re_list_t *instnode);

void ldcl_vs_handler(re_list_t *instnode);

void ldc_vs_handler(re_list_t *instnode);

void ldmda_vs_handler(re_list_t *instnode);

void ldmdb_vs_handler(re_list_t *instnode);

void ldm_vs_handler(re_list_t *instnode);

void ldmib_vs_handler(re_list_t *instnode);

void ldrd_vs_handler(re_list_t *instnode);

void ldrex_vs_handler(re_list_t *instnode);

void ldrexb_vs_handler(re_list_t *instnode);

void ldrexd_vs_handler(re_list_t *instnode);

void ldrexh_vs_handler(re_list_t *instnode);

void mcr_vs_handler(re_list_t *instnode);

void mcr2_vs_handler(re_list_t *instnode);

void mcrr_vs_handler(re_list_t *instnode);

void mcrr2_vs_handler(re_list_t *instnode);

void mla_vs_handler(re_list_t *instnode);

void mls_vs_handler(re_list_t *instnode);

void movt_vs_handler(re_list_t *instnode);

void movw_vs_handler(re_list_t *instnode);

void mrc_vs_handler(re_list_t *instnode);

void mrc2_vs_handler(re_list_t *instnode);

void mrrc_vs_handler(re_list_t *instnode);

void mrrc2_vs_handler(re_list_t *instnode);

void mrs_vs_handler(re_list_t *instnode);

void msr_vs_handler(re_list_t *instnode);

void mul_vs_handler(re_list_t *instnode);

void asrl_vs_handler(re_list_t *instnode);

void dlstp_vs_handler(re_list_t *instnode);

void lctp_vs_handler(re_list_t *instnode);

void letp_vs_handler(re_list_t *instnode);

void lsll_vs_handler(re_list_t *instnode);

void lsrl_vs_handler(re_list_t *instnode);

void sqrshr_vs_handler(re_list_t *instnode);

void sqrshrl_vs_handler(re_list_t *instnode);

void sqshl_vs_handler(re_list_t *instnode);

void sqshll_vs_handler(re_list_t *instnode);

void srshr_vs_handler(re_list_t *instnode);

void srshrl_vs_handler(re_list_t *instnode);

void uqrshl_vs_handler(re_list_t *instnode);

void uqrshll_vs_handler(re_list_t *instnode);

void uqshl_vs_handler(re_list_t *instnode);

void uqshll_vs_handler(re_list_t *instnode);

void urshr_vs_handler(re_list_t *instnode);

void urshrl_vs_handler(re_list_t *instnode);

void vabav_vs_handler(re_list_t *instnode);

void vabd_vs_handler(re_list_t *instnode);

void vabs_vs_handler(re_list_t *instnode);

void vadc_vs_handler(re_list_t *instnode);

void vadci_vs_handler(re_list_t *instnode);

void vaddlva_vs_handler(re_list_t *instnode);

void vaddlv_vs_handler(re_list_t *instnode);

void vaddva_vs_handler(re_list_t *instnode);

void vaddv_vs_handler(re_list_t *instnode);

void vadd_vs_handler(re_list_t *instnode);

void vand_vs_handler(re_list_t *instnode);

void vbic_vs_handler(re_list_t *instnode);

void vbrsr_vs_handler(re_list_t *instnode);

void vcadd_vs_handler(re_list_t *instnode);

void vcls_vs_handler(re_list_t *instnode);

void vclz_vs_handler(re_list_t *instnode);

void vcmla_vs_handler(re_list_t *instnode);

void vcmp_vs_handler(re_list_t *instnode);

void vcmul_vs_handler(re_list_t *instnode);

void vctp_vs_handler(re_list_t *instnode);

void vcvta_vs_handler(re_list_t *instnode);

void vcvtm_vs_handler(re_list_t *instnode);

void vcvtn_vs_handler(re_list_t *instnode);

void vcvtp_vs_handler(re_list_t *instnode);

void vddup_vs_handler(re_list_t *instnode);

void vdup_vs_handler(re_list_t *instnode);

void vdwdup_vs_handler(re_list_t *instnode);

void veor_vs_handler(re_list_t *instnode);

void vfmas_vs_handler(re_list_t *instnode);

void vfma_vs_handler(re_list_t *instnode);

void vfms_vs_handler(re_list_t *instnode);

void vhadd_vs_handler(re_list_t *instnode);

void vhcadd_vs_handler(re_list_t *instnode);

void vhsub_vs_handler(re_list_t *instnode);

void vidup_vs_handler(re_list_t *instnode);

void viwdup_vs_handler(re_list_t *instnode);

void vld20_vs_handler(re_list_t *instnode);

void vld21_vs_handler(re_list_t *instnode);

void vld40_vs_handler(re_list_t *instnode);

void vld41_vs_handler(re_list_t *instnode);

void vld42_vs_handler(re_list_t *instnode);

void vld43_vs_handler(re_list_t *instnode);

void vldrb_vs_handler(re_list_t *instnode);

void vldrd_vs_handler(re_list_t *instnode);

void vldrh_vs_handler(re_list_t *instnode);

void vldrw_vs_handler(re_list_t *instnode);

void vmaxav_vs_handler(re_list_t *instnode);

void vmaxa_vs_handler(re_list_t *instnode);

void vmaxnmav_vs_handler(re_list_t *instnode);

void vmaxnma_vs_handler(re_list_t *instnode);

void vmaxnmv_vs_handler(re_list_t *instnode);

void vmaxnm_vs_handler(re_list_t *instnode);

void vmaxv_vs_handler(re_list_t *instnode);

void vmax_vs_handler(re_list_t *instnode);

void vminav_vs_handler(re_list_t *instnode);

void vmina_vs_handler(re_list_t *instnode);

void vminnmav_vs_handler(re_list_t *instnode);

void vminnma_vs_handler(re_list_t *instnode);

void vminnmv_vs_handler(re_list_t *instnode);

void vminnm_vs_handler(re_list_t *instnode);

void vminv_vs_handler(re_list_t *instnode);

void vmin_vs_handler(re_list_t *instnode);

void vmladava_vs_handler(re_list_t *instnode);

void vmladavax_vs_handler(re_list_t *instnode);

void vmladav_vs_handler(re_list_t *instnode);

void vmladavx_vs_handler(re_list_t *instnode);

void vmlaldava_vs_handler(re_list_t *instnode);

void vmlaldavax_vs_handler(re_list_t *instnode);

void vmlaldav_vs_handler(re_list_t *instnode);

void vmlaldavx_vs_handler(re_list_t *instnode);

void vmlas_vs_handler(re_list_t *instnode);

void vmla_vs_handler(re_list_t *instnode);

void vmlsdava_vs_handler(re_list_t *instnode);

void vmlsdavax_vs_handler(re_list_t *instnode);

void vmlsdav_vs_handler(re_list_t *instnode);

void vmlsdavx_vs_handler(re_list_t *instnode);

void vmlsldava_vs_handler(re_list_t *instnode);

void vmlsldavax_vs_handler(re_list_t *instnode);

void vmlsldav_vs_handler(re_list_t *instnode);

void vmlsldavx_vs_handler(re_list_t *instnode);

void vmovlb_vs_handler(re_list_t *instnode);

void vmovlt_vs_handler(re_list_t *instnode);

void vmovnb_vs_handler(re_list_t *instnode);

void vmovnt_vs_handler(re_list_t *instnode);

void vmulh_vs_handler(re_list_t *instnode);

void vmullb_vs_handler(re_list_t *instnode);

void vmullt_vs_handler(re_list_t *instnode);

void vmul_vs_handler(re_list_t *instnode);

void vmvn_vs_handler(re_list_t *instnode);

void vneg_vs_handler(re_list_t *instnode);

void vorn_vs_handler(re_list_t *instnode);

void vorr_vs_handler(re_list_t *instnode);

void vpnot_vs_handler(re_list_t *instnode);

void vpsel_vs_handler(re_list_t *instnode);

void vpst_vs_handler(re_list_t *instnode);

void vpt_vs_handler(re_list_t *instnode);

void vqabs_vs_handler(re_list_t *instnode);

void vqadd_vs_handler(re_list_t *instnode);

void vqdmladhx_vs_handler(re_list_t *instnode);

void vqdmladh_vs_handler(re_list_t *instnode);

void vqdmlah_vs_handler(re_list_t *instnode);

void vqdmlash_vs_handler(re_list_t *instnode);

void vqdmlsdhx_vs_handler(re_list_t *instnode);

void vqdmlsdh_vs_handler(re_list_t *instnode);

void vqdmulh_vs_handler(re_list_t *instnode);

void vqdmullb_vs_handler(re_list_t *instnode);

void vqdmullt_vs_handler(re_list_t *instnode);

void vqmovnb_vs_handler(re_list_t *instnode);

void vqmovnt_vs_handler(re_list_t *instnode);

void vqmovunb_vs_handler(re_list_t *instnode);

void vqmovunt_vs_handler(re_list_t *instnode);

void vqneg_vs_handler(re_list_t *instnode);

void vqrdmladhx_vs_handler(re_list_t *instnode);

void vqrdmladh_vs_handler(re_list_t *instnode);

void vqrdmlah_vs_handler(re_list_t *instnode);

void vqrdmlash_vs_handler(re_list_t *instnode);

void vqrdmlsdhx_vs_handler(re_list_t *instnode);

void vqrdmlsdh_vs_handler(re_list_t *instnode);

void vqrdmulh_vs_handler(re_list_t *instnode);

void vqrshl_vs_handler(re_list_t *instnode);

void vqrshrnb_vs_handler(re_list_t *instnode);

void vqrshrnt_vs_handler(re_list_t *instnode);

void vqrshrunb_vs_handler(re_list_t *instnode);

void vqrshrunt_vs_handler(re_list_t *instnode);

void vqshlu_vs_handler(re_list_t *instnode);

void vqshl_vs_handler(re_list_t *instnode);

void vqshrnb_vs_handler(re_list_t *instnode);

void vqshrnt_vs_handler(re_list_t *instnode);

void vqshrunb_vs_handler(re_list_t *instnode);

void vqshrunt_vs_handler(re_list_t *instnode);

void vqsub_vs_handler(re_list_t *instnode);

void vrev16_vs_handler(re_list_t *instnode);

void vrev32_vs_handler(re_list_t *instnode);

void vrev64_vs_handler(re_list_t *instnode);

void vrhadd_vs_handler(re_list_t *instnode);

void vrinta_vs_handler(re_list_t *instnode);

void vrintm_vs_handler(re_list_t *instnode);

void vrintn_vs_handler(re_list_t *instnode);

void vrintp_vs_handler(re_list_t *instnode);

void vrintx_vs_handler(re_list_t *instnode);

void vrintz_vs_handler(re_list_t *instnode);

void vrmlaldavha_vs_handler(re_list_t *instnode);

void vrmlaldavhax_vs_handler(re_list_t *instnode);

void vrmlaldavh_vs_handler(re_list_t *instnode);

void vrmlaldavhx_vs_handler(re_list_t *instnode);

void vrmlsldavha_vs_handler(re_list_t *instnode);

void vrmlsldavhax_vs_handler(re_list_t *instnode);

void vrmlsldavh_vs_handler(re_list_t *instnode);

void vrmlsldavhx_vs_handler(re_list_t *instnode);

void vrmulh_vs_handler(re_list_t *instnode);

void vrshl_vs_handler(re_list_t *instnode);

void vrshrnb_vs_handler(re_list_t *instnode);

void vrshrnt_vs_handler(re_list_t *instnode);

void vrshr_vs_handler(re_list_t *instnode);

void vsbc_vs_handler(re_list_t *instnode);

void vsbci_vs_handler(re_list_t *instnode);

void vshlc_vs_handler(re_list_t *instnode);

void vshllb_vs_handler(re_list_t *instnode);

void vshllt_vs_handler(re_list_t *instnode);

void vshl_vs_handler(re_list_t *instnode);

void vshrnb_vs_handler(re_list_t *instnode);

void vshrnt_vs_handler(re_list_t *instnode);

void vshr_vs_handler(re_list_t *instnode);

void vsli_vs_handler(re_list_t *instnode);

void vsri_vs_handler(re_list_t *instnode);

void vst20_vs_handler(re_list_t *instnode);

void vst21_vs_handler(re_list_t *instnode);

void vst40_vs_handler(re_list_t *instnode);

void vst41_vs_handler(re_list_t *instnode);

void vst42_vs_handler(re_list_t *instnode);

void vst43_vs_handler(re_list_t *instnode);

void vstrb_vs_handler(re_list_t *instnode);

void vstrd_vs_handler(re_list_t *instnode);

void vstrh_vs_handler(re_list_t *instnode);

void vstrw_vs_handler(re_list_t *instnode);

void vsub_vs_handler(re_list_t *instnode);

void wlstp_vs_handler(re_list_t *instnode);

void mvn_vs_handler(re_list_t *instnode);

void orr_vs_handler(re_list_t *instnode);

void pkhbt_vs_handler(re_list_t *instnode);

void pkhtb_vs_handler(re_list_t *instnode);

void pldw_vs_handler(re_list_t *instnode);

void pld_vs_handler(re_list_t *instnode);

void pli_vs_handler(re_list_t *instnode);

void qadd_vs_handler(re_list_t *instnode);

void qadd16_vs_handler(re_list_t *instnode);

void qadd8_vs_handler(re_list_t *instnode);

void qasx_vs_handler(re_list_t *instnode);

void qdadd_vs_handler(re_list_t *instnode);

void qdsub_vs_handler(re_list_t *instnode);

void qsax_vs_handler(re_list_t *instnode);

void qsub_vs_handler(re_list_t *instnode);

void qsub16_vs_handler(re_list_t *instnode);

void qsub8_vs_handler(re_list_t *instnode);

void rbit_vs_handler(re_list_t *instnode);

void rev_vs_handler(re_list_t *instnode);

void rev16_vs_handler(re_list_t *instnode);

void revsh_vs_handler(re_list_t *instnode);

void rfeda_vs_handler(re_list_t *instnode);

void rfedb_vs_handler(re_list_t *instnode);

void rfeia_vs_handler(re_list_t *instnode);

void rfeib_vs_handler(re_list_t *instnode);

void rsb_vs_handler(re_list_t *instnode);

void rsc_vs_handler(re_list_t *instnode);

void sadd16_vs_handler(re_list_t *instnode);

void sadd8_vs_handler(re_list_t *instnode);

void sasx_vs_handler(re_list_t *instnode);

void sb_vs_handler(re_list_t *instnode);

void sbc_vs_handler(re_list_t *instnode);

void sbfx_vs_handler(re_list_t *instnode);

void sdiv_vs_handler(re_list_t *instnode);

void sel_vs_handler(re_list_t *instnode);

void setend_vs_handler(re_list_t *instnode);

void setpan_vs_handler(re_list_t *instnode);

void sha1c_vs_handler(re_list_t *instnode);

void sha1h_vs_handler(re_list_t *instnode);

void sha1m_vs_handler(re_list_t *instnode);

void sha1p_vs_handler(re_list_t *instnode);

void sha1su0_vs_handler(re_list_t *instnode);

void sha1su1_vs_handler(re_list_t *instnode);

void sha256h_vs_handler(re_list_t *instnode);

void sha256h2_vs_handler(re_list_t *instnode);

void sha256su0_vs_handler(re_list_t *instnode);

void sha256su1_vs_handler(re_list_t *instnode);

void shadd16_vs_handler(re_list_t *instnode);

void shadd8_vs_handler(re_list_t *instnode);

void shasx_vs_handler(re_list_t *instnode);

void shsax_vs_handler(re_list_t *instnode);

void shsub16_vs_handler(re_list_t *instnode);

void shsub8_vs_handler(re_list_t *instnode);

void smc_vs_handler(re_list_t *instnode);

void smlabb_vs_handler(re_list_t *instnode);

void smlabt_vs_handler(re_list_t *instnode);

void smlad_vs_handler(re_list_t *instnode);

void smladx_vs_handler(re_list_t *instnode);

void smlal_vs_handler(re_list_t *instnode);

void smlalbb_vs_handler(re_list_t *instnode);

void smlalbt_vs_handler(re_list_t *instnode);

void smlald_vs_handler(re_list_t *instnode);

void smlaldx_vs_handler(re_list_t *instnode);

void smlaltb_vs_handler(re_list_t *instnode);

void smlaltt_vs_handler(re_list_t *instnode);

void smlatb_vs_handler(re_list_t *instnode);

void smlatt_vs_handler(re_list_t *instnode);

void smlawb_vs_handler(re_list_t *instnode);

void smlawt_vs_handler(re_list_t *instnode);

void smlsd_vs_handler(re_list_t *instnode);

void smlsdx_vs_handler(re_list_t *instnode);

void smlsld_vs_handler(re_list_t *instnode);

void smlsldx_vs_handler(re_list_t *instnode);

void smmla_vs_handler(re_list_t *instnode);

void smmlar_vs_handler(re_list_t *instnode);

void smmls_vs_handler(re_list_t *instnode);

void smmlsr_vs_handler(re_list_t *instnode);

void smmul_vs_handler(re_list_t *instnode);

void smmulr_vs_handler(re_list_t *instnode);

void smuad_vs_handler(re_list_t *instnode);

void smuadx_vs_handler(re_list_t *instnode);

void smulbb_vs_handler(re_list_t *instnode);

void smulbt_vs_handler(re_list_t *instnode);

void smull_vs_handler(re_list_t *instnode);

void smultb_vs_handler(re_list_t *instnode);

void smultt_vs_handler(re_list_t *instnode);

void smulwb_vs_handler(re_list_t *instnode);

void smulwt_vs_handler(re_list_t *instnode);

void smusd_vs_handler(re_list_t *instnode);

void smusdx_vs_handler(re_list_t *instnode);

void srsda_vs_handler(re_list_t *instnode);

void srsdb_vs_handler(re_list_t *instnode);

void srsia_vs_handler(re_list_t *instnode);

void srsib_vs_handler(re_list_t *instnode);

void ssat_vs_handler(re_list_t *instnode);

void ssat16_vs_handler(re_list_t *instnode);

void ssax_vs_handler(re_list_t *instnode);

void ssub16_vs_handler(re_list_t *instnode);

void ssub8_vs_handler(re_list_t *instnode);

void stc2l_vs_handler(re_list_t *instnode);

void stc2_vs_handler(re_list_t *instnode);

void stcl_vs_handler(re_list_t *instnode);

void stc_vs_handler(re_list_t *instnode);

void stl_vs_handler(re_list_t *instnode);

void stlb_vs_handler(re_list_t *instnode);

void stlex_vs_handler(re_list_t *instnode);

void stlexb_vs_handler(re_list_t *instnode);

void stlexd_vs_handler(re_list_t *instnode);

void stlexh_vs_handler(re_list_t *instnode);

void stlh_vs_handler(re_list_t *instnode);

void stmda_vs_handler(re_list_t *instnode);

void stmdb_vs_handler(re_list_t *instnode);

void stm_vs_handler(re_list_t *instnode);

void stmib_vs_handler(re_list_t *instnode);

void strb_vs_handler(re_list_t *instnode);

void strd_vs_handler(re_list_t *instnode);

void strex_vs_handler(re_list_t *instnode);

void strexb_vs_handler(re_list_t *instnode);

void strexd_vs_handler(re_list_t *instnode);

void strexh_vs_handler(re_list_t *instnode);

void strh_vs_handler(re_list_t *instnode);

void strht_vs_handler(re_list_t *instnode);

void sub_vs_handler(re_list_t *instnode);

void svc_vs_handler(re_list_t *instnode);

void swp_vs_handler(re_list_t *instnode);

void swpb_vs_handler(re_list_t *instnode);

void sxtab_vs_handler(re_list_t *instnode);

void sxtab16_vs_handler(re_list_t *instnode);

void sxtah_vs_handler(re_list_t *instnode);

void sxtb_vs_handler(re_list_t *instnode);

void sxtb16_vs_handler(re_list_t *instnode);

void sxth_vs_handler(re_list_t *instnode);

void teq_vs_handler(re_list_t *instnode);

void trap_vs_handler(re_list_t *instnode);

void tsb_vs_handler(re_list_t *instnode);

void tst_vs_handler(re_list_t *instnode);

void uadd16_vs_handler(re_list_t *instnode);

void uadd8_vs_handler(re_list_t *instnode);

void uasx_vs_handler(re_list_t *instnode);

void ubfx_vs_handler(re_list_t *instnode);

void udf_vs_handler(re_list_t *instnode);

void udiv_vs_handler(re_list_t *instnode);

void uhadd16_vs_handler(re_list_t *instnode);

void uhadd8_vs_handler(re_list_t *instnode);

void uhasx_vs_handler(re_list_t *instnode);

void uhsax_vs_handler(re_list_t *instnode);

void uhsub16_vs_handler(re_list_t *instnode);

void uhsub8_vs_handler(re_list_t *instnode);

void umaal_vs_handler(re_list_t *instnode);

void umlal_vs_handler(re_list_t *instnode);

void umull_vs_handler(re_list_t *instnode);

void uqadd16_vs_handler(re_list_t *instnode);

void uqadd8_vs_handler(re_list_t *instnode);

void uqasx_vs_handler(re_list_t *instnode);

void uqsax_vs_handler(re_list_t *instnode);

void uqsub16_vs_handler(re_list_t *instnode);

void uqsub8_vs_handler(re_list_t *instnode);

void usad8_vs_handler(re_list_t *instnode);

void usada8_vs_handler(re_list_t *instnode);

void usat_vs_handler(re_list_t *instnode);

void usat16_vs_handler(re_list_t *instnode);

void usax_vs_handler(re_list_t *instnode);

void usub16_vs_handler(re_list_t *instnode);

void usub8_vs_handler(re_list_t *instnode);

void uxtab_vs_handler(re_list_t *instnode);

void uxtab16_vs_handler(re_list_t *instnode);

void uxtah_vs_handler(re_list_t *instnode);

void uxtb_vs_handler(re_list_t *instnode);

void uxtb16_vs_handler(re_list_t *instnode);

void uxth_vs_handler(re_list_t *instnode);

void vabal_vs_handler(re_list_t *instnode);

void vaba_vs_handler(re_list_t *instnode);

void vabdl_vs_handler(re_list_t *instnode);

void vacge_vs_handler(re_list_t *instnode);

void vacgt_vs_handler(re_list_t *instnode);

void vaddhn_vs_handler(re_list_t *instnode);

void vaddl_vs_handler(re_list_t *instnode);

void vaddw_vs_handler(re_list_t *instnode);

void vfmab_vs_handler(re_list_t *instnode);

void vfmat_vs_handler(re_list_t *instnode);

void vbif_vs_handler(re_list_t *instnode);

void vbit_vs_handler(re_list_t *instnode);

void vbsl_vs_handler(re_list_t *instnode);

void vceq_vs_handler(re_list_t *instnode);

void vcge_vs_handler(re_list_t *instnode);

void vcgt_vs_handler(re_list_t *instnode);

void vcle_vs_handler(re_list_t *instnode);

void vclt_vs_handler(re_list_t *instnode);

void vcmpe_vs_handler(re_list_t *instnode);

void vcnt_vs_handler(re_list_t *instnode);

void vdiv_vs_handler(re_list_t *instnode);

void vext_vs_handler(re_list_t *instnode);

void vfmal_vs_handler(re_list_t *instnode);

void vfmsl_vs_handler(re_list_t *instnode);

void vfnma_vs_handler(re_list_t *instnode);

void vfnms_vs_handler(re_list_t *instnode);

void vins_vs_handler(re_list_t *instnode);

void vjcvt_vs_handler(re_list_t *instnode);

void vldmdb_vs_handler(re_list_t *instnode);

void vldmia_vs_handler(re_list_t *instnode);

void vldr_vs_handler(re_list_t *instnode);

void vlldm_vs_handler(re_list_t *instnode);

void vlstm_vs_handler(re_list_t *instnode);

void vmlal_vs_handler(re_list_t *instnode);

void vmls_vs_handler(re_list_t *instnode);

void vmlsl_vs_handler(re_list_t *instnode);

void vmmla_vs_handler(re_list_t *instnode);

void vmovx_vs_handler(re_list_t *instnode);

void vmovl_vs_handler(re_list_t *instnode);

void vmovn_vs_handler(re_list_t *instnode);

void vmsr_vs_handler(re_list_t *instnode);

void vmull_vs_handler(re_list_t *instnode);

void vnmla_vs_handler(re_list_t *instnode);

void vnmls_vs_handler(re_list_t *instnode);

void vnmul_vs_handler(re_list_t *instnode);

void vpadal_vs_handler(re_list_t *instnode);

void vpaddl_vs_handler(re_list_t *instnode);

void vpadd_vs_handler(re_list_t *instnode);

void vpmax_vs_handler(re_list_t *instnode);

void vpmin_vs_handler(re_list_t *instnode);

void vqdmlal_vs_handler(re_list_t *instnode);

void vqdmlsl_vs_handler(re_list_t *instnode);

void vqdmull_vs_handler(re_list_t *instnode);

void vqmovun_vs_handler(re_list_t *instnode);

void vqmovn_vs_handler(re_list_t *instnode);

void vqrdmlsh_vs_handler(re_list_t *instnode);

void vqrshrn_vs_handler(re_list_t *instnode);

void vqrshrun_vs_handler(re_list_t *instnode);

void vqshrn_vs_handler(re_list_t *instnode);

void vqshrun_vs_handler(re_list_t *instnode);

void vraddhn_vs_handler(re_list_t *instnode);

void vrecpe_vs_handler(re_list_t *instnode);

void vrecps_vs_handler(re_list_t *instnode);

void vrintr_vs_handler(re_list_t *instnode);

void vrshrn_vs_handler(re_list_t *instnode);

void vrsqrte_vs_handler(re_list_t *instnode);

void vrsqrts_vs_handler(re_list_t *instnode);

void vrsra_vs_handler(re_list_t *instnode);

void vrsubhn_vs_handler(re_list_t *instnode);

void vscclrm_vs_handler(re_list_t *instnode);

void vsdot_vs_handler(re_list_t *instnode);

void vseleq_vs_handler(re_list_t *instnode);

void vselge_vs_handler(re_list_t *instnode);

void vselgt_vs_handler(re_list_t *instnode);

void vselvs_vs_handler(re_list_t *instnode);

void vshll_vs_handler(re_list_t *instnode);

void vshrn_vs_handler(re_list_t *instnode);

void vsmmla_vs_handler(re_list_t *instnode);

void vsqrt_vs_handler(re_list_t *instnode);

void vsra_vs_handler(re_list_t *instnode);

void vstmdb_vs_handler(re_list_t *instnode);

void vstmia_vs_handler(re_list_t *instnode);

void vstr_vs_handler(re_list_t *instnode);

void vsubhn_vs_handler(re_list_t *instnode);

void vsubl_vs_handler(re_list_t *instnode);

void vsubw_vs_handler(re_list_t *instnode);

void vsudot_vs_handler(re_list_t *instnode);

void vswp_vs_handler(re_list_t *instnode);

void vtbl_vs_handler(re_list_t *instnode);

void vtbx_vs_handler(re_list_t *instnode);

void vcvtr_vs_handler(re_list_t *instnode);

void vtrn_vs_handler(re_list_t *instnode);

void vtst_vs_handler(re_list_t *instnode);

void vudot_vs_handler(re_list_t *instnode);

void vummla_vs_handler(re_list_t *instnode);

void vusdot_vs_handler(re_list_t *instnode);

void vusmmla_vs_handler(re_list_t *instnode);

void vuzp_vs_handler(re_list_t *instnode);

void vzip_vs_handler(re_list_t *instnode);

void addw_vs_handler(re_list_t *instnode);

void aut_vs_handler(re_list_t *instnode);

void autg_vs_handler(re_list_t *instnode);

void bfl_vs_handler(re_list_t *instnode);

void bflx_vs_handler(re_list_t *instnode);

void bf_vs_handler(re_list_t *instnode);

void bfcsel_vs_handler(re_list_t *instnode);

void bfx_vs_handler(re_list_t *instnode);

void bti_vs_handler(re_list_t *instnode);

void bxaut_vs_handler(re_list_t *instnode);

void clrm_vs_handler(re_list_t *instnode);

void csel_vs_handler(re_list_t *instnode);

void csinc_vs_handler(re_list_t *instnode);

void csinv_vs_handler(re_list_t *instnode);

void csneg_vs_handler(re_list_t *instnode);

void dcps1_vs_handler(re_list_t *instnode);

void dcps2_vs_handler(re_list_t *instnode);

void dcps3_vs_handler(re_list_t *instnode);

void dls_vs_handler(re_list_t *instnode);

void le_vs_handler(re_list_t *instnode);

void orn_vs_handler(re_list_t *instnode);

void pac_vs_handler(re_list_t *instnode);

void pacbti_vs_handler(re_list_t *instnode);

void pacg_vs_handler(re_list_t *instnode);

void sg_vs_handler(re_list_t *instnode);

void subs_vs_handler(re_list_t *instnode);

void subw_vs_handler(re_list_t *instnode);

void tbb_vs_handler(re_list_t *instnode);

void tbh_vs_handler(re_list_t *instnode);

void tt_vs_handler(re_list_t *instnode);

void tta_vs_handler(re_list_t *instnode);

void ttat_vs_handler(re_list_t *instnode);

void ttt_vs_handler(re_list_t *instnode);

void wls_vs_handler(re_list_t *instnode);

void blxns_vs_handler(re_list_t *instnode);

void bxns_vs_handler(re_list_t *instnode);

void cbnz_vs_handler(re_list_t *instnode);

void cbz_vs_handler(re_list_t *instnode);

void pop_vs_handler(re_list_t *instnode);

void push_vs_handler(re_list_t *instnode);

void brkdiv0_vs_handler(re_list_t *instnode);

void vpop_vs_handler(re_list_t *instnode);

void vpush_vs_handler(re_list_t *instnode);
#endif
#endif
                
//instruction resolvers
void invalid_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void asr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void it_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrsbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrsht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void lsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void lsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ror_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rrx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld4_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst4_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void movs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mov_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void str_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void adc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void add_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void adr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void aesd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void aese_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void aesimc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void aesmc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void and_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvtt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bfc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bfi_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bic_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bkpt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void blx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bxj_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void b_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx1a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx1d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx1da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx2a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx2d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx2da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx3a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx3d_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cx3da_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcx1a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcx1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcx2a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcx2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcx3a_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcx3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cdp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cdp2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void clrex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void clz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cmn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cmp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cps_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void crc32b_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void crc32cb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void crc32ch_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void crc32cw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void crc32h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void crc32w_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dbg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dmb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void eor_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void eret_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmov_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void fldmdbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void fldmiax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmrs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void fstmdbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void fstmiax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void hint_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void hlt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void hvc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void isb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void lda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldaex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldaexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldaexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldaexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldc2l_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldcl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldmda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldmib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ldrexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mcr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mcr2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mcrr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mcrr2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void movt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void movw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mrc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mrc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mrrc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mrrc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mrs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void msr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void asrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dlstp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void lctp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void letp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void lsll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void lsrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sqrshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sqrshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sqshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void srshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void srshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqrshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void urshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void urshrl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vabav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vabd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vabs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vadc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vadci_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaddlva_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaddlv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaddva_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaddv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vand_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vbic_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vbrsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vclz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcmp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vctp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvtm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvtn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvtp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vddup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vdwdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void veor_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfmas_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfms_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vhadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vhcadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vhsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vidup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void viwdup_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld20_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld21_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld40_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld41_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld42_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vld43_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vldrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vldrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vldrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vldrw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmaxav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmaxa_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmaxnmav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmaxnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmaxnmv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmaxnm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmaxv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vminav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmina_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vminnmav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vminnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vminnmv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vminnm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vminv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmin_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmladava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmladavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmladav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmladavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlaldava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlaldavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlaldav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlaldavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlas_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsdava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsdavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsdav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsdavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsldava_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsldavax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsldav_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsldavx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmovlb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmovlt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmovnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmovnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmullb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmullt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmvn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vorn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vorr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpnot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpsel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqabs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmladhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmladh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmlah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmlash_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmlsdhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmlsdh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmullb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmullt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqmovnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqmovnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqmovunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqmovunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmladhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmladh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmlah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmlash_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmlsdhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmlsdh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrshrunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrshrunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshlu_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshrunb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshrunt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrev16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrev32_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrev64_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrhadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrinta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrintm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrintn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrintp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrintx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrintz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlaldavha_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlaldavhax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlaldavh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlaldavhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlsldavha_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlsldavhax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlsldavh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmlsldavhx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrmulh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsbc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsbci_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshlc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshllb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshllt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshrnb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshrnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsli_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsri_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst20_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst21_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst40_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst41_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst42_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vst43_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vstrb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vstrd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vstrh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vstrw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void wlstp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void mvn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void orr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pkhbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pkhtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pldw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pld_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pli_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qdadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qdsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qsub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void qsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rbit_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rev_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rev16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void revsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rfeda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rfedb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rfeia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rfeib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void rsc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sbc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sbfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sdiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void setend_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void setpan_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha1c_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha1h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha1m_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha1p_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha1su0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha1su1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha256h_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha256h2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha256su0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sha256su1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void shadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void shadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void shasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void shsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void shsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void shsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlabb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlabt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlad_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smladx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlalbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlalbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlald_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlaldx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlaltb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlaltt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlatb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlatt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlawb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlawt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlsd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlsdx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlsld_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smlsldx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smmlar_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smmlsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smmulr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smuad_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smuadx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smulbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smulbt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smultb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smultt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smulwb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smulwt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smusd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void smusdx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void srsda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void srsdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void srsia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void srsib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ssat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ssat16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ssax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ssub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ssub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stc2l_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stc2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stcl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stlb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stlex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stlexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stlexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stlexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stlh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stmda_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void stmib_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strex_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strexb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strexd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strexh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void strht_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sub_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void svc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void swp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void swpb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sxtab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sxtab16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sxtah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sxtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sxtb16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sxth_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void teq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void trap_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void tsb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void tst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ubfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void udf_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void udiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uhadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uhadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uhasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uhsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uhsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uhsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void umaal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void umlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void umull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqadd16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqadd8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqasx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqsax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqsub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uqsub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void usad8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void usada8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void usat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void usat16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void usax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void usub16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void usub8_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uxtab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uxtab16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uxtah_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uxtb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uxtb16_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void uxth_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vabal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaba_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vabdl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vacge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vacgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaddhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaddl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vaddw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfmab_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfmat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vbif_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vbit_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vbsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vceq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcle_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vclt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcmpe_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcnt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vdiv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vext_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfmal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfmsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfnma_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vfnms_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vins_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vjcvt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vldmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vldmia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vldr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vlldm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vlstm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmlsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmovx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmovl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmovn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmsr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vmull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vnmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vnmls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vnmul_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpadal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpaddl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpadd_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpmax_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpmin_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmlal_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmlsl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqdmull_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqmovun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqmovn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrdmlsh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqrshrun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vqshrun_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vraddhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrecpe_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrecps_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrintr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrsqrte_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrsqrts_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrsra_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vrsubhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vscclrm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vseleq_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vselge_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vselgt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vselvs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshll_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vshrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsqrt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsra_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vstmdb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vstmia_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vstr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsubhn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsubl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsubw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vsudot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vswp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vtbl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vtbx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vcvtr_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vtrn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vtst_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vudot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vummla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vusdot_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vusmmla_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vuzp_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vzip_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void addw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void aut_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void autg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bfl_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bflx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bf_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bfcsel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bfx_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bti_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bxaut_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void clrm_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void csel_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void csinc_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void csinv_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void csneg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dcps1_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dcps2_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dcps3_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void dls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void le_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void orn_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pac_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pacbti_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pacg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void sg_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void subs_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void subw_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void tbb_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void tbh_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void tt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void tta_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ttat_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void ttt_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void wls_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void blxns_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void bxns_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cbnz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void cbz_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void pop_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void push_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void brkdiv0_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpop_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);

void vpush_resolver(re_list_t* inst, re_list_t* re_deflist, re_list_t* re_uselist);


//instruction post resolvers
int invalid_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int asr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int it_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrht_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrsbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrsht_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int lsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int lsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ror_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rrx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld4_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst4_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrsh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int movs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int str_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int adc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int add_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int adr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int aesd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int aese_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int aesimc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int aesmc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int and_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vdot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvtt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bfc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bfi_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bic_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bkpt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int blx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bxj_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int b_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx1a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx1d_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx1da_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx2a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx2d_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx2da_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx3a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx3d_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cx3da_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcx1a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcx1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcx2a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcx2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcx3a_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcx3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cdp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cdp2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int clrex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int clz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cmn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cps_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int crc32b_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int crc32cb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int crc32ch_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int crc32cw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int crc32h_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int crc32w_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dbg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dmb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int eor_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int eret_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmov_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int fldmdbx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int fldmiax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmrs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int fstmdbx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int fstmiax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int hint_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int hlt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int hvc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int isb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int lda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldaex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldaexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldaexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldaexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldc2l_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldcl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldmda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldmib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ldrexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mcr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mcr2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mcrr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mcrr2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int movt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int movw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mrc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mrc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mrrc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mrrc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mrs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int msr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int asrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dlstp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int lctp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int letp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int lsll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int lsrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sqrshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sqrshrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sqshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sqshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int srshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int srshrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqrshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqrshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int urshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int urshrl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vabav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vabd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vabs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vadc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vadci_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaddlva_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaddlv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaddva_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaddv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vand_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vbic_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vbrsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vclz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcmp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vctp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvta_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvtm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvtn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvtp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vddup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vdup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vdwdup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int veor_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfmas_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfms_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vhadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vhcadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vhsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vidup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int viwdup_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld20_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld21_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld40_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld41_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld42_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vld43_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vldrb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vldrd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vldrh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vldrw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmaxav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmaxa_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmaxnmav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmaxnma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmaxnmv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmaxnm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmaxv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vminav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmina_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vminnmav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vminnma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vminnmv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vminnm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vminv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmin_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmladava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmladavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmladav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmladavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlaldava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlaldavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlaldav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlaldavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlas_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsdava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsdavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsdav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsdavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsldava_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsldavax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsldav_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsldavx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmovlb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmovlt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmovnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmovnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmullb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmullt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmvn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vneg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vorn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vorr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpnot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpsel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpst_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqabs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmladhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmladh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmlah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmlash_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmlsdhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmlsdh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmullb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmullt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqmovnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqmovnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqmovunb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqmovunt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqneg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmladhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmladh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmlah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmlash_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmlsdhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmlsdh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrshrunb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrshrunt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshlu_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshrunb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshrunt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrev16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrev32_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrev64_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrhadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrinta_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrintm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrintn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrintp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrintx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrintz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlaldavha_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlaldavhax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlaldavh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlaldavhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlsldavha_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlsldavhax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlsldavh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmlsldavhx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrmulh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsbc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsbci_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshlc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshllb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshllt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshrnb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshrnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsli_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsri_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst20_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst21_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst40_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst41_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst42_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vst43_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vstrb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vstrd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vstrh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vstrw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int wlstp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int mvn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int orr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pkhbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pkhtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pldw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pld_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pli_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qdadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qdsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qsub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int qsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rbit_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rev_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rev16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int revsh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rfeda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rfedb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rfeia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rfeib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int rsc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sbc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sbfx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sdiv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int setend_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int setpan_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha1c_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha1h_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha1m_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha1p_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha1su0_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha1su1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha256h_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha256h2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha256su0_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sha256su1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int shadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int shadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int shasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int shsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int shsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int shsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlabb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlabt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlad_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smladx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlalbb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlalbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlald_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlaldx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlaltb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlaltt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlatb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlatt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlawb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlawt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlsd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlsdx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlsld_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smlsldx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smmlar_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smmls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smmlsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smmulr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smuad_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smuadx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smulbb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smulbt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smultb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smultt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smulwb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smulwt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smusd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int smusdx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int srsda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int srsdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int srsia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int srsib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ssat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ssat16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ssax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ssub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ssub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stc2l_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stc2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stcl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stlb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stlex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stlexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stlexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stlexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stlh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stmda_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int stmib_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strex_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strexb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strexd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strexh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int strht_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sub_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int svc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int swp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int swpb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sxtab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sxtab16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sxtah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sxtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sxtb16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sxth_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int teq_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int trap_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int tsb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int tst_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ubfx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int udf_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int udiv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uhadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uhadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uhasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uhsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uhsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uhsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int umaal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int umlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int umull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqadd16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqadd8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqasx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqsax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqsub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uqsub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int usad8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int usada8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int usat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int usat16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int usax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int usub16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int usub8_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uxtab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uxtab16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uxtah_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uxtb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uxtb16_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int uxth_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vabal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaba_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vabdl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vacge_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vacgt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaddhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaddl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vaddw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfmab_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfmat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vbif_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vbit_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vbsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vceq_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcge_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcgt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcle_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vclt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcmpe_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcnt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vdiv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vext_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfmal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfmsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfnma_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vfnms_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vins_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vjcvt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vldmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vldmia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vldr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vlldm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vlstm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmlsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmovx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmovl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmovn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmsr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vmull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vnmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vnmls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vnmul_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpadal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpaddl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpadd_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpmax_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpmin_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmlal_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmlsl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqdmull_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqmovun_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqmovn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrdmlsh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqrshrun_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vqshrun_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vraddhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrecpe_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrecps_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrintr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrsqrte_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrsqrts_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrsra_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vrsubhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vscclrm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsdot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vseleq_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vselge_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vselgt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vselvs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshll_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vshrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsmmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsqrt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsra_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vstmdb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vstmia_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vstr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsubhn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsubl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsubw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vsudot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vswp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vtbl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vtbx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vcvtr_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vtrn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vtst_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vudot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vummla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vusdot_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vusmmla_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vuzp_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vzip_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int addw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int aut_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int autg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bfl_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bflx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bf_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bfcsel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bfx_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bti_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bxaut_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int clrm_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int csel_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int csinc_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int csinv_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int csneg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dcps1_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dcps2_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dcps3_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int dls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int le_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int orn_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pac_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pacbti_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pacg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int sg_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int subs_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int subw_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int tbb_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int tbh_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int tt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int tta_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ttat_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int ttt_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int wls_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int blxns_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int bxns_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cbnz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int cbz_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int pop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int push_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int brkdiv0_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpop_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);

int vpush_post_res(re_list_t* inst, re_list_t* deflist, re_list_t* uselist, re_list_t* instlist);


#endif
