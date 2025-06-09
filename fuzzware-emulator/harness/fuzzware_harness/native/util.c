#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <unicorn/unicorn.h>

int get_instruction_size(uint64_t insn, bool is_thumb) {
    if(is_thumb) {
        switch(insn & 0xf800) {
            // Thumb2: 32-bit
            case 0xe800:
            case 0xf000:
            case 0xf800:
                return 4;
            // Thumb: 16-bit
            default:
                return 2;
        }
    } else {
        return 4;
    }
}

#define NUM_DUMPED_REGS 18
static int reg_ids[NUM_DUMPED_REGS] = {
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
    UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_XPSR,
    UC_ARM_REG_SP, UC_ARM_REG_OTHER_SP
};
static char *reg_names[NUM_DUMPED_REGS] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "lr", "pc", "xpsr", "sp", "other_sp"
};
void print_state(uc_engine *uc) {
    uint32_t reg;
    puts("\n==== UC Reg state ====");
    for (int i = 0; i < NUM_DUMPED_REGS; ++i)
    {
        uc_reg_read(uc, reg_ids[i], &reg);
        printf("%s: 0x%08x\n", reg_names[i], reg);
    }
    puts("\n==== UC Stack state ====");
    uint32_t sp;
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    for (int i = -4; i < 16; ++i)
    {
        uint32_t val;
        if(uc_mem_read(uc, sp+4*i, &val, 4)) {
            continue;
        }
        printf("0x%08x: %08x", sp+4*i, val);
        if(!i) {
            puts(" <---- sp");
        } else {
            puts("");
        }
    }
    puts("======================\n");

    puts("\n==== UC Other Stack state ====");
    uc_reg_read(uc, UC_ARM_REG_OTHER_SP, &sp);
    for (int i = -4; i < 16; ++i)
    {
        uint32_t val;
        if(uc_mem_read(uc, sp+4*i, &val, 4)) {
            continue;
        }
        printf("0x%08x: %08x", sp+4*i, val);
        if(!i) {
            puts(" <---- sp");
        } else {
            puts("");
        }
    }
    puts("======================\n");
    fflush(stdout);
}
