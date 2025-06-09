#ifndef CORTEXM_NVIC_H
#define CORTEXM_NVIC_H

#include <string.h>
#include <assert.h>

#include "unicorn/unicorn.h"
#include "cortexm_exception_nums.h"
#include "cortexm_systick.h"

#include "../util.h"
#include "../timer.h"
#include "../native_hooks.h"
#include "../uc_snapshot.h"

#define NVIC_ASSERTIONS

#ifdef NVIC_ASSERTIONS
#define nvic_assert(cond, msg)                  \
    if(!(cond)) {                               \
        printf("ASSERTION ERROR: '%s'\n", msg); \
        fflush(stdout);                         \
        print_state(uc);                        \
        _exit(-1);                              \
    }
#else
#define nvic_assert(condition, msg) ((void)0)
#endif



#define CPSR_FAULT_MASK_BIT (1 << 6)
#define CPSR_IRQ_MASK_BIT (1 << 7)

#define NVIC_ISER 0x00
#define NVIC_ICER 0x80
#define NVIC_ISPR 0x100
#define NVIC_ICPR 0x180
#define NVIC_IABR 0x200
#define NVIC_IPR  0x300

// Register offset range for MMIO access (this is based on the number of supported interrupts)
// We need 1 bit per interrupt, and pack 8 bits per address -> 1:8
#define NVIC_IREG_RANGE(reg_base) \
    (reg_base) ... (((reg_base) + ((NVIC_NUM_SUPPORTED_INTERRUPTS-EXCEPTION_NO_EXTERNAL_START) / 8)) & (~3))

// We need 8 bits per interrupt to express the priority -> 1:1
#define NVIC_IPR_RANGE(reg_base) \
    (reg_base) ... ((reg_base) + (NVIC_NUM_SUPPORTED_INTERRUPTS-EXCEPTION_NO_EXTERNAL_START))


#define SYSCTL_START 0xE000E000
#define SYSCTL_CPUID 0xE000ED00
#define SYSCTL_ICSR  0xE000ED04
#define SYSCTL_VTOR  0xE000ED08
#define SYSCTL_AIRCR 0xE000ED0C
#define SYSCTL_ICTR  0xE000E004
#define SYSCTL_CCR   0xE000ED14
#define SYSCTL_SHPR1 0xE000ED18
#define SYSCTL_SHPR2 0xE000ED1C
#define SYSCTL_SHPR3 0xE000ED20
#define SYSCTL_SHCSR 0xE000ED24
#define SYSCTL_STIR  0xE000EF00

#define SYSCTL_MMIO_BASE SCS_BASE
#define SYSCTL_MMIO_END (SYSCTL_MMIO_BASE + 0xf04)
#define NVIC_MMIO_BASE NVIC_BASE
#define NVIC_MMIO_END (NVIC_MMIO_BASE + 0x600)

#define VECTKEY_HIWORD_MAGIC_READ 0xFA050000u
#define VECTKEY_HIWORD_MAGIC_WRITE 0x05FA0000u
#define NVIC_RESET_VAL_PRIGROUP 0
#define NVIC_INTERRUPT_ENTRY_LR_BASE 0xfffffff1u
#define NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG 4
#define NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG 8

#define NVIC_LOWEST_PRIO 256


struct CortexmNVIC {
    // We put some members to the front as they are required in the basic block hot path
    
    // Direct access pointers for interrupt disable / base priority flags
    uint8_t *reg_daif_ptr;
    int32_t *reg_basepri_ptr;

    // State for the basic block hook to detect differences
    uint8_t prev_primask;
    int32_t prev_basepri;
    uint8_t group_prio_mask;
    uint8_t prigroup_shift;
    uint8_t sub_prio_mask;
    uint8_t highest_ever_enabled_exception_no;

    // dynamic state which we re-calculate upon changes
    int active_group_prio;
    int active_irq;
    int pending_prio;
    int pending_irq;
    int num_active;

    // Vector table base address
    uint32_t vtor;

    uint32_t interrupt_count;
    bool force_stack_align;

    uint8_t ExceptionEnabled[NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t ExceptionActive[NVIC_NUM_SUPPORTED_INTERRUPTS];
    uint8_t ExceptionPending[NVIC_NUM_SUPPORTED_INTERRUPTS];
    int ExceptionPriority[NVIC_NUM_SUPPORTED_INTERRUPTS];

    // We keep track of enabled interrupts for fuzzing
    int num_enabled;
    uint8_t enabled_irqs[NVIC_NUM_SUPPORTED_INTERRUPTS];
};

void pend_interrupt(uc_engine *uc, int exception_no);

uc_err init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts);

// Added for fuzzing purposes
uint16_t get_num_enabled();
uint8_t nth_enabled_irq_num(uint8_t n);

// TODO: remove backward-compatible interface
void nvic_set_pending(uc_engine *uc, uint32_t num, int skip_current_instruction);

#endif