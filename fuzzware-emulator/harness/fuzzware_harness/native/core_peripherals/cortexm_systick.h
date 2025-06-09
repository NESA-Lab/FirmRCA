#ifndef CORTEXM_SYSTICK_H
#define CORTEXM_SYSTICK_H

#include "unicorn/unicorn.h"
#include "cortexm_exception_nums.h"
#include "cmsis/core_cm3.h"
#include "cortexm_nvic.h"
#include "../timer.h"

#define SYST_CSR_RESET_VAL 0
#define SYSTICK_RELOAD_VAL_NONE 0

#define SYSTICK_BASE SysTick_BASE
#define SYSTICK_END (SYSTICK_BASE + 0x1f)

#define SYST_RELOAD_VAL_MASK 0x00ffffff

#define REG_OFF_SYST_CSR 0x0
#define REG_OFF_SYST_RVR 0x4
#define REG_OFF_SYST_CVR 0x8
#define REG_OFF_SYST_CALIB 0xC

#define SYST_CSR_ENABLE (1 <<  0)
#define SYST_CSR_TICKINT (1 <<  1)
#define SYST_CSR_CLKSOURCE (1 <<  2)
#define SYST_CSR_COUNTFLAG (1 << 16)

// Fuzzware specific constants
#define SYSTICK_TICKS_10_MS 500

struct CortexmSysTick {
    /* 
     * We treat SysTick as a timer. From that abstraction we will also query
     * data such as reload values.
     */
    int timer_ind;
    // We have some extra information that is SysTick specific
    int csr;
};

uc_err init_systick(uc_engine *uc, uint32_t reload_val);

void hook_syst_mmio_read(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data);
void hook_syst_mmio_write(uc_engine *uc, uc_mem_type type, uint64_t addr, int size, int64_t value, void *user_data);

#endif