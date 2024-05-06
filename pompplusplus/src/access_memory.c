#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <capstone/capstone.h>
#include "elf_binary.h"
#include "access_memory.h"
#include "reverse_log.h"
#include "global.h"
// #include "ia32_reg.h" // obtain from libdisasm

// get the value by the name of register
// int value_of_register(char *reg, Elf32_Addr *value, struct elf_prstatus thread){
// 	int match = 0;
// 	if(strcmp(reg, "eax") == 0){
// 		*value = thread.pr_reg[EAX];
// 		match = 1;
// 		goto out;
// 	}

// 	if(strcmp(reg, "ebx") == 0){
// 		*value = thread.pr_reg[EBX];
// 		match = 1;
// 		goto out;
// 	}

// 	if(strcmp(reg, "ecx") == 0){
// 		*value = thread.pr_reg[ECX];
// 		match = 1;
// 		goto out;
// 	}

// 	if(strcmp(reg, "edx") == 0){
// 		*value = thread.pr_reg[EDX];
// 		match = 1;
// 		goto out;
// 	}

// 	if(strcmp(reg, "esi") == 0){
// 		*value = thread.pr_reg[ESI];
// 		match = 1;
// 		goto out;
// 	}

// 	if(strcmp(reg, "edi") == 0){
// 		*value = thread.pr_reg[EDI];
// 		match = 1;
// 		goto out;
// 	}

// 	if(strcmp(reg, "ebp") == 0){
// 		*value = thread.pr_reg[EBP];
// 		match = 1;
// 		goto out;
// 	}

// 	if(strcmp(reg, "esp") == 0){
// 		*value = thread.pr_reg[UESP];
// 		match = 1;
// 		goto out;
// 	}

// 	LOG(stderr, "ERROR: register %s need analysis\n", reg);
// 	assert(0);
// out: 
// 	return match; 
// }

/*
unsigned get_value_from_xmm(appinst_t * appint, x86_reg_t reg){

}

// get the value of register from x86_reg_t
unsigned int get_value_from_reg(appinst_t *appinst, x86_reg_t reg){
    int index = get_index_from_x86_reg_t(reg);
    unsigned int value = appinst->data.regs[index];
    if (reg.size == 1){
        if((strcmp(reg.name, "ah") == 0)||(strcmp(reg.name, "bh") == 0)||(strcmp(reg.name, "ch") == 0)||(strcmp(reg.name, "dh") ==0))
            value = value & 0x0000ff00;
        else
            value = value & 0x000000ff;
    }else if (reg.size == 2){
        value = value & 0x0000ffff;
    }else if (reg.size == 4){
        // No change
    }

    return value;
}

// get the value of register from x86_reg_t
void set_value_to_reg(appinst_t *appinst, x86_reg_t reg, unsigned int value){
    int index = get_index_from_x86_reg_t(reg);
    LOG(stdout, "DEBUG: Set reg %s to value 0x%x\n", reg.name, value);
    unsigned int newvalue = appinst->data.regs[index];
    if (reg.size == 1){
        if((strcmp(reg.name, "ah") == 0)||(strcmp(reg.name, "bh") == 0)||(strcmp(reg.name, "ch") == 0)||(strcmp(reg.name, "dh") ==0)){
            newvalue = newvalue & 0xffff00ff;
            newvalue += value << 8;
        }else{
            newvalue = newvalue & 0xffffff00;
            newvalue += value;
        }
    }else if (reg.size == 2){
        newvalue = newvalue & 0xffff0000;
        newvalue += value;
    }else if (reg.size == 4){
        newvalue = value;
    }

    appinst->data.regs[index] = newvalue;
}
*/
//determine the segment this address exists.
//if -1, then this address does not exist in any segment. Illegal access!

//Get the offset of memory in file based on its address


int get_data_from_core(long int start, long int size, char * note_data){
    int fd;
    if ((fd=open(get_core_path(), O_RDONLY, 0)) < 0){
    	LOG(stderr, "Core file open error %s\n", strerror(errno));
    	return -1;
    }
    if(lseek(fd, start, SEEK_SET)<0){
    	LOG(stderr, "Core file lseek error %s\n", strerror(errno));
    	close(fd);
    	return -1;
    }
    if(read(fd, note_data, size)<0){
    	LOG(stderr, "Core file open error %s\n", strerror(errno));
    	close(fd);
    	return -1;
    }
    close(fd);
    return 0;
}


