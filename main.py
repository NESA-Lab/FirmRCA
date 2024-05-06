"""Run the experiment of RCA algorithm.
Settings should be speficied.
"""

import os
import yaml
import subprocess
import datetime
from multiprocessing import Process, Semaphore

exp_timeout = 48 * 3600
date = datetime.datetime.now().strftime("%Y%m%d")
global_jobs = []
sem = Semaphore(20)
MAX_LASTN = 1000000000 # Only analyze the min(specifiedlines, MAX_LASTN) instructions before crash

ground_truth = {
        'syn-sample-01':[(0x1390,0x1390)],
        'syn-sample-02':[(0x208c,0x208c)],
        'syn-sample-03':[(0x206c,0x206c)],
        'syn-sample-04':[(0xd2c,0xd2c)],
        'syn-sample-05':[(0x1398,0x1398)],
        'syn-sample-06':[(0x8001f80,0x8001f80)],
        'syn-sample-07':[(0x8001b28,0x8001b28)],
        'syn-sample-09':[(0x8002024,0x8002024)],
        'syn-sample-10':[(0x143c,0x143c)],
        'p2im-11':[(0x800392c,0x800393e),(0x8004f84,0x8004f8a),(0x8008b8c,0x8008bb2)],
        'p2im-12':[(0x8008620,0x800862c),(0x8002fc6,0x8002fcc),(0x80005d8,0x80006ee)], 
        'p2im-16':[(0x8000a7c,0x8000a8c),(0x8000a7c,0x8000aae),(0x8000a72,0x8000a76),(0x8000c06,0x8000c0c),(0x8000ba6,0x8000bba)],
        'p2im-17':[(0x8000b14,0x8000b16),(0x8000b00,0x8000b0e),],
        'p2im-20':[(0x80056d2,0x80056d4),(0x80056d8,0x80056dc)], 
        'p2im-21':[(0x8003676,0x8003678),(0x8003672,0x8003674)],
        'p2im-22':[(0x8003676,0x8003678),(0x8003672,0x8003674)],
        'p2im-23':[(0x800711c,0x800711c),(0x8008950,0x8008968),(0x8006b42,0x8006b5e)],
        'p2im-24':[(0x8002fc6,0x8002fcc),(0x800072c,0x8000732),(0x80033a6,0x80033a8)],
        'p2im-25':[(0x8000d36,0x8000d38),(0x8000d20,0x8000d34)], 
        'uemu-27':[(0x800d682,0x800d684)], 
        'uemu-28':[(0x3c4,0x3de)], 
        'uemu-29':[(0x424,0x438)], 
        'uemu-36':[(0x12f2,0x12f6),(0x128e,0x1294),(0x1240,0x124a),(0x2c88,0x2c92)], 
        'uemu-37':[(0x12f2,0x12f6),(0x128e,0x1294),(0x1240,0x124a),(0x2c88,0x2c92)],
        'uemu-38':[(0x114a,0x1152),(0x512c,0x512c),(0x3838,0x384c),(0x171c,0x172e),(0xfbe,0xfca)], 
        'uemu-39':[(0x8002112,0x8002112),(0x8002d9c,0x8002d9e),(0x80003c0,0x80003f0),(0x80003da,0x80003e8)], 
        'uemu-40':[(0x800ea94,0x800ea94),(0x800e8de,0x800e8de),(0x800e4ee,0x800e4f8),(0x800e8d2,0x800e8d6)],
        'uemu-41':[(0x800e9be,0x800e9cc),(0x800e8de,0x800e8de),(0x800e4ee,0x800e4f8),(0x800e8d2,0x800e8d6)], 
        'uemu-43':[(0x8009ca2,0x8009ca6),(0x8009c94,0x8009ca0)],
        'uemu-44':[(0x8009ca2,0x8009ca6),(0x8009c94,0x8009ca0)], 
        'uemu-45':[(0x801012c,0x801012c),(0x801007a,0x8010086),(0x800d8d4,0x800d8de),(0x800dab8,0x800dbd6),(0x800f104,0x800f10a)], 
        'zephyr-46':[(0x4029ce,0x4029ce),(0x40dada,0x40dada),(0x407918,0x40797a),(0x40dcda,0x40dce4)], 
        'zephyr-47':[(0x800b63e,0x800b640),(0x8008900,0x8008954),(0x800a3d6,0x800a3e4),(0x8001380,0x800138c),],
        'zephyr-48':[(0x8002cea,0x8002cee),(0x800b030,0x800b038)],
        'zephyr-52':[(0x403b70,0x403b76),(0x403aec,0x403af2),(0x40d202,0x40d204)], 
        'zephyr-53':[(0x40da8c,0x40da90),(0x40dd40,0x40dd46),(0x40dcfa, 0x40dd0a),(0x40cfd8,0x40d018,)],
        'zephyr-54':[(0x8b24,0x8b28),(0x6740,0x674a)], 
        'zephyr-55':[(0x402bd0,0x402bd8),(0x40cdbc,0x40cde0),(0x402bf2,0x402bf4)],
        'contiki-ng-58':[(0x20aa58,0x20aa7a),(0x203a94,0x203a96),(0x205b10,0x205b24),(0x206368,0x206374),(0x20406c,0x20407c)], 
        'contiki-ng-59':[(0x2089c6,0x2089c6),(0x2089a8,0x2089c4),(0x20897a,0x20897e),(0x202d78,0x202d82),(0x206fd4,0x206fde)],
        'contiki-ng-60':[(0x207d2c,0x207d34),(0x7f1a,0x7f1c),(0x204060,0x204074)], 
    }

test_env = {
    'baseline-nolog' : {
        'env' : 'export LD_LIBRARY_PATH= && ',
        'program' : f' timeout {exp_timeout} ./pomp/src/reversenolog' 
    },
    'baseline-log' : {
        'env' : 'export LD_LIBRARY_PATH= && ',
        'program' : f' timeout {exp_timeout} ./pomp/src/reverselog'
    },
    'capnproto-nolog' : {
        'env' : 'export LD_LIBRARY_PATH=./src/lib && ',
        'program' : f' timeout {exp_timeout} ./src/src/reversenolog'
    },
    'capnproto-nolog-ablation1' : {
        'env' : 'export LD_LIBRARY_PATH=./src/lib && ',
        'program' : f' timeout {exp_timeout} ./src/src/ablation1'
    },
    'capnproto-nolog-ablation2' : {
        'env' : 'export LD_LIBRARY_PATH=./src/lib && ',
        'program' : f' timeout {exp_timeout} ./src/src/ablation2'
    },
    'capnproto-nolog-ablation3' : {
        'env' : 'export LD_LIBRARY_PATH=./src/lib && ',
        'program' : f' timeout {exp_timeout} ./src/src/ablation3'
    },
    'capnproto-log' : {
        'env' : 'export LD_LIBRARY_PATH=./src/lib && ',
        'program' : f' timeout {exp_timeout} ./src/src/reverselog'
    },
    'compare-deepvsa-vsa-nolog': {
        'env' : 'export LD_LIBRARY_PATH=./pompplusplus/lib && ',
        'program' : f' timeout {exp_timeout} ./pompplusplus/src/reversenolog'
    },
    'compare-deepvsa-vsa-log': {
        'env' : 'export LD_LIBRARY_PATH=./pompplusplus/lib && ',
        'program' : f' timeout {exp_timeout} ./pompplusplus/src/reverselog'
    },
}

# load yaml config

def load_target_yml(filename):
    with open(filename,'rb') as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
    # logger.debug(f'load yaml config: {data}')
    return data

def get_file_lines(file_abs_name):
    (status, output) = subprocess.getstatusoutput(f'wc -l {os.path.abspath(file_abs_name)}')
    return int(output.split()[0])

def do_execute(command, sem, explog='exp_default_log.txt'):
    sem.acquire()
    res = os.system(command)
    sem.release()

def run_single_rca(target,exp_env,line):
    """Analyze the last `line` lines of the target's execution log file, 
    for verifying the correctness of the RCA algorithm.
    
    The result is saved in the target directory.

    """
    config = load_target_yml('config.yml')
    for item in config:
        if target and item['name'] == target:
            test_dir = os.path.join('./testsuites',item['name'])
            binary_file = os.path.join(test_dir, 'firmware.bin')
            core_dump = os.path.join(test_dir, 'state-out.txt')
            inv_trace_file = os.path.join(test_dir, 'instlist.reverse')
            inv_loglist_file = os.path.join(test_dir, 'loglist.reverse')
            memac_file = os.path.join(test_dir, 'memac.bin')
            start_addr = item['bin_load_addr']
            instlist_lines = get_file_lines(inv_trace_file)
            if line <= 1:
                nline = int(instlist_lines * line)
                ratio = True
            else:
                nline = line
                ratio = False
            nline = min(nline, MAX_LASTN)
            max_rev_ins_num = nline
            root_cause_rev_idx = nline
            if ratio:
                output_log = os.path.join(test_dir, f'execution-{exp_env}-{line}.log')
            else:
                output_log = os.path.join(test_dir, f'execution-{exp_env}-{nline}.log')
            if 'deepvsa' in exp_env:
                run_exp_command = f'{test_env[exp_env]["env"]} {test_env[exp_env]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {inv_loglist_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {output_log}'
            else:
                run_exp_command = f'{test_env[exp_env]["env"]} {test_env[exp_env]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {output_log}'
            try:
                p = Process(target=do_execute, args=(run_exp_command, sem))
                p.start()
                global_jobs.append(p)
                # print(run_exp_command)
            except KeyboardInterrupt as e:
                break

def run_multiple_rca(exp_env, line):
    config = load_target_yml('config.yml')
    jobs =  []
    for item in config:
        test_dir = os.path.join('./testsuites',item['name'])
        binary_file = os.path.join(test_dir, 'firmware.bin')
        core_dump = os.path.join(test_dir, 'state-out.txt')
        inv_trace_file = os.path.join(test_dir, 'instlist.reverse')
        inv_loglist_file = os.path.join(test_dir, 'loglist.reverse')
        memac_file = os.path.join(test_dir, 'memac.bin')
        start_addr = item['bin_load_addr']
        instlist_lines = get_file_lines(inv_trace_file)
        if line <= 1:
            nline = int(instlist_lines * line)
            ratio = True
        else:
            nline = line
            ratio = False
        max_rev_ins_num = nline
        root_cause_rev_idx = nline
        nline = min(nline, MAX_LASTN)
        if ratio:
            output_log = os.path.join(test_dir, f'execution-{exp_env}-{line}.log')
        else:
            output_log = os.path.join(test_dir, f'execution-{exp_env}-{nline}.log')
        if 'deepvsa' in exp_env:
            run_exp_command = f'{test_env[exp_env]["env"]} {test_env[exp_env]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {inv_loglist_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {output_log}'
        else:
            run_exp_command = f'{test_env[exp_env]["env"]} {test_env[exp_env]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {output_log}'
        try:
            print(item['name'], nline)
            p = Process(target=do_execute, args=(run_exp_command, sem))
            p.start()
            jobs.append(p)
        except KeyboardInterrupt as e:
            break
    for job in jobs:
        job.join()

def run_multiple_set_rca(targets, exp_env, line, repeat=1):
    """Run the RCA algorithm for multiple targets under the specified exp_env.
       If repeat > 1, the experiment will be repeated for `repeat` times and the log files
       will be saved in target/{exp_env}-{line}/execution-{exp_env}-{nline}-{num}.log
    """
    config = load_target_yml('config.yml')
    jobs =  []
    for item in config:
        if item['name'] in targets:
            test_dir = os.path.join('./testsuites',item['name'])
            binary_file = os.path.join(test_dir, 'firmware.bin')
            core_dump = os.path.join(test_dir, 'state-out.txt')
            inv_trace_file = os.path.join(test_dir, 'instlist.reverse')
            inv_loglist_file = os.path.join(test_dir, 'loglist.reverse')
            memac_file = os.path.join(test_dir, 'memac.bin')
            start_addr = item['bin_load_addr']
            instlist_lines = get_file_lines(inv_trace_file)
            if line <= 1:
                nline = int(line * instlist_lines)
                ratio = True
            else:
                nline = line
                ratio = False
            nline = min(nline, MAX_LASTN)
            max_rev_ins_num = nline
            root_cause_rev_idx = nline
            for i in range(repeat):
                if repeat > 1:
                    if not os.path.exists(os.path.join(test_dir, f'{exp_env}-{line}')):
                        os.mkdir(os.path.join(test_dir, f'{exp_env}-{line}'))
                    if ratio:
                        output_log = os.path.join(test_dir, f'{exp_env}-{line}', f'execution-{i+1}-{exp_env}-{line}.log')
                    else:
                        output_log = os.path.join(test_dir, f'{exp_env}-{line}', f'execution-{i+1}-{exp_env}-{nline}.log')
                else:
                    if ratio:
                        output_log = os.path.join(test_dir, f'execution-{exp_env}-{line}.log')
                    else:
                        output_log = os.path.join(test_dir, f'execution-{exp_env}-{nline}.log')
                if 'deepvsa' in exp_env:
                    run_exp_command = f'{test_env[exp_env]["env"]} {test_env[exp_env]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {inv_loglist_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {output_log}'
                else:
                    run_exp_command = f'{test_env[exp_env]["env"]} {test_env[exp_env]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {output_log}'
                try:
                    p = Process(target=do_execute, args=(run_exp_command, sem))
                    p.start()
                    jobs.append(p)
                except KeyboardInterrupt as e:
                    break

    for job in jobs:
        job.join()

def exp_resolve_and_resolve_time(lastN,repeat):
    """Check time cost of reverse execution, resovle, vsa and backward analysis.
    """
    targets = list(ground_truth.keys())

    run_multiple_set_rca(targets, 'baseline-nolog', lastN, repeat)
    run_multiple_set_rca(targets, 'capnproto-nolog', lastN, repeat)
    run_multiple_set_rca(targets, 'capnproto-nolog-ablation1', lastN, repeat)
    run_multiple_set_rca(targets, 'capnproto-nolog-ablation2', lastN, repeat)
    run_multiple_set_rca(targets, 'compare-deepvsa-vsa-nolog', lastN, repeat)

def exp_single_run_rca(lastN):
    """Check many metrics for all crashing testcases, only analyzing the last N instructions.
    """
    targets = list(ground_truth.keys())
    for target in targets:
        run_single_rca(target, 'baseline-nolog', lastN)
        run_single_rca(target, 'capnproto-nolog', lastN)
        run_single_rca(target, 'capnproto-nolog-ablation1', lastN)
        run_single_rca(target, 'capnproto-nolog-ablation2', lastN)
        run_single_rca(target, 'capnproto-nolog-ablation3', lastN)
        run_single_rca(target, 'compare-deepvsa-vsa-nolog', lastN)
    for job in global_jobs:
        job.join()

def exp_repeat_test_overhead_lastN(target,settings,sub_dir):
    """Iteratively run the last couples of lines of the target's execution log file,
    for verifying the efficiency of the RCA algorithm.
    """
    config = load_target_yml('config.yml')
    jobs = []
    for item in config:
        try:
            if item['name'] == target:
                test_dir = os.path.join('./testsuites',item['name'])
                if not os.path.exists(os.path.join(test_dir,sub_dir)):
                    os.mkdir(os.path.join(test_dir,sub_dir))
                binary_file = os.path.join(test_dir, 'firmware.bin')
                core_dump = os.path.join(test_dir, 'state-out.txt')
                inv_trace_file = os.path.join(test_dir, 'instlist.reverse')
                inv_loglist_file = os.path.join(test_dir, 'loglist.reverse')
                memac_file = os.path.join(test_dir, 'memac.bin')
                start_addr = item['bin_load_addr']
                instlist_lines = get_file_lines(inv_trace_file)
                lastN_list = [10000 * i for i in range(1, 37)]
                assert instlist_lines >= max(lastN_list)
                for line in lastN_list:
                    max_rev_ins_num = line
                    root_cause_rev_idx = line
                    for setting in settings:
                        log_file = os.path.join(test_dir,sub_dir, f'execution-{setting}-{line}.log')
                        
                        if 'deepvsa' in setting:
                            run_exp_command = f'{test_env[setting]["env"]} {test_env[setting]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {inv_loglist_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {log_file}'
                        else:
                            run_exp_command = f'{test_env[setting]["env"]} {test_env[setting]["program"]} {core_dump} {binary_file} {inv_trace_file} {memac_file} {start_addr} {max_rev_ins_num} {root_cause_rev_idx} > {log_file}'
                        p = Process(target=do_execute, args=(run_exp_command, sem, target+'-exp4log.txt'))
                        p.start()
                        jobs.append(p)
        except KeyboardInterrupt as e:
            break
    for job in jobs:
        job.join()


def debug():
    run_single_rca('contiki-ng-54','capnproto-log',1)


if __name__ == '__main__':
    debug()
    
