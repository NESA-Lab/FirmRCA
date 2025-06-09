import os
import yaml
import shutil

# load yaml config
def load_target_yml(filename):
    with open(filename,'rb') as f:
        data = yaml.load(f, Loader=yaml.FullLoader)
    # logger.debug(f'load yaml config: {data}')
    return data

def save_target_yml(filename, config):
    with open(filename,'w',encoding='utf8') as f:
        yaml.dump(config,f,allow_unicode=True)

# in unicorn d4b9248 commit, UC_ARM_REG_R0 = 66.
# in capstone 7bd3683 commit, ARM_REG_R0 = 73.
# TODO this can be optimized, filtering extra regs using capstone
def dump_reverse_list(filename):
    instlist = []
    reglist = []
    convert = {
        'r0(66)':'73',
        'r1(67)':'74',
        'r2(68)':'75',
        'r3(69)':'76',
        'r4(70)':'77',
        'r5(71)':'78',
        'r6(72)':'79',
        'r7(73)':'80',
        'r8(74)':'81',
        'r9(75)':'82',
        'r10(76)':'83',
        'r11(77)':'84',
        'r12(78)':'85',
        'PC(11)':'14',
        'LR(10)':'13',
        'SP(12)':'16',
    }
    with open(filename, 'r', encoding = 'utf8') as f:
        for line in f:
            if line.startswith('Hook at'):
                instlist.append(line.split()[2])
                reglog = line.split()[3].split(';')
                for ind, val in enumerate(reglog):
                    reglog[ind] = convert[val.split(':')[0]] + ':' + val.split(':')[1]
                reglist.append(';'.join(reglog))
    with open('instlist.reverse', 'w', encoding = 'utf8') as f:
        for data in instlist[::-1]:
            print(data, file = f)
    with open('loglist.reverse','w', encoding = 'utf8') as f:
        for data in reglist[::-1]:
            print(data, file=f)

def generate_dataset():
    # In fact, we do not need so many debug arguments.
    # just `fuzzware emu crashing_input --trace-out=trace-out.txt --state-out=state-out.txt > crash-log.txt` is ok.
    config = load_target_yml('config.yml')
    # command = 'fuzzware emu -M -v -t crashing_input --trace-out=trace-out.txt --state-out=state-out.txt > crash-log.txt'
    # command_no_event     = 'fuzzware emu crashing_input > _nouse'
    # command_action_event = 'fuzzware emu crashing_input --trace-out=trace-out.txt --state-out=state-out.txt --action-event > _nouse'
    # command_data_event   = 'fuzzware emu crashing_input --trace-out=trace-out.txt --state-out=state-out.txt --data-event > _nouse'
    command_both_events  = 'fuzzware emu crashing_input --trace-out=trace-out.txt --state-out=state-out.txt --action-event --data-event > _nouse'
    cnt = 0
    for root, dirs, _ in os.walk(os.getcwd()):
        for dir in dirs:
            for item in config:
                if dir == item['name'].split('-')[-1]:
                    binfile_path = os.path.join('testsuites', item['name'], 'firmware.bin')
                    instlist_path = os.path.join(dir,'instlist')
                    crashlog_path = os.path.join(dir,'crash-log.txt')
                    stateout_path = os.path.join(dir,'state-out.txt')
                    traceout_path = os.path.join(dir,'trace-out.txt')

                    os.system(f'cd {os.path.join(root,dir)} && {command_both_events} && cd ..')

                    if os.path.exists('./tmp'):
                        shutil.rmtree('./tmp')
                    
                    os.mkdir('./tmp')
                    dump_reverse_list(instlist_path)
                    if os.path.exists('./instlist.reverse'):
                        shutil.move('./instlist.reverse','./tmp/instlist.reverse')
                    if os.path.exists('./loglist.reverse'):
                        shutil.move('./loglist.reverse','./tmp/loglist.reverse')
                    shutil.copy(binfile_path,'./tmp/firmware.bin')
                    if os.path.exists(crashlog_path):
                        shutil.copy(crashlog_path,'./tmp/crash-log.txt')
                    if os.path.exists(stateout_path):
                        shutil.copy(stateout_path,'./tmp/state-out.txt')
                    if os.path.exists(traceout_path):
                        shutil.copy(traceout_path,'./tmp/memac.bin')
                    cnt+=1
                    break

    save_target_yml('config.yml',config)

if __name__ == '__main__':
    # Before running this script, make sure you have a `config.yml` file in the current directory.
    # In `config.yml`, you should have a list of dictionaries with at least 'name' and 'bin_load_addr'.
    # You can see the current config file as an example.
    generate_dataset()
