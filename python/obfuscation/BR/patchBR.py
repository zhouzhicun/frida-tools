import queue

import idc
import idaapi
import idautils

from capstone.arm64_const import *
from unicorn.arm64_const import *
from unicorn import *

#自己封装的工具
from OBFInsnUtil import *
from OBFUtil import *
from OBFStruct import *





# 1. 将函数头放到队列中
# 2. 从队列中取出一个地址，开始执行
# 3. 执行时，将执行过的指令和上下文保存到指令栈中
# 4. 判断是否到达了br reg
# 5. 如果到达了br reg，则从指令栈中取指令，判断计算目标地址(单分支、双分支)，patch跳转
# 6. 将目标地址放到队列中
# 7. 遇到了ret或者是bl .__stack_chk_fail 就停止



#条件映射表
ZZCondTable = {
    'EQ': 'NE',
    'NE': 'EQ',
    'CS': 'CC',
    'CC': 'CS',
    'MI': 'PL',
    'PL': 'MI',
    'VS': 'VC',
    'VC': 'VS',
    'HI': 'LS',
    'LS': 'HI',
    'GE': 'LT',
    'LT': 'GE',
    'GT': 'LE',
    'LE': 'GT',
    'AL': 'AL'
}




class OBFManager:
    def __init__(self, config, arch):

        self.config = config
        self.ins_util = OBFInsnUtil(arch)
        self.uc = None

        self.br_table = {}
        self.blr_table = {}
        self.ins_size_table = {}  #存储br/blr指令的长度

        self.path_queue = queue.Queue()
        self.tracedPathDict = {} 
        self.cur_path = None

    def set_uc(self, uc):
        self.uc = uc

    #重置PathTraceState
    def set_cur_path(self, cur_path):
        self.cur_path = cur_path

    #指令数自增    
    def inc_ins_count(self):
        self.cur_path.ins_count += 1


    #入队执行，校验Path是否添加到队列，防止重复执行
    def push_path(self, path):
        path_desc = path.path_desc()
        if path_desc not in self.tracedPathDict:
            print(f'add path = {path_desc}')
            self.tracedPathDict[path_desc] = 1
            self.path_queue.put(path)

    #从队列中取出一个path，开始执行
    def pop_path(self):
        return self.path_queue.get()
    
    #判断是否为死代码
    def is_dead_code(self):
        return self.cur_path.ins_count > self.config.dead_code_insn_max_count

    #打印结果
    def print_track_result(self):
        #打印所有BR分支
        print('---------------- print all br -----------------')
        sorted_keys = sorted(self.br_table.keys())
        for addr_str in sorted_keys:
            print(f'br_addr = {addr_str}, jump info = {self.br_table[addr_str]}' )

        #打印所有BLR分支
        print('---------------- print all blr -----------------')
        sorted_keys = sorted(self.blr_table.keys())
        for addr in sorted_keys:
            print(f'br_addr = {addr_str}, jump info = {self.blr_table[addr_str]}' )
    
manager = None


#################################### unicorn hook ####################################################

def get_offset_str(addr):
    global manager
    return hex(addr - manager.config.mem_code[0])

def log(tip, pc, type, addr, size):
    log('%s, pc:%s type:%d addr:%x size:%x' % (tip, get_offset_str(pc), type, get_offset_str(addr), size))


def hook_unmapped_mem_access(uc, type, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    #log('error! access invalid mem', pc, type, address, size)
    uc.emu_stop()
    return False


def hook_code(uc, address, size, user_data):

    global manager

    #1.解析当前指令并打印
    code = manager.uc.mem_read(address, size)
    cur_ins = list(manager.ins_util.disasm(code, address))[0]
    cur_context = OBFUtil.get_context(uc)
    ins_mnemonic = cur_ins.mnemonic.lower()

    #path指令数+1
    manager.inc_ins_count()
    #print("[+] tracing instruction\t%s:\t%s\t%s" % (get_offset_str(cur_ins.address), cur_ins.mnemonic, cur_ins.op_str))
    
    #判断指令类型
    #2.1 遇到ret直接停止
    if ins_mnemonic == 'ret':
        print("[+] encountered ret, stop")
        uc.emu_stop()
        return
    
    #2.2 遇到bl .__stack_chk_fail停止
    if OBFUtil.is_call_stack_chk_fail(cur_ins, cur_context, manager.config.stack_chk_fail_func_addr):
        print("[+] encountered bl .__stack_chk_fail, stop")
        uc.emu_stop()
        return

    #3.3 简单死代码检测
    if OBFUtil.is_simple_dead_code(cur_ins):
        print("[+] encountered dead code, stop")
        uc.emu_stop()
        return
    
    #3.4 太多指令
    if manager.is_dead_code():
        start_addr, context, cond_desc, ins_count = manager.cur_path.path_info()
        path_desc = f'cur_path_info = start_addr: {hex(start_addr)}, cur_addr: {hex(cur_ins.address)},  cond_desc: {cond_desc}, ins_count: {str(ins_count)}'
        print("[+] encountered too many instructions, stop; " + path_desc)
        uc.emu_stop()
        return
    

    #3.3 跳过bl、svc指令 以及非栈或so本身内存访问
    config = manager.config
    is_access_ilegel_mem = OBFUtil.is_access_ilegel_memory(uc, cur_ins, config.mem_code, config.mem_stack)
    if ins_mnemonic.startswith('bl') or ins_mnemonic.startswith('svc') or is_access_ilegel_mem:
        print("[+] pass instruction %s\t%s\t%s" % (get_offset_str(cur_ins.address), cur_ins.mnemonic, cur_ins.op_str))
        uc.reg_write(UC_ARM64_REG_PC, address + size)  #跳过当前指令
        return

    

    #3.4 判断是否为条件指令
    if OBFUtil.is_condition(ins_mnemonic):
        
        #记录条件指令信息
        print("[+] condition instruction %s\t%s\t%s" % (get_offset_str(cur_ins.address), cur_ins.mnemonic, cur_ins.op_str))
        
        cond_info = OBFUtil.parse_cond_info(cur_ins, cur_context)
        print(f'dest_reg_name = {cond_info.dest_reg_name}  cond_true_value = {cond_info.cond_true_value}, cond_false_value = {cond_info.cond_false_value}')
        print(f'cur_context = {cur_context}')
        cond_true_context = OBFUtil.set_reg_value(cur_context, cond_info.dest_reg_name, cond_info.cond_true_value)
        cond_false_context = OBFUtil.set_reg_value(cur_context, cond_info.dest_reg_name, cond_info.cond_false_value)
        print(f'cond_true_context = {cond_true_context}')
        print(f'cond_false_context = {cond_false_context}')

        next_addr = cur_ins.address + size
        cond_true_path = ZZPathInfo(next_addr, cond_true_context, f'{cond_info.cond}_true')
        cond_false_path = ZZPathInfo(next_addr, cond_false_context, f'{cond_info.cond}_false')
        manager.push_path(cond_true_path)
        manager.push_path(cond_false_path)

        uc.emu_stop()
        return
    
    if ins_mnemonic.startswith('b.'):
        print("[+] encountered b.XX, stop")
        dest_addr = cur_ins.operands[0].imm
        next_addr = cur_ins.address + size
        cond_true_path = ZZPathInfo(dest_addr, cur_context, None)
        cond_false_path = ZZPathInfo(next_addr, cur_context, None)
        manager.push_path(cond_true_path)
        manager.push_path(cond_false_path)
        uc.emu_stop()
        return

  
    #3.4 判断是否到达间接跳转
    if ins_mnemonic == 'br' or ins_mnemonic == 'blr':

        table = manager.br_table
        if ins_mnemonic == 'blr':
            table = manager.blr_table

        _, _, cond_desc, _ = manager.cur_path.path_info()
        ins_addr_str = get_offset_str(cur_ins.address)
        _, reg_value = OBFUtil.parse_reg(cur_ins, cur_context, 0)

        #记录指令长度
        manager.ins_size_table[ins_addr_str] = size

        #记录BR/BLR信息
        dest_addr_desc = ''
        if cond_desc is None:
            dest_addr_desc = f'{hex(reg_value)} '
        else:
            dest_addr_desc = f'{cond_desc}: {hex(reg_value)} '
        
        if ins_addr_str in table:
            pre = table[ins_addr_str]
            result = pre + ' | ' + dest_addr_desc
            table[ins_addr_str] = result
        else:
            table[ins_addr_str] = dest_addr_desc
        
        #构造子路径
        sub_path = ZZPathInfo(reg_value, cur_context, None)
        manager.push_path(sub_path)

        uc.emu_stop()
        return
    





##################################################################################################################



#模拟执行指令流(指令路径), 返回分支路径数组
def emu_run_path(path):

    global manager

    start_addr, context, cond_desc = path.start_addr, path.context, path.cond_desc
    print(f'当前执行路径：\n addr = {get_offset_str(start_addr)}, cond_desc = {cond_desc}, context = {context}')

    #重置path状态
    manager.set_cur_path(path)

    #准备context，并执行
    OBFUtil.set_context(manager.uc, context)    
    manager.uc.emu_start(start_addr, manager.config.mem_code[0] + manager.config.mem_code[1])  




#patch BR/BLR指令：0：BR， 1：BLR
INS_MNEM_BR = 0
INS_MNEM_BLR = 1
def patch(insType):
    
    global manager
    
    bad_table = {}
    jump_table = None
    ins_mnemonic = None
    if insType == INS_MNEM_BR:
        jump_table = manager.br_table
        ins_mnemonic = 'B'
    else:
        jump_table = manager.blr_table
        ins_mnemonic = 'BR'

    for addr in jump_table.keys():

        addr_val = int(addr, 16)
        next_addr_val = addr_val + manager.ins_size_table[addr]

        jmp_infos = jump_table[addr].split(' | ')
        asm_code = None
        if len(jmp_infos) == 1:
            dest_addr = int(jmp_infos[0], 16)
            asm_code = f'{ins_mnemonic} {dest_addr}'
        elif len(jmp_infos) == 2:
            jump_info_true = None
            jump_info_false = None
            jump_info0 = jmp_infos[0]
            jump_info1 = jmp_infos[1]
            if 'true' in jump_info0:
                jump_info_true, jump_info_false = jump_info0, jump_info1
            else:
                jump_info_true, jump_info_false = jump_info1, jump_info0

            cond = jump_info_true.split('_')[0].upper()
            dest_addr_true = int(jump_info_true.split(':')[1], 16)
            dest_addr_false = int(jump_info_false.split(':')[1], 16)

            patch_ins_addr = addr_val 
            if dest_addr_true == next_addr_val:
                asm_code = f'{ins_mnemonic}.{ZZCondTable[cond]} {dest_addr_false}'    
            elif dest_addr_false == next_addr_val:
                asm_code = f'{ins_mnemonic}.{cond} {dest_addr_true}'
            else:
                patch_ins_addr = addr_val - 4
                asm_code = f'{ins_mnemonic}.{cond} {dest_addr_true};'
                asm_code += f'{ins_mnemonic} {dest_addr_false};'
              
        if asm_code is not None:
            bytes, _ = manager.ins_util.asm(asm_code, patch_ins_addr, True)
            print(f'asm_code = {asm_code}, addr = {addr}, bytes = {bytes}')
            idaapi.patch_bytes(addr_val, bytes)
        else:
            bad_table[addr] = jump_table[addr]
        
        
        #打印异常信息
        if len(bad_table) > 0:
            print(f'\n\n----------- {ins_mnemonic} 特殊情况，需手动patch ----------------')
            for addr in bad_table.keys():
                print(f'addr = {addr}, jmp_infos = {bad_table[addr]}' )


def deobf():
    
    global manager

    bin_end_addr = idc.get_inf_attr(idc.INF_MAX_EA)
    bin_bytes = idaapi.get_bytes(0, bin_end_addr)

    #1.创建unicorn
    uc = OBFUtil.create_unicorn(True, manager.config.mem_code, manager.config.mem_stack, bin_bytes, hook_code, hook_unmapped_mem_access)
    manager.set_uc(uc)

    #2.开始模拟执行
    first_path = ZZPathInfo(manager.config.mem_code[0] + manager.config.func_addr, None, None)
    manager.push_path(first_path) 
    
    #2.开始模拟执行
    while not manager.path_queue.empty(): #一直循环，直到队列为空
        #获取并执行path
        cur_path = manager.pop_path()
        emu_run_path(cur_path) 

    #3.打印结果
    manager.print_track_result()



################################################ 初始化并运行 #######################################################

def init():

    global manager

    #默认设置
    unicorn_mem_code =  (0x00000000, 20 * 0x1000 * 0x1000)      #代码：20M
    unicorn_mem_stack = (0x80000000, 8 * 0x1000 * 0x1000)       #栈：8M
    dead_code_ins_max_count = 1000                             #死代码最大指令条数

    #函数信息
    arch = ZZ_ARCH_ARM64
    func_start_addr = 0x1619C
    stack_chk_fail_func_addr = 0x160D0
    

    config = OBFConfig(unicorn_mem_code, unicorn_mem_stack, func_start_addr, stack_chk_fail_func_addr, dead_code_ins_max_count)
    manager = OBFManager(config, arch)


if __name__ == '__main__':

    init()
    deobf()

    print(f'\n\n\n------------------------ 开始patch BR -----------------------------------')
    patch(INS_MNEM_BR)

    print(f'\n\n\n------------------------ 开始patch BLR -----------------------------------')
    patch(INS_MNEM_BLR)
