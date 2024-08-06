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



############################### 全局变量 ################################

uc = None

#指令工具类
insn_util = None

#函数信息
func_info = None

#路径执行状态信息
path_state = None


'''
BR表，存储br的跳转地址, 有两种情况：
1.单分支：(br指令地址，jmp目的地址)
2.双分支：(br指令地址_cond_true, jmp目的地址) 和 (br指令地址_cond_false, jmp目的地址)
'''
br_table = {}


#unicorn内存默认值
unicorn_mem_code = None
unicorn_mem_stack = None

#死代码检测，最大指令条数
check_dead_code_max_insn_count = 10000





#################################### unicorn hook ####################################################

def get_offset_str(addr):
    global unicorn_mem_code
    return hex(addr - unicorn_mem_code[0])


def path_insn(ins, context):
    pass


def hook_unmapped_mem_access(uc, type, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print('error! access invalid mem, pc:%s type:%d addr:%x size:%x' % (get_offset_str(pc), type, get_offset_str(address), size))
    uc.emu_stop()
    return False


def hook_code(uc, address, size, user_data):

    global insn_util
    global func_info
    global path_state
    global br_table

    if path_state.found_BR == True:
        uc.emu_stop()
        return

    #1.解析当前指令并打印
    code = uc.mem_read(address, size)
    ins = list(insn_util.disasm(code, address))[0]
    cur_context = OBFUtil.get_context(uc)
    print("[+] tracing instruction\t%s:\t%s\t%s" % (get_offset_str(ins.address), ins.mnemonic, ins.op_str))


    #2.记录指令信息
    cur_insn_info = ZZInsnInfo(address, size, cur_context)
    path_state.insn_stack.append(cur_insn_info)

    
    ins_mnemonic = ins.mnemonic.lower()

    
    #3.判断指令
    #3.0 首先判断是否为条件指令
    if OBFUtil.is_condition(ins_mnemonic):
        
        #记录条件指令信息
        print("[+] condition instruction 0x%s\t%s\t%s" % (get_offset_str(ins.address), ins.mnemonic, ins.op_str))
        
        cond_info = OBFUtil.parse_cond_info(ins, cur_context)
        path_state.condition_stack.append(ZZInsnInfo(address, size, cur_context, cond_info))
        path_state.prev_insn_is_cond = True
    else:
        if path_state.prev_insn_is_cond:
            #上一条是条件指令, 则更新该条件指令的next_insn_info信息
            last_cond_insn_info = path_state.condition_stack.pop()
            last_cond_insn_info.next_insn_info = cur_insn_info
            path_state.condition_stack.append(last_cond_insn_info)

        path_state.prev_insn_is_cond = False
    

    #3.1 遇到ret直接停止
    if ins_mnemonic == 'ret':
        print("[+] encountered ret, stop")
        path_state.reset()
        uc.emu_stop()
        return

    #3.2 遇到bl .__stack_chk_fail停止
    if OBFUtil.is_call_stack_chk_fail(ins, cur_context, func_info.stack_chk_fail_func_addr):
        print("[+] encountered bl .__stack_chk_fail, stop")
        path_state.reset()
        uc.emu_stop()
        return

    #3.3 简单死代码检测
    if OBFUtil.is_simple_dead_code(ins):
        print("[+] encountered dead code, stop")
        path_state.reset()
        uc.emu_stop()
        return
    
    #3.4 可能是死代码
    if len(path_state.insn_stack) > check_dead_code_max_insn_count:
        print("[+] encountered too many instructions, stop; 可能是死代码")
        path_state.reset()
        uc.emu_stop()
        return


    #3.3 跳过bl、svc指令 以及非栈或so本身内存访问
    is_access_ilegel_mem = OBFUtil.is_access_ilegel_memory(uc, ins, unicorn_mem_code, unicorn_mem_stack)
    if ins_mnemonic.startswith('bl') or ins_mnemonic.startswith('svc') or is_access_ilegel_mem:
        print("[+] pass instruction 0x%s\t%s\t%s" % (get_offset_str(ins.address), ins.mnemonic, ins.op_str))
        uc.reg_write(UC_ARM64_REG_PC, address + size)  #跳过当前指令
        return
    
  
    #3.4 判断是否到达间接跳转
    if ins_mnemonic == "br":
       
        path_state.found_BR = True
        
        #1.解析br跳转地址, 
        br_ins_addr_str = hex(ins.address)
        br_reg_name = ins.reg_name(ins.operands[0].reg)
        br_dest_addr = OBFUtil.get_reg_value(cur_context, br_reg_name)
        
        #并记录新路径
        path_state.sub_branch_path.append(ZZPathInfo(br_dest_addr, cur_context, None))
        print("添加条件分支路径11:" + get_offset_str(br_dest_addr))
    
        ##2.判断是否存在条件分支
        cond_count = len(path_state.condition_stack)
        if cond_count == 0:
            #没有条件, 说明是单分支或某个路径的第二分支
            #1.更新BR表
            if path_state.cond_desc is None:
                br_table[br_ins_addr_str] = hex(br_dest_addr)
            else:
                br_table[path_state.cond_desc] = hex(br_dest_addr)
            
        else:
            #取出条件指令
            last_cond_insn_info = path_state.condition_stack.pop()
               
            #取出条件信息和下一条指令的相关信息
            cond_info = last_cond_insn_info.cond_info
            next_insn_info = last_cond_insn_info.next_insn_info
            next_insn_context = next_insn_info.context

            ##3.判断当前执行的是条件真分支还是假分支
            cur_br_desc = ''
            other_br_desc = ''

            cond_dest_reg_value = OBFUtil.get_reg_value(next_insn_context, cond_info.dest_reg_name) 
            if cond_dest_reg_value == cond_info.cond_true_value:
                #真
                cur_br_desc = br_ins_addr_str + '_' + cond_info.cond + '_true'
                other_br_desc = br_ins_addr_str + '_' + cond_info.cond + '_false'

                #用条件的false值更新下一条指令的上下文
                next_insn_context = OBFUtil.set_reg_value(next_insn_context, cond_info.dest_reg_name, cond_info.cond_false_value)

            else :
                #假
                cur_br_desc = br_ins_addr_str + '_' + cond_info.cond + '_false' 
                other_br_desc = br_ins_addr_str + '_' + cond_info.cond + '_true'
           
                #用条件的true值更新下一条指令的上下文
                next_insn_context = OBFUtil.set_reg_value(next_insn_context, cond_info.dest_reg_name, cond_info.cond_true_value)


            #1.更新BR表, 添加条件的另一个分支路径
            br_table[cur_br_desc] = hex(br_dest_addr)
            path_state.sub_branch_path.append(ZZPathInfo(next_insn_info.addr, next_insn_context, other_br_desc))
            print("添加条件分支路径22:" + get_offset_str(br_dest_addr) + "; desc =" + other_br_desc)
    
        
        uc.emu_stop()
        return
    

##################################################################################################################



#模拟执行指令流(指令路径), 返回分支路径数组
def emu_run(path_start_addr, context, cond_desc):

    global uc
    global path_state

    #重置状态, 准备context
    path_state.reset()                      
    path_state.cond_desc = cond_desc
    OBFUtil.set_context(uc, context)    

    #开始执行
    uc.emu_start(path_start_addr, unicorn_mem_code[0] + unicorn_mem_code[1])  



def trace_path(start_addr):

    global func_info
    global path_state
    global br_table

    #1.初始化路径队列，函数入口是第一个节点，放到队列中去，队列中是PathInfo(地址，上下文, 条件描述);   条件是用于补跑路径用的。
    pathQueue = queue.Queue()
    pathQueue.put(ZZPathInfo(start_addr, None, None)) 
    
    #2.开始模拟执行
    tracedPathDict = {} 
    while not pathQueue.empty(): #一直循环，直到队列为空
        cur_path = pathQueue.get()
        addr, context, cond_desc = cur_path.start_addr, cur_path.context, cur_path.cond_desc
        print(f'当前执行路径：\n addr = {get_offset_str(addr)}, cond_desc = {cond_desc}, context = {context}')
        
        tracedPathDict[addr] = 1
        
        #2.1 模拟执行当前路径
        emu_run(addr, context, cond_desc) 

        print("当前路径模拟执行完毕~~~")
        branch_paths = path_state.sub_branch_path
        print("当前路径模拟执行完毕~~~" + "得到分支路径条数：" + str(len(branch_paths)))
        for path in branch_paths:
            print(f'新的path: \n addr = {path.start_addr}, cond_desc = {path.cond_desc}, context = {path.context}')
            if path.start_addr not in tracedPathDict:
                print("添加到队列")
                pathQueue.put(path)  #将分支节点放到队列中

    #3.打印所有BR分支
    print('---------------- print all br -----------------')
    sorted_keys = sorted(br_table.keys())
    for key in sorted_keys:
        sub_arr = key.split('_')
        if len(sub_arr) > 1:
            print('br_addr = %s, %s => %s' % (sub_arr[0],  key, br_table[key]))
        else:
            print('%s => %s' % (key, br_table[key]))
            



def deobf():
    
    global func_info
    global uc

    binaryFileEnd = idc.get_inf_attr(idc.INF_MAX_EA)
    print("binaryFileEnd ==>" + hex(binaryFileEnd))
    ARM_CODE = idaapi.get_bytes(0, binaryFileEnd)

    data_start = 0
    data_end = 0
    for seg in idautils.Segments():
        name = idc.get_segm_name(seg)
        if name == ".data":
            start = idc.get_segm_start(seg)
            end = idc.get_segm_end(seg)


    #1.创建unicorn
    uc = OBFUtil.create_unicorn(True, unicorn_mem_code, unicorn_mem_stack, ARM_CODE, hook_code, hook_unmapped_mem_access)

    #2.模拟执行
    trace_path(func_info.start_addr)

    # #3.patch
    # if patch:
    #     patch_file_name = 'patch_' + func_info.so_name
    #     with open(patch_file_name, 'wb') as f:
    #         f.write(out_data)


################################################ 初始化并运行 #######################################################


def init():

    global insn_util
    global path_state
    global func_info

    global unicorn_mem_code
    global unicorn_mem_stack
    global check_dead_code_max_insn_count

    #unicorn内存默认值
    unicorn_mem_code =  (0x00000000, 20 * 0x1000 * 0x1000)      #代码：20M
    unicorn_mem_stack = (0x80000000, 8 * 0x1000 * 0x1000)       #栈：8M

    #死代码检测，最大指令条数
    check_dead_code_max_insn_count = 10000

    #函数信息
    func_start_addr = 0x1619C
    stack_chk_fail_func_addr = 0x160D0
    func_info = ZZFuncInfo(None, unicorn_mem_code[0] + func_start_addr, unicorn_mem_code[0] + stack_chk_fail_func_addr)


    #其他
    insn_util = OBFInsnUtil(ZZ_ARCH_ARM64)
    path_state = ZZPathState()



if __name__ == '__main__':

    init()

    deobf()
