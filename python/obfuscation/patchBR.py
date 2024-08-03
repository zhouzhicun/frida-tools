import queue
import re
import struct

import keystone
import unicorn
from capstone.arm64_const import *

from unicorn.arm64_const import *
from unicorn import *

from elftools.elf.elffile import ELFFile



from insnUtil import *
from unicornStruct import *
from unicornUtil import *




# 1. 将函数头放到队列中
# 2. 从队列中取出一个地址，开始执行
# 3. 执行时，将执行过的指令和上下文保存到指令栈中
# 4. 判断是否到达了br reg
# 5. 如果到达了br reg，则从指令栈中取指令，判断计算目标地址(单分支、双分支)，patch跳转
# 6. 将目标地址放到队列中
# 7. 遇到了ret或者是bl .__stack_chk_fail 就停止



############################### 全局变量 ################################


bin_data = None
out_data = None
uc = None

img_size = 0
jmp_table_start = 0x144320
jmp_table_end = 0x148000

branch_path_dict = {}


insn_util = InsnUtil(ZZ_ARCH_ARM64)

#unicorn内存默认值
unicorn_mem_code = (0, 20 * 0x1000 * 0x1000)
unicorn_mem_stack = (0x80000000, 8 * 0x1000 * 0x1000)

#路径执行状态信息
path_state = PathState()

#函数信息
func_info = None




'''
BR表，存储br的跳转地址, 有两种情况：
1.单分支：(br指令地址，jmp目的地址)
2.双分支：(br指令地址_cond_true, jmp目的地址) 和 (br指令地址_cond_false, jmp目的地址)
'''
br_table = {}




#######################################################################################

# def get_double_branch(uc, ins_stack):
#     global insn_util
#     global bin_data

#     #ins_help = InsHelp()

#     flag_br = False
#     flag_sub_add = False
#     flag_ldr = False
#     flag_csel1 = False
#     flag_csel2 = False
#     br_reg = None
#     op_reg1 = None
#     op_reg2 = None
#     reg2_value1 = None
#     reg2_value2 = None
#     op_reg3 = None
#     reg3_value1= None
#     reg3_value2 = None
#     cond = ''

#     for tup in ins_stack[::-1]:
#         addr = tup[0]
#         context = tup[1]
#         ins = list(insn_util.gen_code(bin_data[addr: addr+5], addr, False))[0]

#         mnemonic = ins.mnemonic.lower()

#         # BR              X8
#         if mnemonic == 'br' and flag_br == False:
#             flag_br = True
#             br_reg = ins.operands[0].reg

#         # SUB             X8, X8, X9
#         if  flag_br == True and (mnemonic == 'add' or mnemonic == 'sub') \
#                 and ins.operands[0].reg == br_reg and flag_sub_add == False:
#             if ins.operands[1].type == 1 and ins.operands[2].type == 1:
#                 op_reg1 = ins.operands[1].reg
#                 op_reg2 = ins.operands[2].reg
#                 flag_sub_add = True

#         # CSEL            X9, X10, X9, EQ
#         if flag_sub_add == True and mnemonic == 'csel' and ins.operands[0].reg == op_reg2 \
#                 and flag_csel1 == False:
#             cond = ins.op_str.split(', ')[-1]
#             regname1 = ins.reg_name(ins.operands[1].reg)
#             regname2 = ins.reg_name(ins.operands[2].reg)
#             # index1 = reg_ctou(regname1) - arm64_const.UC_ARM64_REG_X0
#             # index2 = reg_ctou(regname2) - arm64_const.UC_ARM64_REG_X0
#             reg2_value1 = 0 if regname1.lower() == 'xzr' else context[get_unicorn_reg(regname1) - arm64_const.UC_ARM64_REG_X0]
#             reg2_value2 = 0 if regname2.lower() == 'xzr' else context[get_unicorn_reg(regname2) - arm64_const.UC_ARM64_REG_X0]
#             flag_csel1 = True

#         #  LDR             X8, [X25,X9]
#         if flag_sub_add == True and mnemonic == 'ldr' and ins.operands[0].reg == op_reg1 \
#                 and flag_ldr == False:
#             pattern = r'\[(.*?)\]'
#             matches = re.findall(pattern, ins.op_str)
#             assert len(matches) == 1, 'not find []: %x\t%s\t%s' % (addr, ins.mnemonic, ins.op_str)
#             op2_str = matches[0]
#             regs = op2_str.split(', ')
#             assert len(regs) == 2, 'ins invalid!: %x\t%s\t%s' % (addr, ins.mnemonic, ins.op_str)
#             table_base = context[get_unicorn_reg(regs[0]) - arm64_const.UC_ARM64_REG_X0]
#             op_reg3 = get_unicorn_reg(regs[1])
#             flag_ldr = True

#         #  CSEL            X9, X10, X9, EQ
#         if flag_ldr == True and mnemonic == 'csel' and get_unicorn_reg(ins.reg_name(ins.operands[0].reg)) == op_reg3 \
#                 and flag_csel2 == False:
#             regname1 = ins.reg_name(ins.operands[1].reg)
#             regname2 = ins.reg_name(ins.operands[2].reg)
#             # index1 = reg_ctou(regname1) - arm64_const.UC_ARM64_REG_X0
#             # index2 = reg_ctou(regname2) - arm64_const.UC_ARM64_REG_X0
#             reg3_value1 = 0 if regname1.lower() == 'xzr' else context[get_unicorn_reg(regname1) - arm64_const.UC_ARM64_REG_X0]
#             reg3_value2 = 0 if regname2.lower() == 'xzr' else context[get_unicorn_reg(regname2) - arm64_const.UC_ARM64_REG_X0]
#             flag_csel2 = True

#     if flag_csel1 == True and flag_csel2 == True:
#         # 满足条件时走的分支
#         barr1 = uc.mem_read(table_base + reg3_value1, 8) #直接从文件中读数据，注意内存偏移和文件偏移的转换


#         base1 = struct.unpack('q',barr1)
#         offset1 = base1[0] - reg2_value1

#         # 不满足条件时走的分支
#         barr2 = uc.mem_read(table_base + reg3_value2, 8)
#         base2 = struct.unpack('q',barr2)
#         offset2 = base2[0] - reg2_value2
#         return (offset1, offset2, UnicornUtil.get_context(uc), cond)
#     else:
#         return None

# def get_single_branch(uc, ins_stack):
#     global bin_data
#     global insn_util

#     last_addr = ins_stack[-1][0]

#     ins = list(insn_util.disasm(bin_data[last_addr: last_addr + 5], last_addr))[0]
#     if ins.mnemonic.lower() == 'br':
#         context = ins_stack[-1][1]
#         return (context[get_unicorn_reg(ins.reg_name(ins.operands[0].reg)) - arm64_const.UC_ARM64_REG_X0], UnicornUtil.get_context(uc))
#     else:
#         return None




##################################### patch ##################################################

# def find2nop(uc):

#     global insn_util
#     global jmp_table_start
#     global jmp_table_end
#     global out_data

#     for addr in range(jmp_table_start, jmp_table_end, 8):
#         barr = out_data[addr: addr+8]
#         ins_list = list(insn_util.disasm(barr, addr))
#         if ins_list[0].mnemonic.lower() == 'nop' and ins_list[1].mnemonic.lower() == 'nop':
#             return addr
#     return None

# def patch_bytes(old_bytes, new_bytes, addr, length):
#     tmp_bytes = old_bytes[:addr] + new_bytes + old_bytes[addr + length:]
#     return tmp_bytes

# def patch_single_branch(src, dest):
#     global out_data
#     ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
#     jmp_asm = 'b ' + hex(dest)
#     print('patch code: %x\t%s => %s' % (src,list(out_data[src: src + 4]), jmp_bin))
#     out_data = patch_bytes(out_data, bytearray(jmp_bin), src, 4)

# def patch_double_branch(uc, addr, branch):
#     global out_data

#     nop_addr = find2nop(uc)
#     assert nop_addr is not None, 'no find 2 nop'

#     offset1 = branch[0]
#     offset2 = branch[1]
#     cond = branch[3]

#     ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

#     # 1. 把bx reg修改成跳转到nop_addr
#     jmp1_asm = 'b ' + hex(nop_addr)
#     jmp1_bin = ks.asm(jmp1_asm, addr)[0]

#     # 2. bcond addr1
#     jmp2_asm = 'b' + cond + ' ' + hex(offset1)
#     jmp2_bin = ks.asm(jmp2_asm, nop_addr)[0]

#     #3. b addr2
#     jmp3_asm = 'b ' + hex(offset2)
#     jmp3_bin = ks.asm(jmp3_asm, nop_addr + 4)[0]
#     #print(jmp3_bin)

#     #patching
#     print('patch code: %x\t%s => %s' % (addr, list(out_data[addr: addr + 4]), jmp1_bin))
#     out_data = patch_bytes(out_data, bytearray(jmp1_bin), addr, 4)
#     print('patch code: %x\t%s => %s' % (nop_addr, list(out_data[nop_addr: nop_addr + 4]), jmp2_bin))
#     out_data = patch_bytes(out_data, bytearray(jmp2_bin), nop_addr, 4)
#     print('patch code: %x\t%s => %s' % (nop_addr + 4, list(out_data[nop_addr + 4: nop_addr + 8]), jmp3_bin))
#     out_data = patch_bytes(out_data, bytearray(jmp3_bin) , nop_addr + 4, 4)





#################################### unicorn hook ####################################################


def get_unicorn_reg(cap_reg_name): 
    return UnicornUtil.get_unicorn_reg_index(cap_reg_name)

def parse_reg_value(reg_name, context):
    reg_index = get_unicorn_reg(reg_name) - arm64_const.UC_ARM64_REG_X0
    reg_value = context[reg_index]
    return reg_value


def hook_code(uc, address, size, user_data):

    global insn_util
    global path_state
    global func_info
    global br_table
    
    if path_state.found_BR == True:
        uc.emu_stop()
        return

    #1.解析当前指令并打印
    code = uc.mem_read(address, size)
    ins = list(insn_util.disasm(code, address))[0]
    print("[+] tracing instruction\t0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))

    #2.记录指令信息
    path_state.ins_stack.append(InsnInfo(address, size, UnicornUtil.get_context(uc)))

    #3.判断指令
    ins_mnemonic = ins.mnemonic.lower()
    
    #3.0 首先判断是否为条件指令
    if UnicornUtil.is_condition(ins_mnemonic):
        #记录条件指令信息
        print("[+] condition instruction 0x%x\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
        path_state.condition_stack.append(InsnInfo(address, size, UnicornUtil.get_context(uc)))
        return


    #3.1 遇到ret直接停止
    if ins_mnemonic == 'ret':
        print("[+] encountered ret, stop")
        path_state.reset()
        uc.emu_stop()
        return

    #3.2 遇到bl .__stack_chk_fail停止
    if func_info.bl_stack_chk_fail_addr is not None and ins.address == func_info.bl_stack_chk_fail_addr:
        print("[+] encountered bl .__stack_chk_fail, stop")
        path_state.reset()
        uc.emu_stop()
        return

    #3.3 跳过bl、svc指令 以及非栈或so本身内存访问
    is_access_ilegel_mem = UnicornUtil.is_access_ilegal_memory(uc, ins, unicorn_mem_code, unicorn_mem_stack, None)
    if ins_mnemonic.startswith('bl') or ins_mnemonic.startswith('svc') or is_access_ilegel_mem:
        print("[+] pass instruction 0x%x\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
        uc.reg_write(UC_ARM64_REG_PC, address + size)  #跳过当前指令
        return
    
  
    #3.4 判断是否到达间接跳转
    if ins_mnemonic == "br":
        path_state.found_BR = True
        
        #1.解析br跳转地址, 并记录新路径
        br_ins_addr_str = hex(ins.address)
        br_reg_name = ins.reg_name(ins.operands[0].reg)
        br_dest_addr = parse_reg_value(br_reg_name, UnicornUtil.get_context(uc))

        path_state.br_branch.append(PathInfo(br_dest_addr, UnicornUtil.get_context(uc), None))
    
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
            cond_insn_info = path_state.condition_stack.pop()
            cond_code_bytes = uc.mem_read(cond_insn_info.addr, cond_insn_info.size)
            cond_ins = list(insn_util.disasm(cond_code_bytes, address))[0]

            #解析csel条件指令
            cond = ins.op_str.split(', ')[-1]
            csel_reg_name0 = ins.reg_name(ins.operands[0].reg)
            csel_reg_name1 = ins.reg_name(ins.operands[1].reg)
            csel_reg_name2 = ins.reg_name(ins.operands[2].reg)
            csel_reg_value1 = 0 if csel_reg_name1.lower() == 'xzr' else parse_reg_value(csel_reg_name1, cond_insn_info.context)
            csel_reg_value2 = 0 if csel_reg_name2.lower() == 'xzr' else parse_reg_value(csel_reg_name2, cond_insn_info.context)

            #找到当前条件的下一条指令
            next_ins_addr = cond_insn_info.addr + cond_insn_info.size
            next_insn_info = None
            for insn_info in path_state.ins_stack[::-1]:
                if insn_info.addr == next_ins_addr:
                    next_insn_info = insn_info
                    
            
            ##3.判断当前执行的是条件真分支还是假分支
            cur_br_desc = ''
            other_br_desc = ''
            csel_reg_value0 = parse_reg_value(csel_reg_name0, next_insn_info.context)
            if csel_reg_value0 == csel_reg_value1:
                #真
                cur_br_desc = br_ins_addr_str + '_' + cond + '_true'
                other_br_desc = br_ins_addr_str + '_' + cond + '_false'
                next_insn_info.context[get_unicorn_reg(csel_reg_name0) - arm64_const.UC_ARM64_REG_X0] = csel_reg_value2

            else :
                #假
                cur_br_desc = br_ins_addr_str + '_' + cond + '_false' 
                other_br_desc = br_ins_addr_str + '_' + cond + '_true'
                next_insn_info.context[get_unicorn_reg(csel_reg_name0) - arm64_const.UC_ARM64_REG_X0] = csel_reg_value1


            #1.更新BR表, 添加条件的另一个分支路径
            br_table[cur_br_desc] = hex(br_dest_addr)
            path_state.br_branch.append(PathInfo(next_insn_info.addr, next_insn_info.context, None))


        path_state.reset()
        uc.emu_stop()
        return
    

##################################################################################################################


def load_elf(filename):
    global img_size
    global out_data
    segs = []
    with open(filename, 'rb') as f:
        out_data = f.read()
        for seg in ELFFile(f).iter_segments('PT_LOAD'):
            print('file_off:%s, va: %s, size: %s' %(hex(seg['p_offset']), hex(seg['p_vaddr']), hex(seg['p_filesz'])))
            segs.append((seg['p_offset'],seg['p_vaddr'], seg['p_filesz'], seg.data()))

    img_size = segs[-1][1] + segs[-1][2]
    byte_arr = bytearray([0] * img_size)
    for seg in segs:
        vaddr = seg[1]
        size = seg[2]
        data = seg[3]
        byte_arr[vaddr: vaddr + size] = bytearray(data)

    return byte_arr

    # with open('out.bin', 'wb') as f:
    #     f.write(bytearray(byte_arr))



#模拟执行指令流(指令路径), 返回分支路径数组
def emu_run(path_start_addr, context, cond_desc):

    global uc
    global path_state

    #重置状态, 准备context
    path_state.reset()                      
    path_state.cond_desc = cond_desc
    UnicornUtil.set_context(uc, context)    

    #开始执行
    uc.emu_start(path_start_addr, 0x10000)  


     

def trace_path(start_addr):

    #1.初始化路径队列，函数入口是第一个节点，放到队列中去，队列中是PathInfo(地址，上下文, 条件描述);   条件是用于补跑路径用的。
    pathQueue = queue.Queue()
    pathQueue.put(PathInfo(start_addr, None, None)) 
    
    #2.开始模拟执行
    tracedPathDict = {} 
    while not pathQueue.empty(): #一直循环，直到队列为空
        addr, context, cond_desc = pathQueue.get()
        tracedPathDict[addr] = 1
        
        #2.1 模拟执行当前路径
        emu_run(addr, context, cond_desc) 

        branch_paths = path_state.br_branch
        for path in branch_paths:
            if path.start_addr not in tracedPathDict:
                pathQueue.put(path)  #将分支节点放到队列中


    #3.打印所有BR分支
    sorted_keys = sorted(br_table.keys())
    for key in sorted_keys:
        print('%s => %s' % (key, hex(br_table[key])))
            



def deobf(patch = True):
    global func_info
    global bin_data
    global uc

    #1.创建unicorn
    bin_data = bytes(load_elf(func_info.so_name))
    uc = UnicornUtil.create_unicorn(True, unicorn_mem_code, unicorn_mem_stack, bin_data, hook_code, default_hook_unmapped_mem_access)

    #2.模拟执行
    trace_path(func_info.start_addr)

    #3.patch
    if patch:
        patch_file_name = 'patch_' + func_info.so_name
        with open(patch_file_name, 'wb') as f:
            f.write(out_data)


#######################################################################################################


if __name__ == '__main__':

    so_name = 'libmtguard.so'
    start_addr = 0xFD0BC
    bl_stack_chk_fail_addr = None

    func_info = UnicornFuncInfo(so_name, start_addr, bl_stack_chk_fail_addr)
    deobf()
