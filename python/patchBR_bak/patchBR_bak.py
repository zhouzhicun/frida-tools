import queue
import re
import struct

import keystone
import unicorn
from capstone.arm64_const import *
from elftools.elf.elffile import ELFFile
from unicorn.arm64_const import *
from unicorn import *
from ins_help import *


'''
来源：https://bbs.kanxue.com/thread-280231.htm
'''


# 1. 将函数头放到队列中
# 2. 从队列中取出一个地址，开始执行
# 3. 执行时，将执行过的指令和上下文保存到指令栈中
# 4. 判断是否到达了br reg
# 5. 如果到达了br reg，则从指令栈中取指令，判断计算目标地址(单分支、双分支)，patch跳转
# 6. 将目标地址放到队列中
# 7. 遇到了ret或者是bl .__stack_chk_fail 就停止

bin_data = None
out_data = None
uc = None
ins_stack = []
block_flow = {}
is_success = False
img_size = 0
jmp_table_start = 0x144320
jmp_table_end = 0x148000

def reg_ctou(regname):  #
    # This function covert capstone reg name to unicorn reg const.
    type1 = regname[0]
    if type1.lower() == 'w' or type1.lower() == 'x':
        idx = int(regname[1:])
        if type1.lower() == 'w':
            return idx + UC_ARM64_REG_W0
        else:
            if idx == 29:
                return 1
            elif idx == 30:
                return 2
            else:
                return idx + UC_ARM64_REG_X0
    elif regname.lower() == 'sp':
        return 4
    return None

def is_ref_ilegel_emm(mu, ins):
    if ins.op_str.find('[') != -1:
        if ins.op_str.find('[sp') == -1:  # 不是通过sp访问内存
            for op in ins.operands:
                if op.type == ARM64_OP_MEM:
                    addr = 0
                    if op.value.mem.base != 0:
                        addr += mu.reg_read(reg_ctou(ins.reg_name(op.value.mem.base)))
                    if op.value.mem.index != 0:
                        addr += mu.reg_read(reg_ctou(ins.reg_name(op.value.mem.index)))
                    if op.value.mem.disp != 0:
                        addr += op.value.mem.disp
                    if 0x0 <= addr <= img_size: # 访问so中的数据，允许
                        return False
                    elif 0x80000000 <= addr < 0x80000000 + 0x1000 * 0x1000 * 8: #访问栈中的数据，允许
                        return False
                    else:
                        return True
        else:# 是通过sp的内存访问，允许
            return False
    else:
        return False

def set_context(uc, regs):
    if regs is None:
        return

    for i in range(29):  # x0 ~ x28
        idx = UC_ARM64_REG_X0 + i
        uc.reg_write(idx, regs[i])
    uc.reg_write(UC_ARM64_REG_FP, regs[29])  # fp
    uc.reg_write(UC_ARM64_REG_LR, regs[30])  # lr
    uc.reg_write(UC_ARM64_REG_SP, regs[31])  # sp

def get_context(uc):
    regs = []
    for i in range(29):
        idx = UC_ARM64_REG_X0 + i
        regs.append(uc.reg_read(idx))
    regs.append(uc.reg_read(UC_ARM64_REG_FP))
    regs.append(uc.reg_read(UC_ARM64_REG_LR))
    regs.append(uc.reg_read(UC_ARM64_REG_SP))
    return regs

def get_double_branch(uc, ins_stack):
    global bin_data

    ins_help = InsHelp()

    flag_br = False
    flag_sub_add = False
    flag_ldr = False
    flag_csel1 = False
    flag_csel2 = False
    br_reg = None
    op_reg1 = None
    op_reg2 = None
    reg2_value1 = None
    reg2_value2 = None
    op_reg3 = None
    reg3_value1= None
    reg3_value2 = None
    cond = ''

    for tup in ins_stack[::-1]:
        addr = tup[0]
        context = tup[1]
        ins = list(ins_help.disasm(bin_data[addr: addr+5], addr, False))[0]

        # BR              X8
        if ins.mnemonic.lower() == 'br' and flag_br == False:
            flag_br = True
            br_reg = ins.operands[0].reg

        # SUB             X8, X8, X9
        if  flag_br == True and (ins.mnemonic.lower() == 'add' or ins.mnemonic.lower() == 'sub') \
                and ins.operands[0].reg == br_reg and flag_sub_add == False:
            if ins.operands[1].type == 1 and ins.operands[2].type == 1:
                op_reg1 = ins.operands[1].reg
                op_reg2 = ins.operands[2].reg
                flag_sub_add = True

        # CSEL            X9, X10, X9, EQ
        if flag_sub_add == True and ins.mnemonic.lower() == 'csel' and ins.operands[0].reg == op_reg2 \
                and flag_csel1 == False:
            cond = ins.op_str.split(', ')[-1]
            regname1 = ins.reg_name(ins.operands[1].reg)
            regname2 = ins.reg_name(ins.operands[2].reg)
            # index1 = reg_ctou(regname1) - arm64_const.UC_ARM64_REG_X0
            # index2 = reg_ctou(regname2) - arm64_const.UC_ARM64_REG_X0
            reg2_value1 = 0 if regname1.lower() == 'xzr' else context[reg_ctou(regname1) - arm64_const.UC_ARM64_REG_X0]
            reg2_value2 = 0 if regname2.lower() == 'xzr' else context[reg_ctou(regname2) - arm64_const.UC_ARM64_REG_X0]
            flag_csel1 = True

        #  LDR             X8, [X25,X9]
        if flag_sub_add == True and ins.mnemonic.lower() == 'ldr' and ins.operands[0].reg == op_reg1 \
                and flag_ldr == False:
            pattern = r'\[(.*?)\]'
            matches = re.findall(pattern, ins.op_str)
            assert len(matches) == 1, 'not find []: %x\t%s\t%s' % (addr, ins.mnemonic, ins.op_str)
            op2_str = matches[0]
            regs = op2_str.split(', ')
            assert len(regs) == 2, 'ins invalid!: %x\t%s\t%s' % (addr, ins.mnemonic, ins.op_str)
            table_base = context[reg_ctou(regs[0]) - arm64_const.UC_ARM64_REG_X0]
            op_reg3 = reg_ctou(regs[1])
            flag_ldr = True

        #  CSEL            X9, X10, X9, EQ
        if flag_ldr == True and ins.mnemonic.lower() == 'csel' and reg_ctou(ins.reg_name(ins.operands[0].reg)) == op_reg3 \
                and flag_csel2 == False:
            regname1 = ins.reg_name(ins.operands[1].reg)
            regname2 = ins.reg_name(ins.operands[2].reg)
            # index1 = reg_ctou(regname1) - arm64_const.UC_ARM64_REG_X0
            # index2 = reg_ctou(regname2) - arm64_const.UC_ARM64_REG_X0
            reg3_value1 = 0 if regname1.lower() == 'xzr' else context[reg_ctou(regname1) - arm64_const.UC_ARM64_REG_X0]
            reg3_value2 = 0 if regname2.lower() == 'xzr' else context[reg_ctou(regname2) - arm64_const.UC_ARM64_REG_X0]
            flag_csel2 = True

    if flag_csel1 == True and flag_csel2 == True:
        # 满足条件时走的分支
        barr1 = uc.mem_read(table_base + reg3_value1, 8) #直接从文件中读数据，注意内存偏移和文件偏移的转换


        base1 = struct.unpack('q',barr1)
        offset1 = base1[0] - reg2_value1

        # 不满足条件时走的分支
        barr2 = uc.mem_read(table_base + reg3_value2, 8)
        base2 = struct.unpack('q',barr2)
        offset2 = base2[0] - reg2_value2
        return (offset1, offset2, get_context(uc), cond)
    else:
        return None

def get_single_branch(uc, ins_stack):
    global bin_data
    last_addr = ins_stack[-1][0]
    ins_help = InsHelp()
    ins = list(ins_help.disasm(bin_data[last_addr: last_addr + 5], last_addr, False))[0]
    if ins.mnemonic.lower() == 'br':
        context = ins_stack[-1][1]
        return (context[reg_ctou(ins.reg_name(ins.operands[0].reg)) - arm64_const.UC_ARM64_REG_X0], get_context(uc))
    else:
        return None

def find2nop(uc):
    global jmp_table_start
    global jmp_table_end
    global out_data

    help = InsHelp()
    for addr in range(jmp_table_start, jmp_table_end, 8):
        barr = out_data[addr: addr+8]
        ins_list = list(help.disasm(barr, addr, False))
        if ins_list[0].mnemonic.lower() == 'nop' and ins_list[1].mnemonic.lower() == 'nop':
            return addr
    return None

def patch_bytes(old_bytes, new_bytes, addr, length):
    tmp_bytes = old_bytes[:addr] + new_bytes + old_bytes[addr + length:]
    return tmp_bytes

def patch_single_branch(src, dest):
    global out_data
    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
    jmp_asm = 'b ' + hex(dest)
    jmp_bin = ks.asm(jmp_asm, src)[0]
    print('patch code: %x\t%s => %s' % (src,list(out_data[src: src + 4]), jmp_bin))
    out_data = patch_bytes(out_data, bytearray(jmp_bin), src, 4)
def patch_double_branch(uc, addr, branch):
    global out_data

    nop_addr = find2nop(uc)
    assert nop_addr is not None, 'no find 2 nop'

    offset1 = branch[0]
    offset2 = branch[1]
    cond = branch[3]

    ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

    # 1. 把bx reg修改成跳转到nop_addr
    jmp1_asm = 'b ' + hex(nop_addr)
    jmp1_bin = ks.asm(jmp1_asm, addr)[0]

    # 2. bcond addr1
    jmp2_asm = 'b' + cond + ' ' + hex(offset1)
    jmp2_bin = ks.asm(jmp2_asm, nop_addr)[0]

    #3. b addr2
    jmp3_asm = 'b ' + hex(offset2)
    jmp3_bin = ks.asm(jmp3_asm, nop_addr + 4)[0]
    #print(jmp3_bin)

    #patching
    print('patch code: %x\t%s => %s' % (addr, list(out_data[addr: addr + 4]), jmp1_bin))
    out_data = patch_bytes(out_data, bytearray(jmp1_bin), addr, 4)
    print('patch code: %x\t%s => %s' % (nop_addr, list(out_data[nop_addr: nop_addr + 4]), jmp2_bin))
    out_data = patch_bytes(out_data, bytearray(jmp2_bin), nop_addr, 4)
    print('patch code: %x\t%s => %s' % (nop_addr + 4, list(out_data[nop_addr + 4: nop_addr + 8]), jmp3_bin))
    out_data = patch_bytes(out_data, bytearray(jmp3_bin) , nop_addr + 4, 4)
def hook_code(uc, address, size, user_data):
    global ins_stack
    global is_success

    if is_success == True:
        uc.emu_stop()
        return

    ins_help = InsHelp()
    code = uc.mem_read(address, size)
    ins = list(ins_help.disasm(code, address, False))[0]

    print("[+] tracing instruction\t0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))

    #记录指令和上下文环境
    ins_stack.append((address, get_context(uc)))

    #遇到ret直接挺停止
    if ins.mnemonic.lower() == 'ret':
        #uc.reg_write(UC_ARM64_REG_PC, 0)
        print("[+] encountered ret, stop")
        ins_stack.clear()
        uc.emu_stop()
        return

    #遇到bl .__stack_chk_fail停止
    if ins.mnemonic.lower() == 'bl' and ins.operands[0].imm == 0x237C0:
        #uc.reg_write(UC_ARM64_REG_PC, 0)
        print("[+] encountered bl .__stack_chk_fail, stop")
        ins_stack.clear()
        uc.emu_stop()
        return

    #跳过bl、非栈、so本身内存访问、svc
    if ins.mnemonic.lower().startswith('bl') or is_ref_ilegel_emm(uc, ins) or ins.mnemonic.lower().startswith('svc'):
        print("[+] pass instruction 0x%x\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
        uc.reg_write(UC_ARM64_REG_PC, address + size)
        return

    if ins.mnemonic == "br":
        #判断是否到达间接跳转
        is_success = True
        block_base = ins_stack[0][0]
        jmp_addr = ins_stack[-1][0]
        ret = get_double_branch(uc, ins_stack)
        if ret != None:
            print('find double branch: %x => %x, %x' % (block_base, ret[0], ret[1]))
            block_flow[ins_stack[0][0]] = ret
            patch_double_branch(uc, jmp_addr, ret)
        else:
            ret = get_single_branch(uc, ins_stack)
            if ret == None:
                print("[+] find dest failed 0x%x\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
                is_success = False
            else:
                print('find single branch: %x => %x' % (block_base, ret[0]))
                block_flow[block_base] = ret
                patch_single_branch(jmp_addr, ret[0])
        ins_stack.clear()
        uc.emu_stop()
        return
def hook_mem_access(uc, type, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print('error! access invalid mem, pc:%x type:%d addr:%x size:%x' % (pc, type, address, size))
    uc.emu_stop()
    return False

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

def init_unicorn(file_name):
    global bin_data
    global uc

    #装载一下so到内存
    bin_data = bytes(load_elf(file_name))

    uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

    uc.mem_map(0x80000000, 8 * 0x1000 * 0x1000)
    uc.mem_map(0, 8 * 0x1000 * 0x1000)
    # 写入so数据
    uc.mem_write(0, bin_data)
    #设置sp寄存器
    uc.reg_write(UC_ARM64_REG_SP, 0x80000000 + 0x1000 * 0x1000 * 6)
    #设置指令执行hook，执行每条指令都会走hook_code
    uc.hook_add(UC_HOOK_CODE, hook_code)
    #设置非法内存访问hook
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_access)

    barr = uc.mem_read(0x144320, 8)
    print(barr)

def run(addr, context):
    global uc
    global is_success
    global block_flow

    #开始模拟执行，函数返回说明在hook_code中执行了emu_stop
    set_context(uc, context)
    uc.emu_start(addr, 0x10000)
    if is_success == True:
        is_success = False
        return block_flow[addr] #返回分支信息和context

def deobf():
    # 初始化unicorn
    filename = 'libmtguard.so'
    patched_filename = 'out.so'
    start_addr = 0xFD0BC

    init_unicorn(filename)

    q = queue.Queue()
    q.put((start_addr, None)) # 入口函数是第一个节点，放到队列中去，队列中是(地址，上下文)
    traced = {} # 跑过的节点
    while not q.empty(): #一直循环，直到队列为空
        addr, context = q.get()
        traced[addr] = 1 # 跑过了
        s = run(addr, context) #开始模拟执行，找br reg

        if s is None:
            continue

        if len(s) == 2: #单分支
            if s[0] not in traced:
                q.put(s) #将分支节点放到队列中
        else: #双分支
            if s[0] not in traced:
                q.put((s[0], s[2]))#将分支节点放到队列中
            if s[1] not in traced:
                q.put((s[1], s[2]))#将分支节点放到队列中

    #打印代码流
    for addr in block_flow:
        if len(block_flow[addr]) == 4:
            print('%s => %s, %s, %s' % (hex(addr), hex(block_flow[addr][0]), hex(block_flow[addr][1]), block_flow[addr][3]))
        else:
            print('%s => %s' % (hex(addr), hex(block_flow[addr][0])))

    #保存patch后的so
    with open(patched_filename, 'wb') as f:
        f.write(out_data)

if __name__ == '__main__':
    deobf()
    #load_elf('libmtguard.so')