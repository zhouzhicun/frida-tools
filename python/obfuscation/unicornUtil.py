from unicorn.arm64_const import *
from unicorn import *

from capstone.arm64_const import *




def default_hook_unmapped_mem_access(uc, type, address, size, value, userdata):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print('error! access invalid mem, pc:%x type:%d addr:%x size:%x' % (pc, type, address, size))
    uc.emu_stop()
    return False





#unicorn工具类
class UnicornUtil:
    def __init__(self):
        pass

    ################################### 创建unicorn引擎 #######################################

    @classmethod 
    def create_unicorn(cls, isArm64, code_mem, stack_mem, codebytes, hook_code = None, hook_unmapped_mem_access = None):

        #创建一个unicorn引擎
        uc = None
        if isArm64:
            uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        else:
            uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)

        #code
        uc.mem_map(code_mem[0], code_mem[1])
        uc.mem_write(code_mem[0], codebytes)
        
        #stack, 并设置sp寄存器
        uc.mem_map(stack_mem[0], stack_mem[1])
        uc.reg_write(UC_ARM64_REG_SP, stack_mem[0] + stack_mem[1] - 1024 * 1024)


        #设置指令执行hook，执行每条指令都会走hook_code
        if hook_code is not None:
            uc.hook_add(UC_HOOK_CODE, hook_code)
        
        #设置非法内存访问hook
        if hook_unmapped_mem_access is not None:
            uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped_mem_access)

        return uc
        


    ################################### 条件指令 ##########################################

    #判断指令 ins_mnemonic 是否为条件指令，如果是返回 True，否则返回 False。
    @classmethod
    def is_condition(cls, ins_mnemonic):
        ins_mnemonic = ins_mnemonic.lower()
        if ins_mnemonic == "csel" or ins_mnemonic == "cset":
            return True
        return False


    ################################### 内存有效性 ##########################################

    
    #判断指令 ins 中是否存在非法内存访问。
    @classmethod
    def is_access_ilegel_memory(cls, uc, ins, code_mem, stack_mem, params_mem = None):

        code_base, code_size = code_mem
        stack_base, stack_size = stack_mem
        params_base, params_size = params_mem
        
        #1.检查指令的操作数字符串中是否包含内存访问的标记 '[', 没有直接返回false
        if ins.op_str.find('[') == -1:
            return False
        
        #2.判断是否通过sp访问内存，是的话直接返回false
        if ins.op_str.find('[sp') != -1:
            return False 
        
        #3.计算内存地址，并校验地址是否位于有效范围
        for op in ins.operands:
            if op.type == ARM64_OP_MEM:
                addr = 0
                if op.value.mem.base != 0:
                    addr += uc.reg_read(UnicornUtil.get_unicorn_reg_index(ins.reg_name(op.value.mem.base)))
                if op.value.mem.index != 0:
                    addr += uc.reg_read(UnicornUtil.get_unicorn_reg_index(ins.reg_name(op.value.mem.index)))
                if op.value.mem.disp != 0:
                    addr += op.value.mem.disp

                if code_base <= addr <= (code_base + code_size): # 访问so中的数据，允许
                    return False
                elif stack_base <= addr < (stack_base + stack_size): #访问栈中的数据，允许
                    return False
                else:
                    return True




    ################################ 寄存器转换 ####################################

    @classmethod
    def get_unicorn_reg_index(cls, reg_name): 
        reg_type = reg_name[0].lower()
        if reg_type == 'w' or reg_type == 'x':
            idx = int(reg_name[1:])
            if reg_type == 'w':
                return idx + UC_ARM64_REG_W0
            else:
                if idx == 29:
                    return 1
                elif idx == 30:
                    return 2
                else:
                    return idx + UC_ARM64_REG_X0
        elif reg_name.lower() == 'sp':
            return 4
        return None
    

    @classmethod
    def get_reg_name(cls, unicorn_reg_idx):
        if unicorn_reg_idx == 1:
            return 'fp'
        elif unicorn_reg_idx == 2:
            return 'lr'
        elif unicorn_reg_idx == 4:
            return 'sp'
        
        if UC_ARM64_REG_W0 <= unicorn_reg_idx <= UC_ARM64_REG_W30:
            return 'w' + str(unicorn_reg_idx - UC_ARM64_REG_W0)
        elif UC_ARM64_REG_X0 <= unicorn_reg_idx <= UC_ARM64_REG_X30:
            index = unicorn_reg_idx - UC_ARM64_REG_X0 
            if index == 29:
                return 'fp'
            elif index == 30:
                return 'lr'
            return 'x' + str(index)
        return None


    ################################# context操作 ######################################

    @classmethod
    def set_context(cls, uc, regs):
        if regs is None:
            return

        for i in range(29):  # x0 ~ x28
            idx = UC_ARM64_REG_X0 + i
            uc.reg_write(idx, regs[i])
        uc.reg_write(UC_ARM64_REG_FP, regs[29])  # fp
        uc.reg_write(UC_ARM64_REG_LR, regs[30])  # lr
        uc.reg_write(UC_ARM64_REG_SP, regs[31])  # sp

    @classmethod
    def get_context(cls, uc):
        regs = []
        for i in range(29):
            idx = UC_ARM64_REG_X0 + i
            regs.append(uc.reg_read(idx))
        regs.append(uc.reg_read(UC_ARM64_REG_FP))
        regs.append(uc.reg_read(UC_ARM64_REG_LR))
        regs.append(uc.reg_read(UC_ARM64_REG_SP))
        return regs
