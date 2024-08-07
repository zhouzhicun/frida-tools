from unicorn.arm64_const import *
from unicorn import *

from capstone.arm64_const import *

from OBFStruct import *








#unicorn工具类
class OBFUtil:
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
        


    ################################### 条件指令以及解析逻辑 ##########################################

    #判断指令 ins_mnemonic 是否为条件指令，如果是返回 True，否则返回 False。
    @classmethod
    def is_condition(cls, ins_mnemonic):
        ins_mnemonic = ins_mnemonic.lower()
        if ins_mnemonic == "csel" or ins_mnemonic == "cset":
            return True
        return False
    
    #解析条件指令
    @classmethod
    def parse_cond_info(cls, ins, context):
        ins_mnemonic = ins.mnemonic.lower() 
        if ins_mnemonic == 'csel':
            return OBFUtil.parse_CSEL_cond(ins, context)
        elif ins_mnemonic == 'cset':
            return OBFUtil.parse_CSET_cond(ins, context)
        else:
            return None


    #解析csel条件指令
    @classmethod
    def parse_CSEL_cond(cls, ins, context):

        cond = ins.op_str.split(', ')[-1]
        csel_reg_name0 = ins.reg_name(ins.operands[0].reg)
        csel_reg_name1 = ins.reg_name(ins.operands[1].reg)
        csel_reg_name2 = ins.reg_name(ins.operands[2].reg)
        csel_true_value = 0 if csel_reg_name1.lower() == 'xzr' else OBFUtil.get_reg_value(context, csel_reg_name1)
        csel_false_value = 0 if csel_reg_name2.lower() == 'xzr' else OBFUtil.get_reg_value(context, csel_reg_name2)
        print(f'csel_reg_name0 = {csel_reg_name0}')
        return ZZCondInfo('csel', cond, csel_reg_name0, csel_true_value, csel_false_value)

    
    #解析cset条件指令
    @classmethod
    def parse_CSET_cond(cls, ins, context):
        cond = ins.op_str.split(', ')[-1]
        csel_reg_name0 = ins.reg_name(ins.operands[0].reg)
        csel_true_value = 1
        csel_false_value = 0
        print(f'cset_reg_name0 = {csel_reg_name0}')
        return ZZCondInfo('cset', cond, csel_reg_name0, csel_true_value, csel_false_value)


    ################################### 死代码检测 ##########################################

    @classmethod
    def is_simple_dead_code(cls, ins):
        ins_mnemonic = ins.mnemonic.lower()
        if ins_mnemonic == "b":
            dest_addr = ins.operands[0].imm
            if ins.address == dest_addr:
                return True
        return False


    ################################### 内存有效性 ##########################################

    #判断是否是调用__stack_chk_fail_addr
    @classmethod
    def is_call_stack_chk_fail(cls, ins, context, func__stack_chk_fail_addr):

        if func__stack_chk_fail_addr is None:
            return False

        ins_mnemonic = ins.mnemonic.lower()
        if ins_mnemonic == 'bl':
            func_addr = ins.operands[0].imm
            if func_addr == func__stack_chk_fail_addr:
                return True
            
        if ins_mnemonic == 'blr':
            func_addr = OBFUtil.get_reg_value(context, ins.reg_name(ins.operands[0].reg))
            if func_addr == func__stack_chk_fail_addr:
                return True

        return False

    
    #判断指令 ins 中是否存在非法内存访问。
    @classmethod
    def is_access_ilegel_memory(cls, uc, ins, code_mem, stack_mem):

        code_base, code_size = code_mem
        stack_base, stack_size = stack_mem
        
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
                    addr += uc.reg_read(OBFUtil.get_unicorn_reg_index(ins.reg_name(op.value.mem.base)))
                if op.value.mem.index != 0:
                    addr += uc.reg_read(OBFUtil.get_unicorn_reg_index(ins.reg_name(op.value.mem.index)))
                if op.value.mem.disp != 0:
                    addr += op.value.mem.disp

                if code_base <= addr <= (code_base + code_size): # 访问so中的数据，允许
                    return False
                elif stack_base <= addr < (stack_base + stack_size): #访问栈中的数据，允许
                    return False
                else:
                    return True




    ################################ 寄存器操作 ####################################

    @classmethod
    def get_unicorn_reg_index(cls, reg_name): 
        reg_name = reg_name.lower()
        reg_type = reg_name[0]
        if reg_type == 'w' or reg_type == 'x':
            idx = int(reg_name[1:])

            if reg_type == 'w':
                #1.w0-w30
                return idx + UC_ARM64_REG_W0   
            else:
                #2.x0-x30
                if idx == 29:
                    return 1
                elif idx == 30:
                    return 2
                else:
                    return idx + UC_ARM64_REG_X0
        elif reg_name == 'sp':
            return 4
        return None
    

    @classmethod
    def get_reg_name(cls, unicorn_reg_idx):

        #1.fp, lr, sp
        if unicorn_reg_idx == 1:
            return 'fp'
        elif unicorn_reg_idx == 2:
            return 'lr'
        elif unicorn_reg_idx == 4:
            return 'sp'
        
        #2.x0-x28, fp, lr
        if UC_ARM64_REG_W0 <= unicorn_reg_idx <= UC_ARM64_REG_W30:
            #2.1 w0-w30
            return 'w' + str(unicorn_reg_idx - UC_ARM64_REG_W0)
        elif UC_ARM64_REG_X0 <= unicorn_reg_idx <= UC_ARM64_REG_X30:
            #2.2 x0-x30
            index = unicorn_reg_idx - UC_ARM64_REG_X0 
            if index == 29:
                return 'fp'
            elif index == 30:
                return 'lr'
            return 'x' + str(index)
        return None



    #读取寄存器的值
    @classmethod
    def get_reg_value(cls, context, reg_name):
        reg_name = reg_name.lower()
        reg_type = reg_name[0]

        #判断是否为32位寄存器，如果是，则将w寄存器转x寄存器，再取低32位
        if reg_type == 'w':
            reg_idx = int(reg_name[1:])
            reg_name = ''
            if reg_idx == 30:
                reg_name = 'lr'
            elif reg_idx == 29:
                reg_name = 'fp'
            else:
                reg_name = 'x' + str(reg_idx)
            
            reg_value = context[reg_name]
            return reg_value & 0xFFFFFFFF   #读取寄存器的低32位
        else:
            reg_value = context[reg_name]
            return reg_value



    @classmethod
    def set_reg_value(cls, context, reg_name, new_reg_value):
        print(f'reg_name = {reg_name}')
        reg_name = reg_name.lower()
        reg_type = reg_name[0]
        
        #判断是否为32位寄存器，如果是，则先读取对应64位寄存器的值，再修改低32位，再写入上下文
        if reg_type == 'w':
            reg_idx = int(reg_name[1:])
            reg_name = ''
            if reg_idx == 30:
                reg_name = 'lr'
            elif reg_idx == 29:
                reg_name = 'fp'
            else:
                reg_name = 'x' + str(reg_idx)
            reg_value = context[reg_name]
            reg_value = (reg_value & 0xFFFFFFFF00000000) | (new_reg_value & 0xFFFFFFFF)
            context[reg_name] = reg_value
        else:
            context[reg_name] = new_reg_value  
        
        return context


    ################################# context操作 ######################################

    @classmethod
    def set_context(cls, uc, regs):
        if regs is None:
            return
        
        #1.x0-x28
        for i in range(29):  
            reg_name = 'x' + str(i)
            reg_idx = UC_ARM64_REG_X0 + i
            uc.reg_write(reg_idx, regs[reg_name])

        uc.reg_write(UC_ARM64_REG_FP, regs['fp'])  # fp
        uc.reg_write(UC_ARM64_REG_LR, regs['lr'])  # lr
        uc.reg_write(UC_ARM64_REG_SP, regs['sp'])  # sp


    @classmethod
    def get_context(cls, uc):
        
        regs = {}
        
        #2.x0-x28
        for i in range(29):
            reg_name = 'x' + str(i)
            reg_idx = UC_ARM64_REG_X0 + i
            regs[reg_name] = uc.reg_read(reg_idx)

        #3.fp, lr, sp
        regs['fp'] = uc.reg_read(UC_ARM64_REG_FP)
        regs['lr'] = uc.reg_read(UC_ARM64_REG_LR)
        regs['sp'] = uc.reg_read(UC_ARM64_REG_SP)
        return regs
