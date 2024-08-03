
from capstone import *
from keystone import *


ZZ_ARCH_ARM = 0
ZZ_ARCH_ARM64 = 1

class InsnUtil:

    def __init__(self, arch=ZZ_ARCH_ARM64):
        self.init_keystone(arch)
        self.init_capstone(arch)

    ######################################## disasm ###################################################
        
    #生成汇编代码
    # 使用： for i in disasm(hexstr, addr): print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    def disasm(self, hexstr, addr):
        code_bytes = bytes.fromhex(hexstr)
        return self.disasm(code_bytes, addr)
    
    def disasm(self, code_bytes, addr):
        return self.cs.disasm(code_bytes, addr)

        
    #生成汇编代码
    # 使用： for (address, size, mnemonic, op_str) in disasm_lite(hexstr, addr):
    def disasm_lite(self, hexstr, addr):
        code_bytes = bytes.fromhex(hexstr)
        return self.disasm_lite(code_bytes, addr)
    
    def disasm_lite(self, code_bytes, addr):
        return self.cs.disasm_lite(code_bytes, addr)
    

    ######################################## asm ###################################################

    #生成机器码
    # 使用：encoding, count = generate_code(asm_str, addr)
    def asm(self, asm_str, addr):
        return self.ks.asm(asm_str, addr)   


######################################## init ###################################################


    def init_keystone(self, arch):
        if arch == ZZ_ARCH_ARM64:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)
        else:
            self.ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
    

    def init_capstone(self, arch):
        if arch == ZZ_ARCH_ARM64:
            self.cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
        else:
            self.cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)

        self.cs.detail = True        # 设置为详细反汇编模式
        self.cs.skipdata = True      # 设置反汇编跳过数据





###################################### keystone汇编 ####################################################

'''
汇编(ARM64)
ks.asm(code, addr) 是 Keystone 库中的一个函数，用于将汇编代码转换为机器代码。
它接受两个参数：
code：一个字符串，包含要编译的汇编代码。
addr：一个整数，表示代码的起始地址。

这个函数返回一个元组，包含两个元素：
1.一个字节列表，表示编译后的机器代码。
2.一个整数，表示编译的指令数量。
'''

ks = keystone.Ks(keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN)

#code0 = generate_code("sub sp, sp, #0x10; nop", 0)  支持单行或者多行汇编代码，多行汇编代码用分号隔开
def generate_code(asm_code, addr):
    encoding, _ = ks.asm(asm_code, addr)   
    return encoding



###################################### Capstone反汇编 ####################################################


'''
反汇编
md.disasm() 是 Capstone 库中的一个函数，用于反汇编二进制代码。
它接受二进制代码和代码的起始地址作为输入，返回一个生成器，该生成器产生反汇编的指令。
每个生成的指令是一个 CsInsn 对象，包含以下属性：
address: 指令的地址
mnemonic: 指令的助记符
op_str: 指令的操作数，作为字符串
size: 指令的大小（字节数）
bytes: 指令的原始字节，作为字节串
id: 指令的ID
groups: 指令所属的组
regs_read: 指令读取的寄存器
regs_write: 指令写入的寄存器
operands: 指令的操作数，作为一个列表
'''
cs = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
# 设置为详细反汇编模式
cs.detail = True
# 设置反汇编跳过数据
cs.skipdata = True


'''
cs.disasm 用于反汇编二进制代码，返回一个生成器，该生成器产生反汇编的指令。
返回一个生成器，该生成器产生反汇编的指令；每个生成的指令是一个 CsInsn 对象。
'''
def generate_asm(hexstr, addr):
    codebytes = bytes.fromhex(hexstr)
    return cs.disasm(codebytes, addr)

'''
disasm_lite 轻量级反汇编，相比cs.disasm 开销更小
它会做基础的反汇编工作，仅返回：地址、指令助记符、指令长度、操作数这四个信息的元组
返回迭代器：每次迭代返回一个元组，包含上述四个信息
'''
def generate_asm_lite(hexstr, addr):
    codebytes = bytes.fromhex(hexstr)
    return cs.disasm_lite(codebytes, addr)


###################################### IDA指令解析API ####################################################


'''
IDA 指令解析API：
1.调用decode_insn, decode_insn 返回指令长度，ARM64即4，无法解析则返回0
insn = ida_ua.insn_t()
insnLen = ida_ua.decode_insn(insn, ea)

2.调用DecodeInstruction, 解析成功返回 insn对象，解析失败返回 None. 
idautils.DecodeInstruction(ea)

'''



###################################### demo ####################################################

''' 

def demo_keystore():
    asm_code = "sub sp, sp, #0x10; nop"
    addr = 0x10000
    encoding = generate_code(asm_code, addr)
    print(encoding)


def demo_generate_asm():
    hexstr = "FF0301D1F44F02A9FD7B03A9"
    addr = 0x1000
    for i in generate_asm(hexstr, addr): print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


def demo_generate_asm_lite():
    hexstr = "FF0301D1F44F02A9FD7B03A9"
    addr = 0x1000
    for (address, size, mnemonic, op_str) in generate_asm_lite(hexstr, addr):
        print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))



print("==================== 1 ==================")
demo_keystore()

print("==================== 2 ==================")
demo_generate_asm()

print("==================== 3 ==================")
demo_generate_asm_lite()


'''