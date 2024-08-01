'''
参考文档：https://bbs.kanxue.com/thread-282681.htm?style=1

'''

import idaapi
import idc
from unicorn import *
from unicorn.arm64_const import *
from keystone import *

BASE_reg = 0x81  # 基础寄存器编号，x0的编号是0x81(129), x1的编号是0x82(130), x2的编号是0x83(131), x3的编号是0x84(132)...  

class txxxxk:
    def __init__(self, address, size) -> None:
        self.start_addre = address  # 起始地址
        self.size = size  # 大小

        # 从IDA Pro获取指定地址处的字节数据
        data = idaapi.get_bytes(address, size)

        # 初始化Unicorn引擎
        self.mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.mu.mem_map(address & 0xfff000, 0x20000000)  # 内存映射
        self.mu.mem_write(address, data)  # 将数据写入内存
        self.mu.reg_write(UC_ARM64_REG_SP, 0x11000000)  # 设置栈指针
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)  # 添加指令钩子

        # 初始化各种变量和列表
        self.cmp_reg_num = 0  # 比较指令操作数的寄存器编号
        self.no_nop = []  # 不能nop的指令地址列表
        self.br_remake = []  # 需要重构的分支指令地址列表
        self.br_reg = []  # 分支指令涉及的寄存器列表
        self.b_addr1 = 0  # 分支目标地址1
        self.b_addr2 = 0  # 分支目标地址2
        self.cmp_condition = ""  # 比较条件
        self.ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)  # 初始化Keystone引擎，用于汇编指令

    def hook_code(self, mu, address, size, user_data):
        # 打印执行的地址
        print("%x" % address)

        # 解码指定地址处的指令
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, address)

        # 生成反汇编指令行
        dism = idc.generate_disasm_line(address, 0)

        # 处理ARM_cmp指令
        if insn.itype == idaapi.ARM_cmp:
            self.cmp_reg_num = insn.Op1.reg - BASE_reg   #得到op1寄存器序号
            self.br_remake.append(address)
            self.no_nop.append(address)

        # 处理ARM_csel指令
        if insn.itype == idaapi.ARM_csel:
            #1.读取csel指令中op2和op3寄存器的值
            self.b_addr1 = self.mu.reg_read(UC_ARM64_REG_X0 + insn.Op2.reg - BASE_reg)   #insn.Op2.reg - BASE_reg， 得到op2寄存器与x0寄存器的编号差
            self.b_addr2 = self.mu.reg_read(UC_ARM64_REG_X0 + insn.Op3.reg - BASE_reg)

            #2.将op2和op3寄存器序号写入br_reg列表，表示br跳转跟这两个寄存器有关。
            self.br_reg.append(insn.Op2.reg - BASE_reg)
            self.br_reg.append(insn.Op3.reg - BASE_reg)
            print("跳转地址 %x" % self.b_addr1)
            print("跳转地址 %x" % self.b_addr2)

            #3.记录
            self.br_remake.append(address)
            self.no_nop.append(address)
            self.cmp_condition = dism.split(",")[-1].split(" ")[-1]    #获取比较的条件

        # 处理ARM_br指令
        if insn.itype == idaapi.ARM_br:
            self.br_remake.append(address)
            self.no_nop.append(address)

    def start(self):
        try:
            # 开始从start_addre处执行模拟
            self.mu.emu_start(self.start_addre, self.start_addre + self.size)
        except UcError as e:
            if e.errno == UC_ERR_EXCEPTION:
                print("go on")
            else:
                print(e)
                print("ESP = %x" % self.mu.reg_read(UC_ARM64_REG_SP))
                return
        
        # 模拟结束后进行寄存器检查和操作
        self.check_reg()
        print("no_nop list ")
        print(self.no_nop)
        print("br_reg list ")
        print(self.br_reg)
        print("br list")
        print(self.br_remake)
        self.nop()
        self.change_ida_byte()

    def check_reg(self):
        # 检查寄存器以确定插入nop指令的位置
        i = self.size
        nop_list = []

        #从后往前遍历指令：
        while i >= 0:
            #1. 解码指定地址处的指令
            insn = idaapi.insn_t()
            idaapi.decode_insn(insn, self.start_addre + i)

            #2. 遍历当前指令的寄存器，如果其编号在br_reg列表中，则flag 设为 true，说明它有参与比较指令寄存器的操作，需要nop
            flag = False
            for op in insn.ops:
                if op.reg != 0 and (op.reg - BASE_reg) in self.br_reg:
                    flag = True

            #3.再次遍历当前指令的寄存器，如果其编号不在br_reg列表中，则添加进来到br_reg列表中。
            for op in insn.ops:
                if flag:
                    if op.reg != 0 and (op.reg - BASE_reg) not in self.br_reg and op.reg != 0xa1:
                        self.br_reg.append(op.reg - BASE_reg)
                    print("%x 参与计算的其他寄存器 %d" % (self.start_addre + i, op.reg - BASE_reg))
                    nop_list.append(self.start_addre + i)

            i -= 4

        # 从nop_list列表中移除掉不能nop的指令
        for no_nop_i in self.no_nop:
            if no_nop_i in nop_list:
                nop_list.remove(no_nop_i)

       #如果指令地址不在nop_list中，则添加进no_nop列表。 
        j = 0
        while j < self.size:
            if j + self.start_addre not in nop_list:
                self.no_nop.append(self.start_addre + j)
            j += 4

    def nop(self):
        # 在指定位置插入nop指令
        i = 0
        while i < self.size:
            if i + self.start_addre in self.no_nop:
                i += 4
                continue
            idaapi.patch_dword(i + self.start_addre, 0xD503201F)
            i += 4

    def change_ida_byte(self):
        # 修改IDA中的字节码以实现指令更改
        code = "B" + self.cmp_condition + " " + hex(self.b_addr1)
        print(code, self.br_remake[0])
        encoding, count = self.ks.asm(code, self.br_remake[0])
        i = 0
        print(code)
        for cc in encoding:
            idaapi.patch_byte(self.br_remake[0] + i, cc)
            i += 1
        code = "B" + " " + hex(self.b_addr2)
        encoding, count = self.ks.asm(code, self.br_remake[1])
        print(code)
        i = 0
        for cc in encoding:
            idaapi.patch_byte(self.br_remake[1] + i, cc)
            i += 1
