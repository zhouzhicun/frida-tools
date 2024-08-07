

#条件指令信息
class ZZCondInfo:
    def __init__(self, cond_ins_name, cond, dest_reg_name, cond_true_value, cond_false_value):
        self.cond_ins_name = cond_ins_name          #条件指令名字
        self.cond = cond                            #条件
        self.dest_reg_name = dest_reg_name          #目的寄存器名字
        self.cond_true_value = cond_true_value      #条件true的值
        self.cond_false_value = cond_false_value    #条件false的值


#指令信息
class ZZInsnInfo:
    def __init__(self, addr, size, context, cond_info = None, next_insn_info = None):
        self.addr = addr                        #指令地址
        self.size = size                        #指令长度
        self.context = context                  #当前上下文
        self.cond_info = cond_info              #条件信息
        self.next_insn_info = next_insn_info    #下一条指令信息


#路径信息
class ZZPathInfo:
    def __init__(self, start_addr, context, cond_desc):
        self.start_addr = start_addr        #起始地址
        self.context = context              #上下文
        self.cond_desc = cond_desc          #条件描述 

#路径状态
class ZZPathState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.found_BR = False           #是否找到BR
        self.cond_desc = None           #条件描述
        self.insn_stack = []            #指令栈
        self.prev_insn_is_cond = False  #上一条指令是否为条件指令
        self.condition_stack = []       #条件指令栈
        self.sub_branch_path = []            #当前路径的子分支路径，即BR跳转的子分支路径



#函数信息  
class ZZFuncInfo:
    def __init__(self, so_name, start_addr, stack_chk_fail_func_addr):
        self.so_name = so_name              #soName
        self.start_addr = start_addr        #起始地址
        self.stack_chk_fail_func_addr = stack_chk_fail_func_addr  #__stack_chk_fail_addr函数地址
        print("-------------------------")
        print(f'start_addr = {start_addr}, stack_chk_fail_func_addr = {stack_chk_fail_func_addr}')



