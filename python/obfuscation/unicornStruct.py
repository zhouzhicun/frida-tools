



#指令信息
class InsnInfo:
    def __init__(self, addr, size, context):
        self.addr = addr
        self.size = size
        self.context = context


#路径信息
class PathInfo:
    def __init__(self, start_addr, context, cond_desc):
        self.start_addr = start_addr
        self.context = context
        self.cond_desc = cond_desc

#路径状态
class PathState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.found_BR = False       #是否找到BR
        self.cond_desc = None       #条件描述
        self.insn_stack = []        #指令栈
        self.condition_stack = []   #条件栈
        self.br_branch = []         #BR分支路径

#函数信息     
class FuncInfo:
    def __init__(self, so_name, start_addr, bl_stack_chk_fail_addr = None):
        self.so_name = so_name
        self.start_addr = start_addr
        self.bl_stack_chk_fail_addr = bl_stack_chk_fail_addr



