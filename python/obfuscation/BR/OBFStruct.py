

#配置
class OBFConfig:
    def __init__(self, arch, mem_code, mem_stack, so_start_addr, so_end_addr, stack_chk_fail_func_addr, dead_code_insn_max_count, trace_ins_path_table):
        self.arch = arch
        self.mem_code = mem_code                                    #代码内存范围
        self.mem_stack = mem_stack                                  #栈内存范围
        self.so_start_addr = so_start_addr                          #so代码起止地址
        self.so_end_addr = so_end_addr                              
        self.stack_chk_fail_func_addr = stack_chk_fail_func_addr    #__stack_chk_fail_addr函数地址
        self.dead_code_insn_max_count = dead_code_insn_max_count    #死代码检测最大指令条数
        self.trace_ins_path_table = trace_ins_path_table            #需要trace指令的路径表

#条件指令信息
class ZZCondInfo:
    def __init__(self, cond_ins_name, cond, dest_reg_name, cond_true_value, cond_false_value):
        self.cond_ins_name = cond_ins_name          #条件指令名字
        self.cond = cond                            #条件
        self.dest_reg_name = dest_reg_name          #目的寄存器名字
        self.cond_true_value = cond_true_value      #条件true的值
        self.cond_false_value = cond_false_value    #条件false的值

#路径信息
class ZZPathInfo:
    def __init__(self, prev_addr, start_addr, context, cond_desc):
        self.prev_addr = prev_addr          #上一条指令
        self.start_addr = start_addr        #起始地址
        self.context = context              #上下文
        self.cond_desc = cond_desc          #条件描述
        self.ins_count = 0

    def path_desc(self):
        path_desc = hex(self.start_addr)
        if self.cond_desc is not None:
            path_desc = path_desc + ' ' + self.cond_desc
        return path_desc 

    def path_info(self):
        return self.start_addr, self.context, self.cond_desc, self.ins_count


