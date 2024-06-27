

import idc
import idaapi
import ida_bytes
import pyperclip

import zzPluginBase.utils as utils
import zzPluginBase.keycap as keycap

################################### 选择代码块 #############################################

#获取寄存器名字
def get_regName(addr):
    disasm = idc.GetDisasm(addr)
    print("asm => " + disasm)
    disasm = disasm.upper()
    parts = disasm.split()
    if (parts[0] == 'BR') and len(parts) > 1:
        return parts[1]
    else:
        return ""


#检查选择代码是否有效
def check_code():

    invalid = (0, 0, 0, "")

    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if start == idaapi.BADADDR or end == idaapi.BADADDR:
        print("No code selected.")
        return invalid

    regName = get_regName(end - 4)
    if len(regName) < 1:
        print("not BR reg, please check~")
        return invalid
    
    return (1, start, end, regName)


#patch指令: 将BR Xn patch为 B 0xXXXX;  并添加注释
def patch_code(insnAddr, targetAddr):
    
    disasm = idc.GetDisasm(insnAddr)

    #1.patch
    code = f"B {hex(targetAddr)}"
    codeBytes =  keycap.generate_code(code, insnAddr)
    ida_bytes.patch_bytes(insnAddr, bytes(codeBytes))
    print("patch code => " +  hex(insnAddr) + " : " + code)

    #2.添加注释
    idaapi.set_cmt(insnAddr, disasm, 0)


###################################  复制代码 #############################################

#复制选中的汇编代码
def copyAsmCode():

    start = idc.read_selection_start()
    end = idc.read_selection_end()
    if start == idaapi.BADADDR or end == idaapi.BADADDR:
        print("No code selected.")
        return

    # 获取选中的代码
    code = ""
    while start < end:
        line = idc.GetDisasm(start)
        code += line + "\n"
        start += 4

    # 使用 pyperclip 复制代码
    print("selected asm code: \n", code)
    pyperclip.copy(code)
    return code


#复制选中的机器码
def copyMachineCode():

    start = idc.read_selection_start()
    end = idc.read_selection_end()

    if (start != idaapi.BADADDR) and (end != idaapi.BADADDR):
        codeBytes = idc.get_bytes(start, end - start)
        codeStr = utils.hexStrFromBytes(codeBytes)

        # 使用 pyperclip 复制代码
        print("selected machine code: \n", codeStr)
        pyperclip.copy(codeStr)
        return codeStr
    
    return ""



########################################## 生成模拟执行脚本 ############################################



#生成模拟执行脚本
def genEmuRunScript():

    (valid, start, end, regName) = check_code()
    if not valid:
        return

    last = end - 4

    codeBytes = idc.get_bytes(start, end - start)
    codeStr = utils.hexStrFromBytes(codeBytes)

    regName = get_regName(last)

    emu_run_script = '''
    start = %s
    end = %s
    regName = "%s"

    result = flareEmuRun.emu_run_code(start, end, regName)
    copyCode.patch_code(end, result)
    '''

    unicorn_run_script = '''
    codeHex = "%s"
    startAddr = %s
    regName = "%s"

    unicornRun.unicornRun(startAddr, codeHex, regName)
    '''

    emu_run_script = emu_run_script % (hex(start), hex(last), regName)
    unicorn_run_script = unicorn_run_script % (codeStr, hex(start), regName)

    # 打印
    print("=============================================")  
    print("selected machine code: \n", codeStr)

    print("=============================================")   
    print("flare_Emu script: \n", emu_run_script)

    print("=============================================")   
    print("unicorn script: \n", unicorn_run_script)


    
    

