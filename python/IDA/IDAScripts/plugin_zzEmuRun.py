

import ida_bytes
import idaapi
import idc

from ida_idaapi import plugin_t

import zzPluginBase.flareEmuRun as falreEmuRun
import zzPluginBase.keycap as keycap

#####################################  插件逻辑  ##############################################

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




#patch指令
def patch_code(startAddr, endAddr, targetAddr):

    insnCount = int((endAddr - startAddr) / 4)

    # patch 1: 将第一条指令 patch为 BR 0xXXXX;
    code = f"B {hex(targetAddr)}"
    codeBytes =  keycap.generate_code(code, startAddr)
    ida_bytes.patch_bytes(startAddr, bytes(codeBytes))
    print("patch code => " +  hex(startAddr) + " : " + code)

    #patch 2: 将选中的其他指令全部 patch为 NOP
    if insnCount > 1:
        nopCodeBytes = keycap.generate_code("nop", 0)
        ida_bytes.patch_bytes(startAddr + 4, bytes(nopCodeBytes) * (insnCount - 1))


###################################################################################

def emuRunCode():
    (valid, start, end, regName) = check_code()
    if valid:
        falreEmuRun.emu_run_code(start, end, regName)


def emuRunPatchCode():
    (valid, start, end, regName) = check_code()
    if valid:
        result = falreEmuRun.emu_run_code(start, end, regName)
        patch_code(start, end, result)



class EmuRunCodeHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):

        emuRunCode()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class EmuRunPatchCodeHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):

        emuRunPatchCode()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



################################### 插件框架 #############################################

menu_main = 'zzEmuRunCode/'
menu_emu_run = 'my:zz_run_code'
menu_emu_run_patch = 'my:zz_run_code_patch'

class MyUIHooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(widget, popup_handle, menu_emu_run, menu_main)
            idaapi.attach_action_to_popup(widget, popup_handle, menu_emu_run_patch, menu_main)


class EmuRunCodePlugin(plugin_t):

    comment = 'EmuRun插件'
    help = ''
    flags = idaapi.PLUGIN_KEEP
    wanted_name = 'zzEmuRunCode'
    wanted_hotkey = ''

    def init(self):
        print('zzEmuRunCode init')

        # 初始化的时候将动作绑定到菜单
        # 这个函数不支持 kwargs
        # name, label, handler, shortcut=None, tooltip=None, icon=-1, flags=0
        run_code_action_desc = idaapi.action_desc_t(menu_emu_run, '运行选中的Code', EmuRunCodeHandler(), '', '')
        idaapi.register_action(run_code_action_desc)
        run_code_patch_action_desc = idaapi.action_desc_t(menu_emu_run_patch, '运行选中的Code并Patch', EmuRunPatchCodeHandler(), '', '')
        idaapi.register_action(run_code_patch_action_desc)

        global my_ui_hooks
        my_ui_hooks = MyUIHooks()
        my_ui_hooks.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg: int):
        print('zzEmuRunCode plugin run')

    def term(self):
        print('zzEmuRunCode plugin term')


initialized = False
# 注册插件
def PLUGIN_ENTRY():
    return EmuRunCodePlugin()

