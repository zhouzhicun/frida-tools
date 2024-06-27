


import ida_bytes
import idaapi
import idc

from ida_idaapi import plugin_t

import zzPluginBase.copyCode as copyCode
import zzPluginBase.unicornRun as unicornRun
import zzPluginBase.keycap as keycap

#####################################  插件逻辑  ##############################################

# 
# 废弃插件，仅供学习参考
# 局限很大，对于复杂的花指令，比如访问较大的内存空间，或者有条件分支的指令，这个插件就不适用了.
#

def unicornRunCode():
    (valid, start, end, regName) = copyCode.check_code()
    if valid:
        codeHex = copyCode.copyMachineCode()
        unicornRun.unicornRun(start, codeHex, regName)



def unicornRunPatchCode():
    (valid, start, end, regName) = copyCode.check_code()
    if valid:
        codeHex = copyCode.copyMachineCode()
        result = unicornRun.unicornRun(start, codeHex, regName)
        copyCode.patch_code(start, end, result)



class UnicornRunCodeHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("UnicornRunCodeHandler")
        unicornRunCode()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class UnicornRunPatchCodeHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        print("UnicornRunPatchCodeHandler")
        unicornRunPatchCode()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



################################### 插件框架 #############################################

menu_main = 'zzUnicornEmuRunCode/'
menu_unicorn_run = 'my:zz_unicorn_emu_run_code'
menu_unicorn_run_patch = 'my:zz_unicorn_emu_run_code_patch'

class MyUIHooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(widget, popup_handle, menu_unicorn_run, menu_main)
            idaapi.attach_action_to_popup(widget, popup_handle, menu_unicorn_run_patch, menu_main)


class UnicornRunCodePlugin(plugin_t):

    comment = 'UnicornEmuRun插件'
    help = ''
    flags = idaapi.PLUGIN_KEEP
    wanted_name = 'zzUnicornEmuRunCode'
    wanted_hotkey = ''

    def init(self):
        print('zzUnicornRunCode init')

        # 初始化的时候将动作绑定到菜单
        # 这个函数不支持 kwargs
        # name, label, handler, shortcut=None, tooltip=None, icon=-1, flags=0
        run_code_action_desc = idaapi.action_desc_t(menu_unicorn_run, '运行选中的Code', UnicornRunCodeHandler(), '', '')
        idaapi.register_action(run_code_action_desc)
        run_code_patch_action_desc = idaapi.action_desc_t(menu_unicorn_run_patch, '运行选中的Code并Patch', UnicornRunPatchCodeHandler(), '', '')
        idaapi.register_action(run_code_patch_action_desc)

        global my_ui_hooks
        my_ui_hooks = MyUIHooks()
        my_ui_hooks.hook()
        return idaapi.PLUGIN_KEEP

    def run(self, arg: int):
        print('zzUnicornEmuRunCode plugin run')

    def term(self):
        print('zzUnicornEmuRunCode plugin term')


initialized = False
# 注册插件
def PLUGIN_ENTRY():
    return UnicornRunCodePlugin()

