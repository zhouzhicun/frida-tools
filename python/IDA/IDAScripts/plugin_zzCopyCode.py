
import idc
import idaapi
import pyperclip

from ida_idaapi import plugin_t

import zzPluginBase.copyCode as copyCode


###################################  插件逻辑  #############################################


class CopyAsmCodeHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        copyCode.copyAsmCode()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class CopyMachineCodeHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        copyCode.copyMachineCode()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    

class GenEmuScriptHandler(idaapi.action_handler_t):

    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        copyCode.genEmuRunScript()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


############################################## 插件框架  ##########################################################

menu_main = 'zzCopyCode/'
menu_copy_asm = 'my:copy_asm_code'
menu_copy_machine = 'my:copy_machine_code'
menu_gen_emu_script = 'my:gen_emu_script_code'

class MyUIHooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(widget, popup_handle, menu_copy_asm, menu_main)
            idaapi.attach_action_to_popup(widget, popup_handle, menu_copy_machine, menu_main)
            idaapi.attach_action_to_popup(widget, popup_handle, menu_gen_emu_script, menu_main)


class CopyCodePlugin(plugin_t):

    comment = 'CopyCode插件'
    help = ''
    flags = idaapi.PLUGIN_KEEP
    wanted_name = 'zzCopyCode'
    wanted_hotkey = ''


    def init(self):
        print('zzCopyCode init')

        # 初始化的时候将动作绑定到菜单
        # 这个函数不支持 kwargs
        # name, label, handler, shortcut=None, tooltip=None, icon=-1, flags=0
        copy_asm_code_action_desc = idaapi.action_desc_t(menu_copy_asm, '复制选中的AsmCode', CopyAsmCodeHandler(), '', '')
        idaapi.register_action(copy_asm_code_action_desc)
        copy_machine_code_action_desc = idaapi.action_desc_t(menu_copy_machine, '复制选中的machineCode', CopyMachineCodeHandler(), '', '')
        idaapi.register_action(copy_machine_code_action_desc)
        gen_emu_script_action_desc = idaapi.action_desc_t(menu_gen_emu_script, '生成选中指令的模拟执行脚本', GenEmuScriptHandler(), '', '')
        idaapi.register_action(gen_emu_script_action_desc)

        global my_ui_hooks
        my_ui_hooks = MyUIHooks()
        my_ui_hooks.hook()
        return idaapi.PLUGIN_KEEP

    # 插件运行中 这里是主要逻辑
    def run(self, arg: int):
        print('GenFridaCode run')

    def term(self):
        print('zzCopyCode term')


# 注册插件
def PLUGIN_ENTRY():
    return CopyCodePlugin()

