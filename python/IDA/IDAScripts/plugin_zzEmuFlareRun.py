

import ida_bytes
import idaapi
import idc

from ida_idaapi import plugin_t

import zzPluginBase.flareEmuRun as falreEmuRun
import zzPluginBase.copyCode as copyCode
import zzPluginBase.keycap as keycap

#####################################  插件逻辑  ##############################################


def emuRunCode():
    (valid, start, end, regName) = copyCode.check_code()
    if valid:
        falreEmuRun.emu_run_code(start, end, regName)


def emuRunPatchCode():
    (valid, start, end, regName) = copyCode.check_code()
    if valid:
        result = falreEmuRun.emu_run_code(start, end, regName)
        copyCode.patch_code(start, end, result)


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

menu_main = 'zzFlareEmuRunCode/'
menu_emu_run = 'my:zz_flare_emu_run_code'
menu_emu_run_patch = 'my:zz_flare_emu_run_code_patch'

class MyUIHooks(idaapi.UI_Hooks):

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if idaapi.get_widget_type(widget) == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(widget, popup_handle, menu_emu_run, menu_main)
            idaapi.attach_action_to_popup(widget, popup_handle, menu_emu_run_patch, menu_main)


class EmuRunCodePlugin(plugin_t):

    comment = 'FlareEmuRun插件'
    help = ''
    flags = idaapi.PLUGIN_KEEP
    wanted_name = 'zzFlareEmuRunCode'
    wanted_hotkey = ''

    def init(self):
        print('zzFlareEmuRunCode init')

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
        print('zzFlareEmuRunCode plugin run')

    def term(self):
        print('zzFlareEmuRunCode plugin term')


initialized = False
# 注册插件
def PLUGIN_ENTRY():
    return EmuRunCodePlugin()

