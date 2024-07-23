


import idaapi
from ida_idaapi import plugin_t

import zzPluginBase.utils as utils
import zzPluginBase.funcUtils as funcUtils
import zzPluginBase.pluginUtils as pluginUtils



################################ 插件逻辑 ##########################################

svc0_code = "010000D4"       #svc 0
svc80_code = "011000D4"      #svc 0x80

def searchAllSVC():
    segNames = None
    matchSVC0 = utils.searchCode(segNames, svc0_code)
    matchSVC80 = utils.searchCode(segNames, svc80_code)
    printResult("found SVC0 at all: \n", matchSVC0)
    printResult("found SVC80 at all: \n", matchSVC80)

    segNames = ['.text']
    matchSVC0 = utils.searchCode(segNames, svc0_code)
    matchSVC80 = utils.searchCode(segNames, svc80_code)
    printResult("found SVC0 at .text: \n", matchSVC0)
    printResult("found SVC80 at .text: \n", matchSVC0)



def searchBR():
    brCode = funcUtils.get_all_instructions("BR")
    print("found BR at .text: \n" + brCode)



def searchCSEL():
    cselCode = funcUtils.get_all_instructions("CSEL")
    ssetCode = funcUtils.get_all_instructions("CSET")
    print("found CSEL at .text: \n" + cselCode)
    print("found CSET at .text: \n" + ssetCode)
    

def printResult(tip, matchAddrs):
    str = tip
    for addr in matchAddrs:
        str += hex(addr) + ","
    print(str)  



#################################### 插件配置 ##################################################


ZZSearchCode_wanted_name = 'ZZSearchCode'
ZZSearchCode_comment = ''
ZZSearchCode_help = ''
ZZSearchCode_wanted_hotkey = ''
ZZSearchCode_flags = idaapi.PLUGIN_KEEP

ZZSearchCodeMenuConfig = pluginUtils.PluginMenuConfig("ZZSearchCode/", [
    pluginUtils.PluginSubMenu('my:search_svc', '搜索SVC指令', searchAllSVC),
    pluginUtils.PluginSubMenu('my:search_br', '搜索BR指令', searchBR),
    pluginUtils.PluginSubMenu('my:search_csel', '搜索CSEL/CSET指令', searchCSEL)
])


#################################### 插件框架 ##################################################

class ZZSearchCodeUIHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        pluginUtils.registerUIHook(widget, popup_handle, ZZSearchCodeMenuConfig)


class ZZSearchCode(plugin_t):

    wanted_name = ZZSearchCode_wanted_name
    comment = ZZSearchCode_comment
    help = ZZSearchCode_help
    wanted_hotkey = ZZSearchCode_wanted_hotkey
    flags = ZZSearchCode_flags


    def init(self):

        pluginUtils.registerAction(ZZSearchCodeMenuConfig)

        global my_ui_hooks
        my_ui_hooks = ZZSearchCodeUIHooks()
        my_ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    # 插件运行中 这里是主要逻辑
    def run(self, arg: int):
        pass

    def term(self):
        pass 


# 注册插件
def PLUGIN_ENTRY():
    return ZZSearchCode()















