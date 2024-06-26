
import ida_kernwin
import idaapi
import idc

import zzPluginBase.jniSignature as jniSignature


'''
jni_helper插件git仓库：https://github.com/evilpan/jni_helper

基于jni_helper插件修改，支持导入 hook_RegisterNativers.js（https://github.com/lasting-yang/frida_hook_libart） 脚本打印的日志，文件格式为txt。

'''


######################################## 插件实现 ################################################

# 定义日志函数，用于打印信息
def log(fmt, *args):
    print("[+]", fmt % args)

# 选择并解析文件
def select_and_parse_file():
    # 询问用户选择txt签名文件
    logfile = ida_kernwin.ask_file(0, "*.txt", "Select .txt log file")
    log("loading log file: %s", logfile)

    if logfile and logfile.endswith('.txt'):

        #打开并读取txt文件, 返回lines
        with open(logfile, 'r') as file:
            lines = file.readlines()
        print("lines = {}".format(lines))
        return lines
    
    return None


def load_methods(lines):

    for line in lines:
        line.strip()
        arr = line.split(" ")
        clsName = arr[2]
        funcName = arr[4]
        sig = arr[6]
        offset_info = arr[12].split("!")
        addr = int(offset_info[1], 16)

        jni_method_name, ret, args = jniSignature.parse_method_signature(clsName, funcName, sig)
        print("jni_method_name = {}, ret = {}, args = {}".format(jni_method_name, ret, args))
        apply_signature(addr,  jni_method_name, ret, args)


def apply_signature(ea, funcname, ret, args):
    log('apply 0x%x %s', ea, funcname)
    decl = '{} {}({})'.format(ret, funcname, args)
    # log(decl)
    prototype_details = idc.parse_decl(decl, idc.PT_SILENT)
    idc.set_name(ea, funcname)
    idc.apply_type(ea, prototype_details)


def main():
    log("zzJNIHelper plugin run")
    st = idc.set_ida_state(idc.IDA_STATUS_WORK)

    lines = select_and_parse_file()
    if lines:
        load_methods(lines)
    
    idc.set_ida_state(st)



######################################## 插件框架 ################################################

class JNIHelperPlugin(idaapi.plugin_t):
    flags = 0
    comment = "Import txt log file"
    help = "Apply log to JNI functions"
    wanted_name = "zzJNIHelper"
    wanted_hotkey = ""
    
    def init(self):
        log("zzJNIHelper plugin init")
        return idaapi.PLUGIN_OK 

    def term(self):
        log("zzJNIHelper plugin term")

    def run(self, arg):
        main()

def PLUGIN_ENTRY():
    return JNIHelperPlugin()