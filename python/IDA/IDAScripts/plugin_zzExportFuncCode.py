# -*- coding:utf-8 -*-
import os
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
import ida_nalt
import idaapi
import idautils
import idc
import time

#
#仓库地址：https://github.com/jitcor/export_func_code/
#

# 获取SO文件名和路径
def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    filepath,filename = os.path.split(fullpath)
    return filepath,filename

# 获取代码段的范围
def getSegAddr():
    textStart = []
    textEnd = []

    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)).lower() == '.text' or (
        idc.get_segm_name(seg)).lower() == 'text'or (
        idc.get_segm_name(seg)).lower() == '__text':
            tempStart = idc.get_segm_start(seg)
            tempEnd = idc.get_segm_end(seg)

            textStart.append(tempStart)
            textEnd.append(tempEnd)

    if len(textStart) > 0:
        return min(textStart), max(textEnd)
    else:
        return 0, idc.BADADDR


def getTextSegAddr():
    textStart = []
    textEnd = []
    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)).lower() == '.text' or (
        idc.get_segm_name(seg)).lower() == 'text'or (
        idc.get_segm_name(seg)).lower() == '__text':
            tempStart = idc.get_segm_start(seg)
            tempEnd = idc.get_segm_end(seg)

            textStart.append(tempStart)
            textEnd.append(tempEnd)

    if len(textStart) > 0:
        return min(textStart), max(textEnd)
    else:
        return 0, 0


def getAllAddr():
    return 0, idc.BADADDR


def export(start, end):
    ea = start
    ed = end
    so_path, so_name = getSoPathAndName()
    script_name = so_name.split(".")[0] + "_" + str(int(time.time())) +".txt"
    save_path = os.path.join(so_path, script_name)
    print(f"导出路径：{save_path}")
    F=open(save_path, "w+", encoding="utf-8")
    F.write("\n#####################################\n")
    for func in idautils.Functions(ea, ed):
        try:
            functionName = str(idaapi.ida_funcs.get_func_name(func))
            if len(list(idautils.FuncItems(func))) > 10:
                # 如果是thumb模式，地址+1
                arm_or_thumb = idc.get_sreg(func, "T")
                if arm_or_thumb:
                    func += 1

                #反编译函数，得到伪代码
                code=str(idaapi.decompile(func))+"\n#####################################\n"
                print(code)
                F.write(code)
                F.flush()
        except Exception as e:
            print(e)
    print(f"导出完成：{save_path}")
    F.close()




class ExportFuncCode(plugin_t):
    flags = PLUGIN_PROC
    comment = "export_func_code"
    help = ""
    wanted_name = "zzExportFuncCode"
    wanted_hotkey = ""

    def init(self):
        print("export_func_code(v0.1) plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):
        # 查找需要的函数
        print("开始导出 text段 ==> ")
        ea, ed = getTextSegAddr()
        if(ed == ea):
            print("没有找到 text段")
        else:
            export(ea, ed)

        print("开始导出 所有段 ==> ")
        ea, ed = getAllAddr()
        if(ed == ea):
            print("所有段都没有！！！")
        else:
            export(ea, ed)

       
    def term(self):
        pass


def PLUGIN_ENTRY():
    return ExportFuncCode()
