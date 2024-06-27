
import idautils
import idaapi
import idc
import ida_nalt
import ida_entry

from operator import itemgetter



#获取函数列表，按照xref数量排序
def get_func_list_orderby_xref():
    functionList = []
    for func in idautils.Functions():
        xrefs = idautils.CodeRefsTo(func, 0)
        xrefCount = len(list(xrefs))
        oneFuncDict = {"funcName":idc.get_func_name(func), "Address": hex(func), "xrefCount": xrefCount}
        functionList.append(oneFuncDict)

    function_list_by_countNum = sorted(functionList, key=itemgetter('xrefCount'),reverse=True)
    for func in function_list_by_countNum[:20]:
        print(func)

#获取函数列表，按照指令数量排序
def get_func_list_orderby_insn_count():
    functionList = []
    for func in idautils.Functions():
        insnCount = idc.get_func_attr(func, idc.FUNCATTR_END) - idc.get_func_attr(func, idc.FUNCATTR_START)
        oneFuncDict = {"funcName":idc.get_func_name(func), "Address": hex(func), "insnCount": insnCount}
        functionList.append(oneFuncDict)

    function_list_by_countNum = sorted(functionList, key=itemgetter('insnCount'),reverse=True)
    for func in function_list_by_countNum[:20]:
        print(func)


#获取函数列表，按照加解密特征指令数量排序(LSL, AND, ORR, LSR, ROR)
def get_func_list_orderby_eor():
    functionList = []
    for addr in list(idautils.Functions()):
        funcName = idc.get_func_name(addr)
        func = idaapi.get_func(addr)
        length = func.size()
        dism_addr = list(idautils.FuncItems(addr))
        count = 0
        if length > 0x10:
            for line in dism_addr:
                m = idc.print_insn_mnem(line)
                if m.startswith("LSL") | m.startswith("AND") | m.startswith("ORR") | m.startswith("LSR") | m.startswith("ROR"):
                    count += 1

            oneFuncDict = {"funcName": funcName, "Address": hex(addr), "rate": count / length}
            functionList.append(oneFuncDict)

    function_list_by_countNum = sorted(functionList, key=itemgetter('rate'), reverse=True)
    for func in function_list_by_countNum[:20]:
        print(func)


#获取导出函数列表
def get_export_func_list():

    exports = []
    
    # 获取当前二进制文件的导入函数数量
    n = ida_entry.get_entry_qty()
    
    # 遍历每一个导入函数
    for i in range(0, n):
        # 获取第 i 个导入函数的序号
        ordinal = ida_entry.get_entry_ordinal(i)
        
        # 使用序号获取导入函数的地址
        ea = ida_entry.get_entry(ordinal)
        
        # 使用序号获取导入函数的名称
        name = ida_entry.get_entry_name(ordinal)
        
        # 将导入函数的名称和地址作为一个字典添加到列表中
        exports.append({"funcName": name, "addr": ea})
    
    # 打印所有导入函数的信息
    print("===============导出函数列表===================")
    print(exports)
    return exports


#获取导入函数列表
def get_import_func_list():
    def imp_cb(ea, name, ord):
        if not name:
            name = ''
        imports.append({"funcName": name, "addr": ea})
        return True

    imports = []
    nimps = ida_nalt.get_import_module_qty()
    for i in range(0, nimps):
        ida_nalt.enum_import_names(i, imp_cb)

    print("===============导入函数列表===================")
    print(imports)
    return imports

