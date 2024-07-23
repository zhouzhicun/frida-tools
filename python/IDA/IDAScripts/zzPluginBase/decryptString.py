

import ida_bytes
import ida_idaapi
import idaapi
import idautils
import idc
import re

import zzPluginBase.utils as utils


################################### Hikari混淆字符串解密 ##########################################

class HikariHandler:

    #reset段
    @classmethod
    def resetDataSection(self):
        start = 0
        end = 0
        for seg in idautils.Segments():
            name = idc.get_segm_name(seg)
            if name == ".data":
                start = idc.get_segm_start(seg)
                end = idc.get_segm_end(seg)
        for address in range(start, end):
            #找到 data 段，将其中所有数据先 del_items转成 undefined，再 create_data转成 byte_xxx。
            ida_bytes.del_items(address, 0, 1)
            ida_bytes.create_data(address, 0, 1, ida_idaapi.BADADDR)


    #匹配并patch模式1：byte_xxx ^= AAAu 
    @classmethod
    def patchMode1(self, codes):
        matches = re.findall(r"byte_([0-9a-fA-F]+) \^= (.*)u", codes)
        if len(matches) > 0:
            for match in matches:
                address = int(match[0], 16)
                xorValue = int(match[1], 16)
                decrypt_c = xorValue ^ idaapi.get_byte(address)
                ida_bytes.patch_byte(address, decrypt_c)


    #匹配并patch模式2：byte_xxx = ~byte_xxx
    @classmethod
    def patchMode2(self, codes):
        matches = re.findall(r"byte_([0-9a-fA-F]+) = ~byte_\1", codes)
        if len(matches) > 0:
            for match in matches:
                address = int(match, 16)
                xorValue = 0xFF
                decrypt_c = xorValue ^ idaapi.get_byte(address)
                ida_bytes.patch_byte(address, decrypt_c)

    @classmethod    
    def decryptOneFunc(self, func):
        decompilerStr = str(idaapi.decompile(func))
        HikariHandler.patchMode1(decompilerStr)
        HikariHandler.patchMode2(decompilerStr)

    @classmethod
    def decryptString(self):
        print("------------------- decrypt string  start ----------------------------")
        HikariHandler.resetDataSection()
        for func in idautils.Functions(0, ida_idaapi.BADADDR):
            HikariHandler.decryptOneFunc(func)
        utils.reAnalyze(["text", "data"])
        print("------------------- decrypt string  end ----------------------------")




################################### Armariris混淆字符串解密  #######################################

#只需在 init_array 运行结束后的任意时机做 dump，字符串全部处于解密状态。





