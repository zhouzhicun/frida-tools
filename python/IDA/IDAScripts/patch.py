
import ida_auto
import ida_bytes
import idautils
import idaapi

'''
dump内存:
dump 可以使用 frida, dd命令(ADB)、IDA动态调试、GG 修改器、 GDB/LLDB 等等。
如果不存在 Anti Frida，那么 Frida dump就是最方便的选择。

回填使用 IDA 脚本更不是唯一选择，只需要使得 dump 下来的内容覆盖原先 data 段的物理地址范围就行。
需要注意区分物理偏移和虚拟地址，IDA 解析和展示 SO 时，采用虚拟地址（address），而处理静态文件时，需要基于实际偏移 offset 。
以 data segment 的起始地址为例，其虚拟地址和实际物理偏移并不一定相同。
1.IDA 中 patch 遵照其虚拟地址即可，因为 IDA 会替我们处理，映射到合适的物理地址上，
2.而将 SO 作为二进制文件 patch 时，需要用实际物理地址。可以使用 readelf 查看详细的节信息。


字符串加密解密：
OLLVM 的变种 Armariris 和 hikari 都是在字符串使用的时候才解密。
并且字符串解密函数作为内联函数，更有利于代码保护；否则的话，通过hook解密函数，就可以定位到检测点。

'''

####################################### helper  ################################################

# #patch操作
# def patch_bytes(start_addr, hex_string):
#     byteArr = bytes.fromhex(hex_string)
#     idaapi.patch_bytes(start_addr, byteArr)

# def reAnalyze(segNameArr):
#     for i in idautils.Segments():
#         seg = idaapi.getseg(i)
#         segName = idaapi.get_segm_name(seg)

#         #判断段名是否在segNameArr中，是的话先删除该段的分析，然后重新分析；
#         if segName in segNameArr:
#             startAddress = seg.start_ea
#             endAddress = seg.end_ea
#             ida_bytes.del_items(startAddress, 0, endAddress)
#             ida_auto.plan_and_wait(startAddress, endAddress)


####################################### 业务逻辑  ################################################


from base import patch_bytes, reAnalyze


#修改下面参数，然后运行脚本即可
hex_string = "0000000000000000000000000000000000000000000000000000000000000000"
# hex_string = "1111111111111111111111111111111111111111111111111111111111111111"
start_addr = 0x8410
segNameArr = [".text"]

patch_bytes(start_addr, hex_string)
reAnalyze(segNameArr)





