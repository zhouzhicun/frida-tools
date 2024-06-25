
import ida_auto
import ida_bytes
import idautils
import idaapi


#patch操作
def patch_bytes(start_addr, hex_string):
    byteArr = bytes.fromhex(hex_string)
    idaapi.patch_bytes(start_addr, byteArr)

def reAnalyze(segNameArr):
    for i in idautils.Segments():
        seg = idaapi.getseg(i)
        segName = idaapi.get_segm_name(seg)

        #判断段名是否在segNameArr中，是的话先删除该段的分析，然后重新分析；
        if segName in segNameArr:
            startAddress = seg.start_ea
            endAddress = seg.end_ea
            ida_bytes.del_items(startAddress, 0, endAddress)
            ida_auto.plan_and_wait(startAddress, endAddress)



