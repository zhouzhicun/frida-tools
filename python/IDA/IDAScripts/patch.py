
import IDA.IDAPlugins.zzPluginBase.utils as utils


#修改下面参数，然后运行脚本即可
hex_string = "0000000000000000000000000000000000000000000000000000000000000000"
start_addr = 0x8410
segNameArr = [".text"]


utils.patch_bytes(start_addr, hex_string)
utils.reAnalyze(segNameArr)


