

import zzPluginBase.keycap as keycap




def demo_generate_asm():
    #hexstr = "FF77F6F1"
    #hexstr = "F1F677FF"
    hexstr = "77DF8B85"
    addr = 0x1000
    print("-------------------")
    for i in keycap.generate_asm(hexstr, addr):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


demo_generate_asm()