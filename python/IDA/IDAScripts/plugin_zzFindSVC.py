




import idc
import ida_ida
import ida_nalt
import idaapi
import idautils
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK

import zzPluginBase.utils as utils

#
# 查找so库中的svc指令
#

svc_code = [
    "010000D4",     #svc 0
    "011000D4"      #svc 0x80
]

def searchSVC(segNames):
    matches = []
    if segNames is None or len(segNames) == 0:
        matches.extend(utils.binSearch(0, 0, svc_code[0]))
        matches.extend(utils.binSearch(0, 0, svc_code[1]))
    else:
        for segName in segNames:
            start, size = utils.getSegmentAddrRange(segName)
            end = start + size
            if end > 0:
                print("segName = " + segName + ", start = " + hex(start) + ", end = " + hex(end))
                matches.extend(utils.binSearch(start, end, svc_code[0]))
                matches.extend(utils.binSearch(start, end, svc_code[1]))
    return matches


def main():
    print("---------------------- Start find SVC --------------------")
    allMatches = searchSVC(None)
    textMatches = searchSVC(['.text'])
    str = ''
    for match in allMatches:
        str += hex(match) + ","
    print("All SVC at: " + str)  

    str = ''
    for match in textMatches:
        str += hex(match) + ","
    print(".text SVC at: " + str)  

    print("---------------------- end find SVC --------------------")

class zzFindSVC(plugin_t):
    flags = PLUGIN_PROC
    comment = "find svc"
    help = ""
    wanted_name = "zzFindSVC"
    wanted_hotkey = ""

    def init(self):
        print("zzFindSVC plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):
        main()

    def term(self):
        pass


def PLUGIN_ENTRY():
    return zzFindSVC()