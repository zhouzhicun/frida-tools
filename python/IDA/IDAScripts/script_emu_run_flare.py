

import zzPluginBase.flareEmuRun as flareEmuRun
import zzPluginBase.copyCode as copyCode


#模拟执行

start = 0x50a30
end = 0x50acc
regName = "X8"

result = flareEmuRun.emu_run_code(start, end, regName)
copyCode.patch_code(start, end, result)