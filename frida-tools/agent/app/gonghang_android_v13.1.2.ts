

import { anti_jd_frida } from "../../android/antiFrida/other/anti_jd_frida.js";
import { AntiNativeDebug } from "../../android/AntiNativeDebug.js";
import { AndSo } from "../../android/utils/AndSo.js";
import { AndUI } from "../../android/utils/AndUI.js";
import { Base } from "../../base/zzBase.js";


/**
 * gonghang
 */
export function main() {

    let targetSoName = 'libtongdun.so'
    let bundleName = "com.icbc"

    AndSo.print_module_init_func(targetSoName)


}

