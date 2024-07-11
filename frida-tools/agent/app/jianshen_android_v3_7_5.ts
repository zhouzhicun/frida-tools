//App模板

import { AntiJavaDebug } from "../../android/AntiJavaDebug.js";
import { AntiNativeDebug } from "../../android/AntiNativeDebug.js";
import { AndEncrypt } from "../../android/AndEncrypt.js";
import { AndHttps } from "../../android/network/AndHttps.js";
import { AndSocket } from "../../android/network/AndSocket.js";
import { AndUI } from "../../android/utils/AndUI.js";
import { AndSo } from "../../android/utils/AndSo.js";
import { Base } from "../../base/zzBase.js";


//见圳v3.7.5:com.sznews; 应用宝下载
export function main() {

    let soName = "libxloader.so"
    AndSo.print_module_init_func(soName)


    // AndSo.hook_mod_init_func(soName, function (addr: NativePointer) {

    //     Thread.sleep(3000);

    // }, function(addr: NativePointer) {

    // })

}