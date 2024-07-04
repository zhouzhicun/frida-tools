



//App模板

import { AntiJavaDebug } from "../android/antiDebug/AntiJavaDebug.js";
import { AntiNativeDebug } from "../android/antiDebug/AntiNativeDebug.js";
import { AndEncrypt } from "../android/encrypt/AndEncrypt.js";
import { SOUtils } from "../android/native/SoUtils.js";
import { AndHttps } from "../android/network/AndHttps.js";
import { AndSocket } from "../android/network/AndSocket.js";
import { AndUI } from "../android/utils/AndUI.js";
import { HookFuncHandler } from "../base/HookFuncHandler.js";
import { Utils } from "../base/Utils.js";

import * as ssl from "../android/network/AndSSLUnpinning.js"
import * as fridaTrace from "../base/FridaTrace.js"
import * as r0tracer from "../base/r0tracer.js"
import * as jtrace from "../android/jtrace/jtrace.js"




export function main() {


    // App名称
    let app_name = "多点";
    // App包名
    let app_package = "com.wm.dmall";
    // App版本
    let app_version = "v6.2.1";

    //1.定位frida检测的so库
    //SOUtils.hook_location_anti_frida()


    let targetSoName = "libshell-super.com.wm.dmall.so";
    let svc_addrs = [0x4826c,0x487bc,0x48dc4,0x496d4,0x49880,0x499d0,0x4b200,0x4bf40,0x51578,0x51598,0x516fc,0x51984,0x519bc,0x51a34,0x51b24,0x51b9c,0x51e98]

    SOUtils.hook_linker_call_constructor(targetSoName, function(){
        SOUtils.print_soinfo(targetSoName)

        //1.定位检测位置
        //SOUtils.watch_svc_points(targetSoName, svc_addrs);

        //2.Patch sub_515C4调用
        let base = Module.findBaseAddress(targetSoName)
        Utils.patchCode64_v2(base.add(0x5157C), "000080D2")

    });

    AndUI.hook_ui()

}