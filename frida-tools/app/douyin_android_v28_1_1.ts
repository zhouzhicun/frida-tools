
//App模板

import { AndUI } from "../android/utils/AndUI.js";
import { HookFuncHandler } from "../base/HookFuncHandler.js";

// import { AntiJavaDebug } from "../android/antiDebug/AntiJavaDebug";
// import { AntiNativeDebug } from "../android/antiDebug/AntiNativeDebug";
// import { SOUtils } from "../android/native/SoUtils";
// import { AndHttps } from "../android/network/AndHttps";
// import { AndSocket } from "../android/network/AndSocket";




export function main() {

    // // App名称
    // let app_name = "抖音";
    // // App包名
    // let app_package = "com.ss.android.ugc.aweme";
    // // App版本
    // let app_version = "v28.1.1";
    // // App版本号
    // let app_version_code = "280101";
    // // App作者
    // let app_author = "Frida-Tools";
    // // App邮箱
    // let app_email = ""

    // AntiJavaDebug.anti_debug();
    // AntiNativeDebug.anti_debug();
    // UI.print_config = FuncHandler.FuncPrintType.func_callstacks;
    // UI.hook_ui();





    AndUI.print_config = HookFuncHandler.FuncPrintType.func_callstacks
    AndUI.hook_ui()

    // AntiJavaDebug.anti_debug()
    // AntiNativeDebug.anti_debug()

    // AndHttps.print_config = HookFuncHandler.FuncPrintType.func_callstacks
    // AndHttps.hook_https()

    // AndSocket.print_config = HookFuncHandler.FuncPrintType.func_callstacks
    // AndSocket.hook_socket()

    

    
    // SOUtils.hook_location_anti_frida()

    // SOUtils.hook_dlopen("libnesec.so", function () {
    //     console.log("libnesec.so dlopen enter")
    // }, function() {
    //     console.log("libnesec.so dlopen leave")
    //     SOUtils.dump_so_export_symbols("libnesec.so", "com.netease.cloudmusic");
    // });

    // SOUtils.hook_linker_call_constructor("libnesec.so", function() {
    //     console.log("libnesec.so linker::CallConstructors enter")
    // });


}