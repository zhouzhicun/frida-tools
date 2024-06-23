
//App模板
import { Utils } from "../android/utils/utils.js";
import { UI } from "../android/ui.js";
import { Https } from "../android/https.js";
import { Socket } from "../android/socket.js";

import { AntiJavaDebug } from "../android/antiDebug/antiJavaDebug.js";
import { AntiNativeDebug } from "../android/antiDebug/antiNativeDebug.js";
import { FuncHandler } from "../android/utils/funcHandle.js";


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

    AntiJavaDebug.anti_debug();
    AntiNativeDebug.anti_debug();

    UI.print_config = FuncHandler.FuncPrintType.func_callstacks;
    UI.hook_ui();

}