
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





    //AntiJavaDebug.anti_debug();
    //AntiNativeDebug.anti_debug();


    let targetSoName = "libxloader.so";
    SOUtils.hook_dlopen(targetSoName, function () {
        AntiNativeDebug.hook_dlsym("pthread_create", function (funcPtr: any) {
            console.log("------------------------------------------------------------------")
            Interceptor.attach(funcPtr, {
                onEnter: function(args) {
                    Utils.print_native_callstacks(this.context)
                    console.log("thread_create enter")
                    let thread_func_ptr = args[3]
                    console.log("thread_func_ptr = " + thread_func_ptr)
                },
                onLeave: function(retval) {

                }
            });

        });
    }, function () {
        
    });



    // SOUtils.hook_linker_call_constructor(targetSoName, function() {

    //     //SOUtils.dump_so(targetSoName, "com.sznews")
    //     let targetModule = Process.findModuleByName(targetSoName);
    //     let base = targetModule.base;
    //     let end = base.add(targetModule.size);
    //     console.log(`${targetModule.name}  ==> (${base.toString(16)},  ${end.toString(16)})`)
    //     //AntiNativeDebug.anti_debug();


        

    //     AntiNativeDebug.hook_dlsym("pthread_create", function (funcPtr: any) {
    //         console.log("------------------------------------------------------------------")
    //         Interceptor.attach(funcPtr, {
    //             onEnter: function(args) {
    //                 console.log("thread_create enter")
    //                 let thread_func_ptr = args[3]
    //                 console.log("thread_func_ptr = " + thread_func_ptr)
    //             },
    //             onLeave: function(retval) {

    //             }
    //         });

    //     });


    //     //SOUtils.trace_instruction(targetSoName, 0x42B44, base.toUInt32(), end.toUInt32(), []);

    // });

    



    // AndUI.print_config = HookFuncHandler.FuncPrintType.func_callstacks;
    // AndUI.hook_ui();


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


    // AndEncrypt.print_config = HookFuncHandler.FuncPrintType.func_params
    // AndEncrypt.hook_encrypt()
    // ssl.anti_ssl_cronet_32()
    // ssl.droidSSLUnpinning()



    // r0tracer.configLite(true);
    // r0tracer.hookALL();

    
    // jtrace.configShowCacheLog(false)
    // jtrace.hook_all_jni()

    // //trace用法：
    // SOUtils.hook_dlopen("libencrypt.so", function () {
    //     //onEnter
    // }, function() {
    //     //onLeave
    //     fridaTrace.traceInsnAddr("libencrypt.so", 0x3D1A0)
    // });

}