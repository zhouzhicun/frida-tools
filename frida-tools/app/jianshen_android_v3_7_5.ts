


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
    let app_name = "见圳";
    // App包名
    let app_package = "com.sznews";
    // App版本
    let app_version = "v3.7.5";


    let targetSoName = "libxloader.so";
    // SOUtils.hook_dlopen(targetSoName, function () {

    //     AntiNativeDebug.hook_dlsym("pthread_create", function (funcPtr: any) {
    //         console.log("------------------------------------------------------------------")
    //         Interceptor.attach(funcPtr, {
    //             onEnter: function(args) {
    //                 console.log("---------------------------------2222---------------------------------")
    //                 //Utils.print_native_callstacks(this.context)
    //                 console.log("thread_create enter")
    //                 let thread_func_ptr = args[3]
    //                 console.log("thread_func_ptr = " + thread_func_ptr)
    //             },
    //             onLeave: function(retval) {
    //                 console.log("----------------------------------3333--------------------------------")
    //             }
    //         });

    //     });
    // }, function () {
        
    // });



    let debug = true
    if(debug) {

        SOUtils.hook_dlopen(targetSoName, function() {
            AntiNativeDebug.anti_debug()
            hook_dlsym();
        }, function() {
    
        });

        SOUtils.hook_linker_call_constructor(targetSoName, function(){
            //bypass();
        });


    } else {

        SOUtils.hook_linker_call_constructor(targetSoName, function(){
            bypass();
        });
    
    }



    function bypass() {
        let base = Module.findBaseAddress(targetSoName);
        // Utils.patchFunc64(base.add(0x61A70));
        // Utils.patchFunc64(base.add(0x61284));

        Utils.nop64_batch([base.add(0x61530), base.add(0x613A8), base.add(0x615A0), base.add(0x6181C)]);

    }


    function hook_dlsym() {

        console.log("=== HOOKING dlsym ===")
        var interceptor = Interceptor.attach(Module.findExportByName(null, "dlsym"),
            {
                onEnter: function (args) {
                    
                    const name = args[1].readCString()
                    console.log("[dlsym] =>", name)
                    if (name == "pthread_create") {
                        this.frida = true
                    } else {
                        this.frida = false
                    }
                },
                onLeave: function(retval) {
                    console.log("addr: ", retval)
                    if(this.frida) {
                        hook_thread_create(retval)
                    }
    
                }
            }
        )
        return interceptor
    }

    function hook_thread_create(addr: any) {
        console.log(`thread_create_func_addr: ${addr}`)
        var interceptor = Interceptor.attach(addr, {
            onEnter: function (args) {
                var funcptr = args[2];
                var base = Process.findModuleByName("libxloader.so").base;
                console.log(`funcptr: ${funcptr}, base: ${base}, offset: ${funcptr.sub(base)}`)
                //printNativeStack(this.context, true);
                //nop64(funcptr)
               
            }
        })
        return interceptor
    }


}