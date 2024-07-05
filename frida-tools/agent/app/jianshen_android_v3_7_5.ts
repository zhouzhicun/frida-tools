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


 

    // //1.定位frida检测的so库
    // //SOUtils.hook_location_anti_frida()


    // let targetSoName = "libxloader.so";
    // SOUtils.hook_linker_call_constructor(targetSoName, function(){
    //     //AntiNativeDebug.anti_debug()
    //     hook_dlsym();
    //     bypass();
    // });



    // function bypass() {
    //     let base = Module.findBaseAddress(targetSoName);
    //     Utils.nop64(base.add(0x615A0), 1);
    //     Utils.nop64(base.add(0x6181C), 1);
      
        

    //     // Utils.patchFunc64(base.add(0x61A70));
    //     // Utils.patchFunc64(base.add(0x61284));
    // }


    // //定位检测线程
    // let hook_pthread_create = false
    // function hook_dlsym() {

    //     console.log("=== HOOKING dlsym ===")
    //     var interceptor = Interceptor.attach(Module.findExportByName(null, "dlsym"),
    //         {
    //             onEnter: function (args) {
                    
    //                 const name = args[1].readCString()
    //                 console.log("[dlsym] =>", name)
    //                 if (name == "pthread_create") {
    //                     this.frida = true
    //                 } else {
    //                     this.frida = false
    //                 }
    //             },
    //             onLeave: function(retval) {
    //                 console.log("addr: ", retval)
    //                 if(this.frida) {
    //                     if(!hook_pthread_create) {
    //                         hook_thread_create(retval)
    //                     }
    //                 }
    
    //             }
    //         }
    //     )
    //     return interceptor
    // }

    // function hook_thread_create(addr: any) {
    //     console.log(`thread_create_func_addr: ${addr}`)
    //     var interceptor = Interceptor.attach(addr, {
    //         onEnter: function (args) {
    //             var funcptr = args[2];
    //             var base = Process.findModuleByName("libxloader.so").base;
    //             console.log(`funcptr: ${funcptr}, base: ${base}, offset: ${funcptr.sub(base)}`)               
    //         }
    //     })
    //     return interceptor
    // }


}