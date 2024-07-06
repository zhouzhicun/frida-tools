

import { anti_jd_frida } from "../../android/antiFrida/other/anti_jd_frida.js";
import { AntiNativeDebug } from "../../android/AntiNativeDebug.js";
import { AndSo } from "../../android/utils/AndSo.js";
import { AndUI } from "../../android/utils/AndUI.js";
import { Base } from "../../base/zzBase.js";


/**
 * gh
 */
export function main() {


    //AndSo.location_anti_frida()


    //hook Runtime.getRuntime().exec("su") 函数


    // // 使用Frida hook Runtime.getRuntime().exec("su") 函数
    // Java.perform(function () {
    //     var runtime = Java.use('java.lang.Runtime');
    //     runtime.exec.overload('java.lang.String').implementation = function (command: string) {
    //         console.log(`------------------Runtime.exec(${command})-------------------------`);
    //         if (command.includes("su")) {
    //             console.log("Detected 'su' command execution");
    //             // 在这里执行你的操作
    //             return Java.use('java.lang.Process').$new()
    //         }
    //         return this.exec(command);
    //     };
    // });


    let targetSoName = 'libtongdun.so'
    let bundleName = "com.icbc"
    AndSo.hook_linker_call_constructor(targetSoName, function () {

        anti_exit()
        anti_kill()
        // Base.zzPatch.nopFunc64_by_offset(targetSoName, 0xD92A8)

        // let base = Module.findBaseAddress(targetSoName)
        // Interceptor.attach(base.add(0x106C4), {
        //     onEnter: function(){
        //         Base.zzPatch.patchCode64_with_codeHex(base.add(0x106C8), 'fc6fc6a8c0035fd6') 
        //     }
        // })

        // Interceptor.attach(base.add(0x2CDA0), {
        //     onEnter: function(){
        //         Base.zzPatch.patchCode64_with_codeHex(base.add(0x2CDA4), 'ff430191c0035fd6') 
        //     }
        // })

        // Interceptor.attach(base.add(0x343C8), {
        //     onEnter: function(){
        //         Base.zzPatch.patchCode64_with_codeHex(base.add(0x343CC), 'fc6fc6a8c0035fd6') 
        //     }
        // })


        // Interceptor.attach(base.add(0x38E98), {
        //     onEnter: function(){
        //         Base.zzPatch.patchCode64_with_codeHex(base.add(0x38E9C), 'fc6fc6a8c0035fd6') 
        //     }
        // })


        // Interceptor.attach(base.add(0x39434), {
        //     onEnter: function(){
        //         Base.zzPatch.patchCode64_with_codeHex(base.add(0x39438), 'fc6fc6a8c0035fd6') 
        //     }
        // })
  
    })


    var dumpresult = false
    function anti_exit() {

        //void _exit(int status);
        // Base.zzNativeFunc.replaceFunc('_exit', new NativeCallback(function () {
        //     console.log("------------------ _exit dump ---------------------------------")
        //     // if(dumpresult == false) {
        //     //     AndSo.dump_so(targetSoName, bundleName)
        //     //     AndSo.dump_so_export_symbols("libc.so", bundleName)
        //     //     dumpresult = true
        //     // }

        //     Base.zzCallStack.printNativeCallstacksV2(this.context)
      
            
        // }, 'void', ['int']));

        // //void _Exit(int status);
        // Base.zzNativeFunc.replaceFunc('_Exit', new NativeCallback(function () {
        //     print_callstacks('_Exit', this.context);
        // }, 'void', ['int']));

        //void exit(int status);
        Base.zzNativeFunc.replaceFunc('exit', new NativeCallback(function () {
            console.log("------------------ exit dump ---------------------------------")
            //AndSo.dump_so(targetSoName, bundleName)
            Base.zzCallStack.printNativeCallstacksV2(this.context)
        }, 'void', ['int']));

        // //void exit_group(int status);
        // Base.zzNativeFunc.replaceFunc('exit_group', new NativeCallback(function () {
        //     console.log("------------------ exit_group dump ---------------------------------")
        //     AndSo.dump_so(targetSoName, bundleName)
        // }, 'void', ['int']));

    }

    function anti_kill() {

        //int kill(pid_t pid, int sig);
        Base.zzNativeFunc.replaceFunc('kill', new NativeCallback(function () {
            console.log("------------------ kill dump ---------------------------------")
            //AndSo.dump_so(targetSoName, bundleName)
            Base.zzCallStack.printNativeCallstacksV2(this.context)
            return 0;
        }, 'int', ['int', 'int']));
    }






    //通过hook strstr函数获取frida检测的堆栈，并进一步分析，从而获得检测函数地址
    function hook_strstr() {
        var pt_strstr = Module.findExportByName("libc.so", 'strstr');
        Interceptor.attach(pt_strstr, {
            onEnter: function (args) {
                var str1 = args[0].readCString();
                var str2 = args[1].readCString();
                console.log("strstr-->", str1, str2);
                console.log('strstr called from:\\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
                // console.log('strstr called from:\\n' + Thread.backtrace(this.context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join('\\n') + '\\n');
            }
        });

    }


}

