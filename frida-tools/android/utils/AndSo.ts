

import { Base } from "../../base/zzBase.js";

export namespace AndSo {

    /************************************** helper **************************************************** */

    export function print_soinfo(soName: string) {
        var targetModule = Process.findModuleByName(soName);
        console.log("get_soinfo ==>" + soName + " base = " + targetModule.base + "size = " + targetModule.size)
    }

    //获取真实地址
    export function get_addr(soName: string, offset: number) {
        const base = Module.findBaseAddress(soName);
        return base.add(offset);
    }

    //获取jstring
    export function get_jstring(jstrAddr: NativePointer) {
        var jStrCls = Java.use('java.lang.String');
        var str = Java.cast(jstrAddr, jStrCls);
        return str
    }

    /************************************** dump操作 **************************************************** */

    export function dump_root_path(bundleName: string) {
        return "/data/data/" + bundleName + "/"
    }

    //dump 指定so库, 并保存到/data/data/bundleName/目录下
    export function dump_so(soName: string, bundleName: string) {

        var targetModule = Process.getModuleByName(soName);
        var savePath = dump_root_path(bundleName)
        var dump_file_path = savePath + soName.replace(".so", "") + targetModule.base + "_" + targetModule.base.add(targetModule.size) + ".bin";

        //写文件
        var success = write_dump_to_file(dump_file_path, targetModule.base, targetModule.size);
        if (success) {
            console.log("[dump so]:", dump_file_path);
        }
    }


    //dump指定so的导出符号列表, 并保存到/data/data/bundleName/目录下
    export function dump_so_export_symbols(soName: string, bundleName: string) {

        var targetModule = Process.findModuleByName(soName);
        var exportSymbols = targetModule.enumerateExports();


        //写文件
        var savePath = dump_root_path(bundleName)
        var dump_file_path = savePath + soName.replace(".so", "") + "_symbols.log";
        console.log("dump_file_path = ", dump_file_path);

        var file_handle = new File(dump_file_path, "a+");
        for (var i = 0; i < exportSymbols.length; i++) {
            file_handle.write(exportSymbols[i].name + ": " + (exportSymbols[i].address) + "\n");
        }

        file_handle.flush();
        file_handle.close();
        console.log("[dump symbols]:", dump_file_path);

    }

    export function dump_memory(soName: string, offset: number, length: number, bundleName: string) {

        var base_addr = Module.findBaseAddress(soName);
        var dump_start_addr = base_addr.add(offset);
        console.log(hexdump(dump_start_addr, { length: length }));


        //写文件
        var savePath = dump_root_path(bundleName)
        var dump_file_path = savePath + dump_start_addr + "_" + dump_start_addr.add(length) + ".bin";

        var success = write_dump_to_file(dump_file_path, dump_start_addr, length);
        if (success) {
            console.log("[dump memory]:", dump_file_path);
        }
    }

    function write_dump_to_file(dump_file_path: string, base: NativePointer, size: number): boolean {

        var file_handle = new File(dump_file_path, "wb");
        if (file_handle && file_handle != null) {
            Memory.protect(base, size, 'rwx');
            var libso_buffer = base.readByteArray(size);
            file_handle.write(libso_buffer);
            file_handle.flush();
            file_handle.close();
            return true;
        }
        return false;

    }

    /************************************************************************************** */

    /**
     * 定位frida防护的so库
     */
    export function location_anti_frida() {

        let android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
        if (android_dlopen_ext != null) {
            Interceptor.attach(android_dlopen_ext, {
                onEnter: function (args) {

                    let so_name = args[0].readCString();
                    console.log("[LOAD] ==> " + so_name);

                }, onLeave: function (retval) {
                    Thread.sleep(3)
                }
            });
        }
    }



    /**
     * hook dlopen函数，可用于定位指定so的加载时机
     * 
     * @param soName so的名字
     * @param enterFunc enter的回调函数, 无入参
     * @param leaveFunc leave的回调函数，无入参
     */
    export function hook_dlopen(soName: string, enterFunc: any, leaveFunc: any) {

        let android_dlopen_ext = Module.findExportByName(null, "android_dlopen_ext");
        if (android_dlopen_ext != null) {
            Interceptor.attach(android_dlopen_ext, {
                onEnter: function (args) {

                    let so_name = args[0].readCString();
                    console.log("[LOAD] ==> " + so_name);

                    if (so_name.indexOf(soName) !== -1) {
                        this.hook = true;
                        enterFunc();   //进入指定so时，回调enterFunc()
                    }
                }, onLeave: function (retval) {
                    if (this.hook) {
                        this.hook = false;
                        leaveFunc();  //离开指定so时，回调leaveFunc()
                    }
                }
            });
        }
    }


    /**
     * hook linker::CallConstructors函数，可用于定位so的初始化时机，比如hook so的 init函数.
     * 例如：打印init_array的所有函数地址：https://blog.seeflower.dev/archives/299/
     * 
     * @param soName so的名字
     * @param initFunc 初始化函数，无入参
     */
    export function hook_linker_call_constructor(soName: string, initFunc: any) {

        //1.找到 Linker::CallConstructors 函数

        let already_hook = false;

        let get_soname: any = null;
        let call_constructor_addr = null;

        let linker = null;
        if (Process.pointerSize == 4) {
            linker = Process.findModuleByName("linker");
        } else {
            linker = Process.findModuleByName("linker64");
        }

        //遍历符号列表
        let symbols = linker.enumerateSymbols();
        for (let i = 0; i < symbols.length; i++) {
            let symbol = symbols[i];
            if (symbol.name.indexOf("call_constructor") !== -1) {    //或者：(symbol.name == "__dl__ZN6soinfo17call_constructorsEv")
                call_constructor_addr = symbol.address;
            } else if (symbol.name.indexOf("get_soname") !== -1) {   //或者：(symbol.name == "__dl__ZNK6soinfo10get_sonameEv")
                get_soname = new NativeFunction(symbol.address, "pointer", ["pointer"]);
            }
        }

        //2. hook Linker::CallConstructors 函数
        if (call_constructor_addr != null) {
            console.log(`get construct address ${call_constructor_addr}`);
            Interceptor.attach(call_constructor_addr, {
                onEnter: function (args) {

                    let soinfo = args[0];

                    //打印当前INIT的so的名字
                    if (soinfo != null && get_soname != null) {
                        let soname = get_soname(soinfo).readCString();
                        console.log(`[INIT] ==> ${soname}`);
                    }

                    if (already_hook === false) {
                        const targetModule = Process.findModuleByName(soName);
                        if (targetModule !== null) {
                            already_hook = true;
                            initFunc();
                        }
                    }
                }
            });
        }
    }



}



