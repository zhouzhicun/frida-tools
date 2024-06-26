
import { Utils } from "../../base/Utils.js";

export namespace SOUtils {

    /************************************** helper **************************************************** */

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

    export function get_dump_root_path(bundleName: string) {
        return "/data/data/" + bundleName + "/"
    }




    /************************************** dump操作 **************************************************** */

    //dump指定so的导出符号列表, 并保存到/data/data/bundleName/目录下
    export function dump_so_export_symbols(soName: string, bundleName: string) {

        var targetModule = Process.findModuleByName(soName);
        var exportSymbols = targetModule.enumerateExports();

        var savePath = get_dump_root_path(bundleName)
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


    //dump 指定so库, 并保存到/data/data/bundleName/目录下
    export function dump_so(soName: string, bundleName: string) {

        var targetModule = Process.getModuleByName(soName);
        var savePath = get_dump_root_path(bundleName)
        var dump_file_path = savePath + soName.replace(".so", "") + targetModule.base + "_" + targetModule.base.add(targetModule.size) + ".bin";

        //写文件
        var success = dump_to_file(dump_file_path, targetModule.base, targetModule.size);
        if (success) {
            console.log("[dump so]:", dump_file_path);
        }
    }


    export function dump_memory(soName: string, offset: number, length: number, bundleName: string) {

        var base_addr = Module.findBaseAddress(soName);
        var dump_start_addr = base_addr.add(offset);
        console.log(hexdump(dump_start_addr, { length: length }));

        var savePath = get_dump_root_path(bundleName)
        var dump_file_path = savePath + dump_start_addr + "_" + dump_start_addr.add(length) + ".bin";

        //写文件
        var success = dump_to_file(dump_file_path, dump_start_addr, length);
        if (success) {
            console.log("[dump memory]:", dump_file_path);
        }
    }

    function dump_to_file(dump_file_path: string, base: NativePointer, size: number): boolean {

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
     * 定位frida防护的so库, 
     */
    export function hook_location_anti_frida() {

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


    /******************************************* watch ***************************************************** */

    /**
     * 从内存中搜索特征数据, 例如：
     * arm64 svc 0 : 010000D4
     * arm64 svc 0x80: 011000D4
     * ssl_cronet(libsscronet.so): 参考 FridaContainer的 Anti.ts文件。
     * 01 06 44 BF 6F F0 CE 00 70 47 81 04 44 BF 6F F0 95 00 70 47 41 01 44 BF 6F F0 D8 00 70 47 41 06 44 BF 6F F0 CD 00 70 47 41 07 44 BF 6F F0 C9 00 70 47 C1 07 1C BF 6F F0 C7 00 70 47 C1 01 44 BF
    */
    export function search_memory(soName: string, hexStr: string) {

        // 获取模块基址和大小
        var module = Process.getModuleByName(soName);
        var base = module.base;
        var size = module.size;

        var matchedArr: NativePointer[]

        // 在模块地址范围内搜索特征数据
        var matches = Memory.scan(base, size, hexStr, {
            onMatch: function (address, size) {
                var offset = address.sub(base);
                matchedArr.push(offset)
            },
        });

        return matchedArr
    }

    



    /**
     * 对对应的偏移地址下断点，并打印其堆栈。
     * 用途：比如通过IDA搜索 svc 0的机器码得到其指令的偏移地址，然后通过frida hook它，并打印堆栈。
     * 
     * @param soName so名称
     * @param points 待观察的指令偏移地址数组
     * 
     */
    export function watch_points(soName: string, points: number[]) {

        var base_addr = Module.findBaseAddress(soName);
        points.forEach((addr) => {
            Interceptor.attach(base_addr.add(addr), {
                onEnter: function () {
                    Utils.print_native_callstacks(this.context);
                }
            });
        })

    }


    /******************************************* Stalker trace ***************************************************** */

    /**
     * stalker trace 指定指令，并在命中观察点的时候打印context信息。
     * 
     * @param soName so的名字
     * @param hook_addr hook的偏移地址，先进行Hook，在Hook的回调中再stalker
     * @param start_offset stalker的起始地址
     * @param end_offset   stalker的结束地址
     * @param watch_points 观察点：一组偏移地址
     */
    export function trace_instruction(soName: string, hook_addr: number, start_offset: number, end_offset: number, watch_points: number[]) {

        var base_addr = Module.findBaseAddress(soName);

        Interceptor.attach(base_addr.add(hook_addr), {
            onLeave: function (retval) {
                Stalker.unfollow(this.pid)
                console.log("stalker follow stop ==>")
            },
            onEnter: function (args) {

                console.log("stalker follow start ==>")
                this.pid = Process.getCurrentThreadId();
                Stalker.follow(this.pid, {
                    events: {
                        call: false,    // CALL instructions: yes please            
                        ret: false,     // RET instructions
                        exec: false,    // all instructions: not recommended as it's
                        block: false,   // block executed: coarse execution trace
                        compile: false  // block compiled: useful for coverage
                    },

                    // onReceive: Called with `events` containing a binary blob comprised of one or more GumEvent structs. 
                    // See `gumevent.h` for details about the format. Use `Stalker.parse()` to examine the data.
                    onReceive(events) {

                    },

                    transform: function (iterator: any) {

                        //iterator 对应一个基本块。基本块是一组连续的指令，没有分支。
                        var instruction = iterator.next();

                        //判断当前指令是不是原函数内的指令
                        const inst_addr = instruction.address;
                        var isModule = inst_addr.compare(base_addr.add(start_offset)) >= 0 && inst_addr.compare(base_addr.add(end_offset)) < 0;

                        //遍历执行该基本块的所有指令
                        do {
                            if (isModule) {

                                var inst_offset_addr = instruction.address.sub(base_addr)
                                console.log(inst_offset_addr + "\t:\t" + instruction);

                                if (watch_points.includes(inst_offset_addr)) {

                                    //命中时，打印上下文信息
                                    console.log("hit watch_point = " + inst_offset_addr);
                                    iterator.putCallout((context: any) => {
                                        var contextStr = JSON.stringify(context)
                                        console.log("context = \n" + contextStr);
                                    });

                                }

                            }
                            iterator.keep();
                        } while ((instruction = iterator.next()) !== null);

                    }
                });

            }
        })
    }

}



