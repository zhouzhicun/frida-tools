import { StringUtils } from "./StringUtils.js";


export namespace Utils {


    /************************* java ******************************** */

    //获取java对象的类名
    export function get_class_name(object: any) {
        if (object !== null) {
            return object.getClass().getName();
        } else {
            return null;
        }
    }

    /************************* 常规函数 ******************************** */

    //java打印堆栈
    export function print_java_callstacks() {
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    }

    //打印native堆栈
    export function print_native_callstacks(context: any) {
        console.log(' called from:\n' + Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
    }

    //打印分割线
    export function print_divider(tips: string = '') {
        console.log(`==============================${tips}==============================`)
    }

    //打印参数
    export function print_arguments() {
        console.log('arguments: ', ...arguments)
    }




    /**
     * 打印指定层数的栈信息（8字节为一层），并输出 module 信息 (如果有）
     * @param {CpuContext} context
     * @param {number} number
     */
    export function showStacksModInfo(context: CpuContext, number: number) {
        var sp: NativePointer = context.sp;

        for (var i = 0; i < number; i++) {
            var curSp = sp.add(Process.pointerSize * i);
            console.log('showStacksModInfo curSp: ' + curSp + ', val: ' + curSp.readPointer()
                + ', module: ' + getModuleByAddr(curSp.readPointer()));
        }
    }

      /**
     * 根据地址获取模块信息
     * @param {NativePointer} addr
     * @returns {string}
     */
      export function getModuleByAddr(addr: NativePointer): Module | null {
        var result = null;
        Process.enumerateModules().forEach(function (module: Module) {
            if (module.base <= addr && addr <= (module.base.add(module.size))) {
                result = JSON.stringify(module);
                return false; // 跳出循环
            }
        });
        return result;
    }
    


    /**
     * 获取 LR 寄存器值
     * @param {CpuContext} context
     * @returns {NativePointer}
     */
    export function getLR(context: CpuContext) {
        if (Process.arch == 'arm') {
            return (context as ArmCpuContext).lr;
        }
        else if (Process.arch == 'arm64') {
            return (context as Arm64CpuContext).lr;
        }
        else {
            console.log('not support current arch: ' + Process.arch);
        }
        return ptr(0);
    }


    /************************* 内存读写 ******************************** */

    export function readMemory(startAddr: any, size: any) {
        Memory.protect(startAddr, size, 'rwx');
        var buffer = startAddr.readByteArray(size);
        return buffer
    }

    export function writeMemory(startAddr: any, str: any) {
        Memory.protect(startAddr, str.length, 'rwx');
        startAddr.writeAnsiString(str);
    }


 /*********************************** 函数处理 ******************************************** */
    
    export function getFuncPtr(funcName: string) {
        const funcPtr = Module.findExportByName(null, funcName);
        console.log("getFuncPtr ==>" + funcName + " : " + funcPtr);
        return funcPtr;
    }

    export function replaceFunc(funcName: string, callBack: NativePointerValue) {
        let funcPtr = getFuncPtr(funcName);
        if(funcPtr){
            Interceptor.replace(funcPtr, callBack);
        }
    }


    //创建一个假的函数, 该函数直接返回
    export function create_fake_func() {
        const fake_func = Memory.alloc(4096)
        Memory.protect(fake_func, 4096, "rwx")
        Memory.patchCode(fake_func, 4096, code => {
            const cw = new Arm64Writer(code, { pc: fake_func })
            cw.putRet()
            cw.flush()
        })
        return fake_func
    }


    /*********************************** Patch指令 ARM64 ******************************************** */

    /**
     * patch 连续N条ARM64指令
     * v1版本: 通过调用putInstruction函数逐指令patch， 传入指令hex字符串
     * v2版本：通过调用v3函数进行patch， 传入指令hex字符串
     * v3版本：通过调用putBytes多字节批量path，传入指令的字节数组
     * 
     */


    /**
     * @param addr 起始地址
     * @param codehex N条指令对应的机器码(16进制表示)，每条指令占8个字符，支持空格隔开，例如：
     * '9511168d393ceaeeefb4ed6c03c60941' 或者 '9511168d 393ceaee efb4ed6c 03c60941'
     */
    export function patchCode64_v1(startAddr: NativePointer, codehex: string) {

        //1.替换指令代码中的空格
        codehex = codehex.replace(/\s/g, '');
        const byteCount = Math.floor(codehex.length / 2);

        //2.开始patch
        Memory.patchCode(startAddr, byteCount, code => {
            
            const cw = new Arm64Writer(code, { pc: startAddr });

            //1条ARM64指令占4个字节，所以每次取8个字符；并转换为16进制整数, 然后写入
            for (let i = 0; i < codehex.length; i += 8) {
                let subStr = codehex.substring(i, i + 8);
                let hexNumber = parseInt(subStr, 16);
                cw.putInstruction(hexNumber);
            }
            cw.flush();
        });

    }

    export function patchCode64_v2(startAddr: NativePointer, codehex: string) {

        //1.替换指令代码中的空格
        codehex = codehex.replace(/\s/g, '');
        const bytes = StringUtils.hexToBytes(codehex)
        patchCode64_v3(startAddr, bytes)

    }

    export function patchCode64_v3(startAddr: NativePointer, codeBytes: number[]) {
        Memory.patchCode(startAddr, codeBytes.length, code => {
            const cw = new Arm64Writer(code, { pc: startAddr });
            cw.putBytes(codeBytes);
            cw.flush();
        });
    }

    //批量patch
    export function patchCode64_batch(startAddrArr: NativePointer[], codehexArr: string[]) {

        if (startAddrArr.length != codehexArr.length) {
            console.log("patchCode64_batch: 参数长度不一致")
            return
        }

        for (let i = 0; i < startAddrArr.length; i++) {
            patchCode64_v2(startAddrArr[i], codehexArr[i])
        }

    }


    /**
     * patch函数，使其直接返回；要求arm64
     * @param funcBaseAddr 
     */
    export function patchFunc64(funcBaseAddr: NativePointer) {
        Memory.patchCode(funcBaseAddr, 4, code => {
            const cw = new Arm64Writer(code, { pc: funcBaseAddr });
            cw.putRet();
            cw.flush();
        });
    }

    export function patchFunc64_by_offset(soName: string, offset: number) {
        let targetModule = Process.findModuleByName(soName);
        let funcBaseAddr = targetModule.base.add(offset);
        Memory.patchCode(funcBaseAddr, 4, code => {
            const cw = new Arm64Writer(code, { pc: funcBaseAddr });
            cw.putRet();
            cw.flush();
        });
    }

    /**
     * 
     * @param funcBaseAddrArr 批量patch函数
     */
    export function patchFunc64_batch(funcAddrArr: NativePointer[]) {
        for (let i = 0; i < funcAddrArr.length; i++) {
            patchFunc64(funcAddrArr[i])
        }
    }

    export function patchFunc64_batch_by_offset(soName: string, funcOffsetAddrArr: number[]) {

        let targetModule = Process.findModuleByName(soName);
        for (let i = 0; i < funcOffsetAddrArr.length; i++) {
            patchFunc64(targetModule.base.add(funcOffsetAddrArr[i]))
        }
    }


    /**
     * NOP连续N条arm64指令，N默认为1
     * @param startAddr 起始地址
     * @param n         指令条数
     */
    export function nop64(startAddr: NativePointer, n: number = 1) {
        Memory.patchCode(startAddr, 4 * n, code => {
            const cw = new Arm64Writer(code, { pc: startAddr });
            for (let i = 0; i < n; i++) {
                cw.putNop();
            }
            cw.flush();
        });
    }

    /**
     * 批量NOP
     * @param startAddr 地址数组 
     */
    export function nop64_batch(addrs: NativePointer[]) {
        for (let i = 0; i < addrs.length; i++) {
            nop64(addrs[i])
        }
    }


}

