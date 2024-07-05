


/**
 * 函数堆栈信息
 * 支持ARM64 android, iOS
 */
export namespace ZZCallStack {



    //================================= 函数调用栈打印 =========================================

    //打印Java方法调用堆栈
    export function printJavaCallstacks() {
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    }

    //打印native函数调用堆栈
    export function printNativeCallstacks(context: any) {
        console.log(' called from:\n' + Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
    }


    //================================= 当前函数栈信息 =========================================

    /**
     * 获取当前上下文寄存器信息，返回JSON字符串
     * @param context 
     * @returns 
     */
    export function getRegisterContext(context: CpuContext) {
        let regContext = JSON.stringify(context)
        return regContext
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



    /**
     * 打印函数栈信息（指定栈层数，8字节为一层），并输出 module 信息 (如果有）
     * @param {CpuContext} context
     * @param {number} number
     */
    export function printFuncStackInfo(context: CpuContext, number: number) {
        var sp: NativePointer = context.sp;

        for (var i = 0; i < number; i++) {
            var curSp = sp.add(Process.pointerSize * i);
            console.log('showStacksModInfo curSp: ' + curSp + ', val: ' + curSp.readPointer()
                + ', module: ' + getModuleInfoByAddr(curSp.readPointer()));
        }
    }

    /**
     * 根据地址获取模块信息
     * @param {NativePointer} addr
     * @returns {string}
     */
    function getModuleInfoByAddr(addr: NativePointer): Module | null {
        var result = null;
        Process.enumerateModules().forEach(function (module: Module) {
            if (module.base <= addr && addr <= (module.base.add(module.size))) {
                result = JSON.stringify(module);
                return false; // 跳出循环
            }
        });
        return result;
    }




}

