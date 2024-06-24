

export namespace Utils {

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

}

