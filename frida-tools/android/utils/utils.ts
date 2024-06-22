export namespace Utils {



    //java打印堆栈
    export function print_java_callstacks() {
        console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));
    }

    //打印native堆栈
    export function print_native_callstacks(context: any) {
        console.log(' called from:\n' + Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
    }

    //打印分割线
    export function print_divider(tips = '') {
        console.log(`==============================${tips}==============================`)
    }

    //打印参数
    export function print_arguments() {
        console.log('arguments: ', ...arguments)
    }

    export function get_class_name(obj: any) {
       if (obj !== null) {
           return obj.getClass().getName();
       } else {
           return null;
       }
    }

}


