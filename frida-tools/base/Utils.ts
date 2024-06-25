

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


    //创建一个假的函数, 该函数直接返回
    export function create_fake_func() {
        const fake_func = Memory.alloc(4096)
        Memory.protect(fake_func, 4096, "rwx")
        Memory.patchCode(fake_func, 4096, code => {
            const cw = new Arm64Writer(code, { pc: fake_func })
            cw.putRet()
        })
        return fake_func
    }


    /*********************************** Patch指令 ARM64 ******************************************** */



    /**
     * patch 连续N条ARM64指令
     * 
     * @param addr 起始地址
     * @param n N条arm64指令
     * @param codehex N条指令对应的机器码(16进制表示)，每条指令占8个字符，支持空格隔开，例如：
     * 9511168d393ceaeeefb4ed6c03c60941 或者 9511168d 393ceaee efb4ed6c 03c60941
     */
    export function patchCode64(startAddr: NativePointer, n: number, codehex: string) {

        //1.替换指令代码中的空格
        codehex = codehex.replace(/\s/g, '');

        //2.开始patch
        Memory.patchCode(startAddr, n * 4, code => {
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

    /**
     * 
     * @param funcBaseAddrArr 批量patch函数
     */
    export function patchFunc64_batch(funcBaseAddrArr: NativePointer[]) {
        for (let i = 0; i < funcBaseAddrArr.length; i++) {
            patchFunc64(funcBaseAddrArr[i])
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

