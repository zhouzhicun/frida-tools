
import { Utils } from "../../base/Utils.js";

export namespace AntiNativeDebug {

    const antiDebugLogTip = "anti_native_debug ==>"

    //打印函数调用栈
    function print_callstacks(funcName: string, context: any) {
        console.log(antiDebugLogTip + funcName);
        //print_LR(context);
        Utils.print_native_callstacks(context);
    }

    function print_LR(context: any) {
        let lr = Utils.getLR(context)
        console.log("lr = " + lr.toString(16))
    }


    export function anti_debug() {

        anti_dlsym();
        anti_fork();
        anti_ptrace();
        anti_syscall();
        anti_fgets();

        anti_app_exit();
    }

    export function anti_app_exit() {
        anti_abort();
        anti_exit();
        anti_kill();
        anti_raise();
    }


    export function anti_dlsym() {

        let funcPtr = Utils.getFuncPtr("dlsym");
        let origin_func = new NativeFunction(funcPtr, 'pointer', ['pointer', 'pointer']);
        Interceptor.replace(funcPtr, new NativeCallback(function (handle: any, name: any) {
            let funcName = name.readCString()
            console.log(antiDebugLogTip + `dlsym(${funcName}) called\n`);
            if(funcName == "pthread_create") {
                print_callstacks('dlsym', this.context);
            }
            return origin_func(handle, name);

        }, 'pointer', ['pointer', 'pointer']));

    }


    export function hook_dlsym(targetFuncName: string, callBack: any) {

        let funcPtr = Utils.getFuncPtr("dlsym");
        let origin_func = new NativeFunction(funcPtr, 'pointer', ['pointer', 'pointer']);
        Interceptor.replace(funcPtr, new NativeCallback(function (handle: any, name: any) {
            let curFuncName = name.readCString()
            console.log(antiDebugLogTip + `dlsym(${curFuncName}) called\n`);
            let result = origin_func(handle, name);
            console.log("curFuncName = " + curFuncName + " targetFuncName = " + targetFuncName);
            if(curFuncName == targetFuncName) {
                console.log("---------------------------------11111111111---------------------------------")
                console.log("func_addr = 0x" + result.toString(16))
                callBack(result);
            }
            return result;

        }, 'pointer', ['pointer', 'pointer']));

    }


    export function anti_ptrace() {

        //long ptrace(enum __ptrace_request op, pid_t pid, void *addr, void *data);
        let funcPtr = Utils.getFuncPtr("ptrace");
        let origin_func = new NativeFunction(funcPtr, 'long', ['int', "int", 'pointer', 'pointer']);
        Interceptor.replace(funcPtr, new NativeCallback(function (request: any, pid: any, addr: any, data: any) {

            //PT_DENY_ATTACH 31
            if (request == 31) {
                print_callstacks('ptrace', this.context);
                return 0;
            } 
            return origin_func(request, pid, addr, data);

        }, 'long', ['int', "int", 'pointer', 'pointer']));

    }

    
    export function anti_syscall() {

        //long syscall(long number, ...);
        let funcPtr = Utils.getFuncPtr("syscall");
        let origin_func = new NativeFunction(funcPtr, 'long', ['long', 'pointer']);
        Interceptor.replace(funcPtr, new NativeCallback(function (code: any, args: any) {
            
            //ptrace 26
            if (code == 26) {
                let arg0 = args[0]
                if(arg0 == 31) {
                    print_callstacks('syscall(ptrace)', this.context);
                    return 0;
                }
            } 
            return origin_func(code, args);

        }, 'long', ['long', 'pointer']));
    }


    export function anti_fork() {
        // pid_t fork(void);
        let funcPtr = Utils.getFuncPtr("fork");
        let origin_func = new NativeFunction(funcPtr, 'int', []);
        Utils.replaceFunc('fork', new NativeCallback(function () {
            print_callstacks('fork', this.context);
            return origin_func();
        }, 'int', []));
    }


    export function anti_abort() {

        //void abort(void);
        Utils.replaceFunc('abort', new NativeCallback(function () {
            print_callstacks('abort', this.context);
            return 0;
        }, 'void', []));
    }

    export function anti_exit() {

        //void _exit(int status);
        Utils.replaceFunc('_exit', new NativeCallback(function () {
            print_callstacks('_exit', this.context);
        }, 'void', ['int']));

        // //void _Exit(int status);
        // Utils.replaceFunc('_Exit', new NativeCallback(function () {
        //     print_callstacks('_Exit', this.context);
        // }, 'void', ['int']));

        //void exit(int status);
        Utils.replaceFunc('exit', new NativeCallback(function () {
            print_callstacks('exit', this.context);
        }, 'void', ['int']));

        //void exit_group(int status);
        Utils.replaceFunc('exit_group', new NativeCallback(function () {
            print_callstacks('exit_group', this.context);
        }, 'void', ['int']));

    }

    export function anti_kill() {

        //int kill(pid_t pid, int sig);
        Utils.replaceFunc('kill', new NativeCallback(function () {
            print_callstacks('kill', this.context);
            return 0;
        }, 'int', ['int', 'int']));
    }

    export function anti_raise() {

        // int raise(int sig);
        Utils.replaceFunc('raise', new NativeCallback(function () {
            print_callstacks('raise', this.context);
            return 0;
        }, 'int', ['int']));
    }


    /**
     * @state_name: 
     * cat /proc/xxx/stat ==> ...(<state_name>) S...
     * cat /proc/xxx/status ==> ...(<state_name>) S...
     *
     * anti fgets function include :
     * status->TracerPid, SigBlk, S (sleeping)
     * State->(package) S
     * wchan->SyS_epoll_wait
     */
    export function anti_fgets() {

        //char *fgets(char *restrict s, int n, FILE *restrict stream);
        var funcPtr = Utils.getFuncPtr("fgets");
        var origin_fgets = new NativeFunction(funcPtr, 'pointer', ['pointer', 'int', 'pointer']);
        Interceptor.replace(funcPtr, new NativeCallback(function (buffer: any, size: any, fp: any) {

            var retval = origin_fgets(buffer, size, fp);
            var bufstr = buffer.readCString();

            var logs = ''
            if (null != bufstr) {

                if (bufstr.indexOf("TracerPid:") > -1) {
                    buffer.writeUtf8String("TracerPid:\t0");
                    logs = "fgets(TracerPid)";
                }
                //State:	S (sleeping)
                else if (bufstr.indexOf("State:\tt (tracing stop)") > -1) {
                    buffer.writeUtf8String("State:\tS (sleeping)");
                    logs = "fgets(State)";
                }
                // ptrace_stop
                else if (bufstr.indexOf("ptrace_stop") > -1) {
                    buffer.writeUtf8String("sys_epoll_wait");
                    logs = "fgets(ptrace_stop)";
                }

                //(sankuai.meituan) t
                else if (bufstr.indexOf(") t") > -1) {
                    buffer.writeUtf8String(bufstr.replace(") t", ") S"));
                    logs = "fgets(stat_t)";
                }

                // SigBlk
                else if (bufstr.indexOf('SigBlk:') > -1) {
                    buffer.writeUtf8String('SigBlk:\t0000000000001204');
                    logs = "fgets(SigBlk)";
                }

                // frida
                else if (bufstr.indexOf('frida') > -1) {
                    print_callstacks('fgets', this.context);
                    buffer.writeUtf8String("zz");
                    logs = "fgets(frida)";
                }

                if (logs.length > 0) {
                    console.log(logs);
                    print_callstacks('fgets', this.context);
                }
            }
            return retval;



        }, 'pointer', ['pointer', 'int', 'pointer']));

    }
}




