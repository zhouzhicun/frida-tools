
import { Utils } from "../../base/Utils";

export namespace AntiNativeDebug {

    const antiDebugLogTip = "anti_native_debug ==>"

    //打印函数调用栈
    function print_callstacks(funcName: string, context: any) {
        console.log(antiDebugLogTip + funcName);
        //Utils.print_native_callstacks(context);
    }


    export function anti_debug() {

        anti_dlsym();
        anti_abort();
        anti_exit();
        anti_kill();
        anti_fork();
        anti_ptrace();
        anti_fgets();
    }


    export function anti_dlsym() {
        const dlsym_ptr = Module.findExportByName(null, 'dlsym');
        console.log(antiDebugLogTip + "dlsym_func_ptr = " + dlsym_ptr);
        if (null == dlsym_ptr) {
            return;
        }

        //hook dlsym函数
        Interceptor.attach(dlsym_ptr, {
            onEnter: function (args) {
                var name = args[1].readCString();
                console.log(antiDebugLogTip + `dlsym(${name}) called\n`);
                print_callstacks('dlsym', this.context);
            },
            onLeave: function (retval) {
                console.log(antiDebugLogTip + "dlsym retval = " + retval);
            }
        });

    }

    export function anti_abort() {

        const abort_ptr = Module.findExportByName(null, 'abort');
        console.log(antiDebugLogTip + "abort_func_ptr = " + abort_ptr);
        if (null == abort_ptr) {
            return;
        }


        const abort_new_func = new NativeCallback(function () {
            print_callstacks('abort', this.context);
            return 0;
        }, 'void', []);

        console.log(antiDebugLogTip + "abort_new_func_ptr = " + abort_new_func.toString());

        //替换abort函数
        Interceptor.replace(abort_ptr, abort_new_func);
    }


    export function anti_exit() {


        //替换_exit函数
        const exit_ptr1 = Module.findExportByName(null, '_exit');
        console.log(antiDebugLogTip + "_exit_func_ptr = " + exit_ptr1);
        if (null == exit_ptr1) {
            return;
        }

        const _exit_new_func = new NativeCallback(function (code: any) {
            print_callstacks('_exit', this.context);
            return 0;
        }, 'int', ['int']);
        
        console.log(antiDebugLogTip + "_exit_new_func_ptr = " + _exit_new_func.toString());

        Interceptor.replace(exit_ptr1, _exit_new_func);


        //替换exit函数
        const exit_ptr2 = Module.findExportByName(null, 'exit');
        console.log(antiDebugLogTip + "exit_func_ptr = " + exit_ptr2);
        if (null == exit_ptr2) {
            return;
        }

        const exit_new_func = new NativeCallback(function (code: any) {
            print_callstacks('exit', this.context);
            return 0;
        }, 'int', ['int'])
        
        console.log(antiDebugLogTip + "exit_new_func_ptr = " + exit_new_func.toString());
        Interceptor.replace(exit_ptr2, exit_new_func);


    }

    export function anti_kill() {
        const kill_ptr = Module.findExportByName(null, 'kill');
        console.log(antiDebugLogTip + "kill_func_ptr = " + kill_ptr);
        if (null == kill_ptr) {
            return;
        }



        const kill_new_func = new NativeCallback(function (ptid: any, code: any) {
            print_callstacks('kill', this.context);
            return 0;
        }, 'int', ['int', 'int'])
        
        console.log(antiDebugLogTip + "kill_new_func_ptr = " + kill_new_func.toString());
        Interceptor.replace(kill_ptr, kill_new_func);
    }


    export function anti_ptrace() {
        var ptrace_ptr = Module.findExportByName(null, "ptrace");
        console.log(antiDebugLogTip + "ptrace_func_ptr = " + ptrace_ptr);
        if (null == ptrace_ptr) {
            return;
        }


        const ptrace_new_func = new NativeCallback(function (p1: any, p2: any, p3: any, p4: any) {
            print_callstacks('ptrace', this.context);
            return 1;
        }, 'long', ['int', "int", 'pointer', 'pointer']);
        
        console.log(antiDebugLogTip + "ptrace_new_func_ptr = " + ptrace_new_func.toString());

        Interceptor.replace(ptrace_ptr, ptrace_new_func);

    }

    export function anti_fork() {
        var fork_ptr = Module.findExportByName(null, "fork");
        console.log(antiDebugLogTip + "fork_func_ptr = " + fork_ptr);
        if (null == fork_ptr) {
            return;
        }


        const fork_new_func = new NativeCallback(function () {
            print_callstacks('fork', this.context);
            return -1;
        }, 'int', []);
        
        console.log(antiDebugLogTip + "fork_new_func_ptr = " + fork_new_func.toString());

        Interceptor.replace(fork_ptr, fork_new_func);
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
  
        const fgets_ptr = Module.findExportByName(null, 'fgets');
        //console.log(antiDebugLogTip + "fgets_func_ptr = " + fgets_ptr);
        if (null == fgets_ptr) {
            return;
        }

        var origin_fgets = new NativeFunction(fgets_ptr, 'pointer', ['pointer', 'int', 'pointer']);
        const fgets_new_func = new NativeCallback(function (buffer, size, fp) {

            //print_callstacks('fgets', this.context);

            // 读取原 buffer, 并针对性修改~
            var retval = origin_fgets(buffer, size, fp);
            var bufstr = buffer.readCString();


            var logs = ''

            if (null != bufstr) {
                if (bufstr.indexOf("TracerPid:") > -1) {
                    buffer.writeUtf8String("TracerPid:\t0");
                    logs = antiDebugLogTip + "fgets(TracerPid)";
                }
                //State:	S (sleeping)
                else if (bufstr.indexOf("State:\tt (tracing stop)") > -1) {
                    buffer.writeUtf8String("State:\tS (sleeping)");
                    logs = antiDebugLogTip + "fgets(State)";
                }
                // ptrace_stop
                else if (bufstr.indexOf("ptrace_stop") > -1) {
                    buffer.writeUtf8String("sys_epoll_wait");
                    logs = antiDebugLogTip + "fgets(ptrace_stop)";
                }

                //(sankuai.meituan) t
                else if (bufstr.indexOf(") t") > -1) {
                    buffer.writeUtf8String(bufstr.replace(") t", ") S"));
                    logs = antiDebugLogTip + "fgets(stat_t)";
                }

                // SigBlk
                else if (bufstr.indexOf('SigBlk:') > -1) {
                    buffer.writeUtf8String('SigBlk:\t0000000000001204');
                    logs = antiDebugLogTip + "fgets(SigBlk)";
                }

                // frida
                else if (bufstr.indexOf('frida') > -1) {
                    // 直接回写空有可能引起崩溃
                    buffer.writeUtf8String("zzmimi");
                    logs = antiDebugLogTip + "fgets(frida)";
                    Utils.print_native_callstacks(this.context);
                }

                if(logs.length > 0){
                    console.log(logs);
                    print_callstacks('fgets', this.context);
                }

            }
            return retval;
        }, 'pointer', ['pointer', 'int', 'pointer'])
        
        console.log(antiDebugLogTip + "fgets_new_func_ptr = " + fgets_new_func.toString());

        Interceptor.replace(fgets_ptr, fgets_new_func);
    }


}

