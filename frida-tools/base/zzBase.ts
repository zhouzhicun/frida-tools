


import * as ZZStalkerTrace from "./zzStalkerTrace.js"
import * as ZZR0trace from "./zzR0trace.js"


import { ZZCallStack } from "./zzCallStack.js";
import { ZZHookFuncHandler } from "./zzHookFuncHandler.js";
import { ZZPatch } from "./zzPatch.js";
import { ZZStringUtils } from "./zzStringUtils.js";
import { ZZNativeFunc } from "./zzNativeFunc.js";

import { ZZSyscallTable } from "./zzSyscallTable.js";



export namespace Base {

    export let zzCallStack = ZZCallStack;
    export let zzStalkerTrace = ZZStalkerTrace;
    export let zzHookFuncHandler = ZZHookFuncHandler
    export let zzR0trace = ZZR0trace
    export let zzPatch = ZZPatch
    export let zzStringUtils = ZZStringUtils
    export let zzNativeFunc = ZZNativeFunc
    export let syscallTable = ZZSyscallTable

    

}

