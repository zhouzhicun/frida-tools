
import { Utils } from "../android/utils/utils.js";
import { FuncHandler } from "../android/utils/funchandle.js";

import { AntiJavaDebug } from "../android/antiDebug/antiJavaDebug.js";
import { AntiNativeDebug } from "../android/antiDebug/antiNativeDebug.js";

import { UI } from "../android/ui.js";


AntiJavaDebug.anti_debug();
AntiNativeDebug.anti_debug();

UI.print_config = FuncHandler.FuncPrintType.func_callstacks;
UI.hook_ui();



// const header = Memory.alloc(16);
// header
//     .writeU32(0xdeadbeef).add(4)
//     .writeU32(0xd00ff00d).add(4)
//     .writeU64(uint64("0x1122334455667788"));
// log(hexdump(header.readByteArray(16) as ArrayBuffer, { ansi: true }));

// Process.getModuleByName("libSystem.B.dylib")
//     .enumerateExports()
//     .slice(0, 16)
//     .forEach((exp, index) => {
//         log(`export ${index}: ${exp.name}`);
//     });

// Interceptor.attach(Module.getExportByName(null, "open"), {
//     onEnter(args) {
//         const path = args[0].readUtf8String();
//         log(`open() path="${path}"`);
//     }
// });
