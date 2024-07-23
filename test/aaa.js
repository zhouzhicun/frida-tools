var GWorld_Offset = 0x0B32D8A8
var GName_Offset = 0x0B171CC0
var GUObjectArray_Offset = 0xB1B5F98

function aaa() {

    console.log("------------------------------------------")
    let moduleBase = Module.findBaseAddress("libUE4.so");

    //UE4基地址加上在IDA中获取的GName偏移获取GName地址
    let GName = moduleBase.add(GName_Offset);

    //同上获取GUObjectArray的地址
    let GUObjectArray = moduleBase.add(GUObjectArray_Offset);

    //读取GWorld的指针
    let GWorld = moduleBase.add(GWorld_Offset).readPointer();

    console.log("GWorld: " + GWorld)
    console.log("GName: " + GName)
    console.log("GUObjectArray: " + GUObjectArray)


    // set("libUE4.so")
}





function set(moduleName) {
    //获取libUE4的基地址
    console.log("moduleName=", moduleName)
    let moduleBase = Module.findBaseAddress(moduleName);

    //UE4基地址加上在IDA中获取的GName偏移获取GName地址
    let GName = moduleBase.add(GName_Offset);

    //同上获取GUObjectArray的地址
    let GUObjectArray = moduleBase.add(GUObjectArray_Offset);

    //读取GWorld的指针
    let GWorld = moduleBase.add(GWorld_Offset).readPointer();


    console.log("GWorld: " + GWorld, "GName: " + GName, "GUObjectArray: " + GUObjectArray);

}

setImmediate(function () {
    //延迟1秒调用Hook方法
    setTimeout(aaa, 3000)
});
