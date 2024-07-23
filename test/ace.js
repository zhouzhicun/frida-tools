
console.log("------------------------------------------------")

var GWorldOffset = 0xB32D8A8
var GName_Offset = 0xB171CC0
var GUObjectArray_Offset = 0xB1B5F98
var playerName = "FirstPersonCharacter_C"
var moduleBase
var GWorld
var GName
var GUObjectArray

//Class: UObject
//对象的内部索引，用于唯一标识对象。
var offset_UObject_InternalIndex = 0xC;

//指向描述对象类的 UClass 对象
var offset_UObject_ClassPrivate = 0x10;

//对象名称在 FName 表中的索引
var offset_UObject_FNameIndex = 0x18;

//指向包含该对象的外部对象，表示层次关系。
var offset_UObject_OuterPrivate = 0x20;
var UObject = {
    getClass: function (obj) {
        var classPrivate = ptr(obj).add(offset_UObject_ClassPrivate).readPointer();//读取指针
        //console.log(`classPrivate: ${classPrivate}`);
        return classPrivate;
    },
    getNameId: function (obj) {
        //console.log(`obj:${obj}`);
        try {
            var nameId = ptr(obj).add(offset_UObject_FNameIndex).readU32();//读取4字节。
            //console.log(`nameId:${nameId}`);
            return nameId;
        } catch (e) {
            console.log("error")
            return 0;
        }
    },
    getName: function (obj) {
        if (this.isValid(obj)) {
            return getFNameFromID(this.getNameId(obj));
        } else {
            return "None";
        }
    },
    getClassName: function (obj) {
        if (this.isValid(obj)) {
            var classPrivate = this.getClass(obj);
            return this.getName(classPrivate);
        } else {
            return "None";
        }
    },
    isValid: function (obj) {
        var isValid = (ptr(obj) > 0 && this.getNameId(obj) > 0 && this.getClass(obj) > 0);
        // console.log(`isValid: ${isValid}`);
        return isValid;
    }

}
function getFNameFromID(index) {
    // FNamePool相关偏移量和步长
    var FNameStride = 0x2;                   // FNameEntry 的步长，每个FNameEntry占用2字节
    var offset_GName_FNamePool = 0x30;       // GName 到 FNamePool 的偏移量
    var offset_FNamePool_Blocks = 0x10;      // FNamePool 到 Blocks 的偏移量

    // FNameEntry相关偏移量和位
    var offset_FNameEntry_Info = 0;          // FNameEntry 到 Info 的偏移量
    var FNameEntry_LenBit = 6;               // FNameEntry 长度位
    var offset_FNameEntry_String = 0x2;      // FNameEntry 到字符串部分的偏移量

    // 计算块和偏移量
    var Block = index >> 16;                 // 块索引
    var Offset = index & 65535;              // 块内偏移量

    // 获取FNamePool的起始地址
    var FNamePool = GName.add(offset_GName_FNamePool);
    // console.log(`FNamePool: ${FNamePool}`);
    // console.log(`Block: ${Block}`);

    // 获取特定块的地址
    var NamePoolChunk = FNamePool.add(offset_FNamePool_Blocks + Block * 8).readPointer();
    // console.log(`NamePoolChunk: ${NamePoolChunk}`);

    // 计算FNameEntry的地址
    var FNameEntry = NamePoolChunk.add(FNameStride * Offset);
    // console.log(`FNameEntry: ${FNameEntry}`);

    try {
        // 读取FNameEntry的Header
        if (offset_FNameEntry_Info !== 0) {
            var FNameEntryHeader = FNameEntry.add(offset_FNameEntry_Info).readU16();
        } else {
            var FNameEntryHeader = FNameEntry.readU16();
        }
    } catch (e) {
        // 捕捉读取异常并返回空字符串
        // console.log(e);
        return "";
    }
    // console.log(`FNameEntryHeader: ${FNameEntryHeader}`);

    // 获取字符串地址
    var str_addr = FNameEntry.add(offset_FNameEntry_String);
    // console.log(`str_addr: ${str_addr}`);

    // 计算字符串长度和宽度
    var str_length = FNameEntryHeader >> FNameEntry_LenBit; // 计算字符串长度
    var wide = FNameEntryHeader & 1;                       // 判断字符串是否为宽字符

    // 如果是宽字符，返回 "widestr"
    if (wide) return "widestr";

    // 如果字符串长度合理，读取并返回UTF-8字符串
    if (str_length > 0 && str_length < 250) {
        var str = str_addr.readUtf8String(str_length);
        return str;
    } else {
        return "None"; // 长度不合理，返回 "None"
    }
}

//获取对象实例
function getActorAddr(str) {
    var player_addr;
    var actorsAddr = getActorsAddr();
    for (var key in actorsAddr) {
        if (key == str) {
            console.log(actorsAddr[key]);
            player_addr = actorsAddr[key];
        }
    }
    if (player_addr == null) {
        console.log("null pointer!");
    }
    return player_addr;
}
function getActorsAddr() {
    var Level_Offset = 0x30//偏移
    var Actors_Offset = 0x98
    var Level = GWorld.add(Level_Offset).readPointer()//读取GWorld的level指针
    var Actors = Level.add(Actors_Offset).readPointer()//读取Actors的指针
    var Actors_Num = Level.add(Actors_Offset).add(8).readU32()//获取Actor的数量
    var actorsAddr = {};//空对象，下面的实现类似字典
    for (var index = 0; index < Actors_Num; index++) {
        var actor_addr = Actors.add(index * 8).readPointer()//读取当前索引处的Actor地址
        var actorName = UObject.getName(actor_addr)//通过地址获取字符串名字
        actorsAddr[actorName] = actor_addr;//以字符串名字对应地址值
        //console.log(`actors[${index}]`,actorName);
    }


    //console.log("actorsAddr = ", actorsAddr)

    var json = JSON.stringify(actorsAddr)
    console.log("actorsAddr = ", json)

    return actorsAddr;
}
function set(moduleName) {
    //获取libUE4的基地址
    console.log("moduleName=", moduleName)
    moduleBase = Module.findBaseAddress(moduleName);

    //UE4基地址加上在IDA中获取的GName偏移获取GName地址
    GName = moduleBase.add(GName_Offset);

    //同上获取GUObjectArray的地址
    GUObjectArray = moduleBase.add(GUObjectArray_Offset);

    //读取GWorld的指针
    GWorld = moduleBase.add(GWorldOffset).readPointer();


    console.log("GWorld: " + GWorld, "GName: " + GName, "GUObjectArray: " + GUObjectArray);

}
function setPlayerHP(hp = 1000000) {
    //生命值属性的偏移
    getActorAddr(playerName).add(0x510).writeFloat(hp);//写入
}


//瞬移////////////////////////////////////
class Vector {//设置向量对象
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    // 将向量转换为字符串
    toString() {
        return `(${this.x}, ${this.y}, ${this.z})`;
    }
}
function dumpVector(addr) {
    // dumpAddr('firstPersion_RootComponent',firstPersion_RootComponent_ptr,0x152)
    // 从地址空间中读取三个浮点数

    console.log("--------- dump ----------")
    console.log(hexdump(addr, {
        offset: 0,
        length: 12,
        header: true,
        ansi: false
    }));

    //解析浮点数---
    const values = Memory.readByteArray(addr, 3 * 4);  // 3个float共占12个字节
    // 解析浮点数并初始化 Vector 对象
    const vec = new Vector(
        new Float32Array(values, 0, 1)[0],  // 读取第一个浮点数
        new Float32Array(values, 4, 1)[0],  // 读取第二个浮点数
        new Float32Array(values, 8, 1)[0]   // 读取第三个浮点数
    );
    console.log('[+] 坐标：', vec);//打出坐标。

    // frida16 不支持Memory.readFloat()
    // const a = Memory.readFloat(addr)
    // const b = Memory.readFloat(addr + 4)
    // const c = Memory.readFloat(addr + 8)
    // console.log(`a = ${a}, b = ${b}, c = ${c}`)


}

function getActorLocation(actor_addr) {
    GWorld = moduleBase.add(GWorldOffset).readPointer();
    actor_addr = ptr(actor_addr)
    var buf = Memory.alloc(0x100);
    var f_addr = moduleBase.add(0x965ddf8);
    // 将目标函数地址转换为JavaScript函数
    var getLocationFunc = new NativeFunction(f_addr, 'void', ['pointer', 'pointer', 'pointer']);

    // 调用目标函数并传递内存地址作为参数
    try {
        console.log("start getLocationFunc---------------")
        getLocationFunc(actor_addr, buf, buf);
        dumpVector(buf);
        return buf;
        //info(ptr(actor_addr).add(0x130).readPointer().add(0x14c).readU8()&32 != 0);
    }
    catch (e) {
        console.log("getLocationFunc error!!!!!!!!!")
    }
}
// 965dc3c
function setActorLocation(actor_addr, x, y, z) {
    GWorld = moduleBase.add(GWorldOffset).readPointer();
    actor_addr = ptr(actor_addr)
    var f_addr = moduleBase.add(0x8C3181C);//加上偏移获取目标函数的偏移
    // 将目标函数地址转换为JavaScript函数
    var setLocationFunc = new NativeFunction(f_addr, 'bool', ['pointer', 'bool', 'pointer', 'bool', 'float', 'float', 'float']);
    // 调用目标函数并传递内存地址作为参数
    setLocationFunc(actor_addr, 0, ptr(0), 0, x, y, z);
    //dumpVector(buf);

}


////显示
//void SetVisibility(bool bNewVisibility, bool bPropagateToChildren);
function SetVisibility(Component, bNewVisibility, bPropagateToChildren) {
    var pSetVisibility = moduleBase.add(0x8E619BC);
    var callSetVisibility = new NativeFunction(pSetVisibility, "void", ['pointer', 'int', 'int']);
    callSetVisibility(ptr(Component).add(0x130).readPointer(), bNewVisibility, bPropagateToChildren);
}

////碰撞函数
function setActorEnableCollision(actor_addr, bNewActorEnableCollision = 1) {
    var f_addr = moduleBase.add(0x8C21320);
    let CallFunc = new NativeFunction(f_addr, 'void', ['pointer', 'char']);
    CallFunc(ptr(actor_addr), bNewActorEnableCollision);
}
function setStaticMeshActorCollisionEnabled(actor_addr, NewType = 3) {

    actor_addr = ptr(actor_addr)
    var f_addr = actor_addr.add(0x220).readPointer().readPointer().add(0x660).readPointer();//这段似乎进行了一个读取虚函数表的操作
    var getActorCollisionEnabled = new NativeFunction(f_addr, 'char', ['pointer', 'char']);
    let ret = getActorCollisionEnabled(actor_addr.add(0x220).readPointer(), NewType);
    console.log("未知函数：", ret);
}
function SetCollisionEnable(actor_addr, dr = 3) {
    var f_addr = moduleBase.add(0x933b300);
    let CallFunc = new NativeFunction(f_addr, 'void', ['pointer', 'int']);
    CallFunc(ptr(actor_addr).add(0x130).readPointer(), dr);
}


//获取虚表指针
function GetActorVrtualAdress() {
    try {
        moduleBase = Module.findBaseAddress("libUE4.so");
        console.log("[+] moduleBase:", moduleBase);
        console.log("[+] GWorld_Offset:", GWorldOffset);
        GWorld = moduleBase.add(GWorldOffset).readPointer();
        console.log("[+] GWorld:", GWorld);
        var Level_Offset = 0x30;
        var Actors_Offset = 0x98;
        var Level = GWorld.add(Level_Offset).readPointer();

        console.log("[+] Level Address:", Level);

        var Actors = Level.add(Actors_Offset).readPointer();
        console.log("[+] Actors Address:", Actors);
        var Actors_Num1 = Level.add(Actors_Offset).add(8).readU32();
        console.log("[+] ActorNum:", ptr(Actors_Num1));

        // 使用循环遍历每个 Actor
        for (var index = 0; index < Actors_Num1; index++) {
            try {
                console.log("[+] Number:", index);
                var actor_addr = Actors.add(index * 8).readPointer();
                if (actor_addr.isNull()) {
                    console.error(`Error: Actor address at index ${index} is null`);
                    continue;
                }
                var ActorClass = UObject.getClassName(actor_addr);
                var vtable_addr = actor_addr.readPointer();

                console.log(`[+] Actor Class: ${ActorClass}`);
                console.log(`[+] Actor Address: ${actor_addr}`);
                console.log(`[+] Virtual Address: 0x${(vtable_addr.sub(moduleBase)).toString(16)}`);
            } catch (h) {
                console.error("Error occurred:1", h);
            }
        }
    } catch (e) {
        console.error("Error occurred:2", e);
    }
}


// (async () => {
//     await GetActorVrtualAdress();
// })();


//主要实现作弊的hanshu
function dumpActorInstances() {
    GWorld = moduleBase.add(GWorldOffset).readPointer();//找到GWorld这个类并储存它的地址作为指针
    var Level_Offset = 0x30
    var Actors_Offset = 0x98
    var Level = GWorld.add(Level_Offset).readPointer()//关卡的指针
    var Actors = Level.add(Actors_Offset).readPointer()//Actor的指针
    var Actors_Num = Level.add(Actors_Offset).add(8).readU32()//Actors的数量
    var actorsInstances = {};
    for (var index = 0; index < Actors_Num; index++) {
        var actor_addr = Actors.add(index * 8).readPointer();
        var ActorName = UObject.getName(actor_addr)
        actorsInstances[index] = ActorName;
        //console.log(`actors[${index}]:${actor_addr}`,actorName);

        if (ActorName.includes("Cube")) { //设置为可碰撞
            try {
                console.log('[+] ActorName:', ActorName);
                //setStaticMeshActorCollisionEnabled(actor_addr,1);
                setStaticMeshActorCollisionEnabled(actor_addr, 3);
                //SetCollisionEnable(actor_addr,3);
            }
            catch (gg) { }
            //getActorLocation(actor_addr);
        }
        var ccc = getActorLocation(actor_addr)
        const values = Memory.readByteArray(ccc, 3 * 4);
        var z = new Float32Array(values, 8, 1)[0];//高度,Section1
        if (z > 3000)//高度大于3000则执行
        {
            try {
                //setActorHidden(actor_addr)
                //setActorCollisionEnabled(actor_addr,1)
                SetVisibility(actor_addr, 1, 0);
            }
            catch (e) { }
        }
    }
}






function main() {

    console.log("------------------------------------")

    set("libUE4.so")

    setPlayerHP();
    GetActorVrtualAdress();
    var b = getActorAddr(playerName);
    getActorLocation(b);
    //getActorLocation(b);
    //dumpActorInstances();
    //(-1569.0198974609375, -415.2847595214844, 268.3680725097656)
    //setActorLocation(b,-1500,-400,3000);

}


setImmediate(function () {
    //延迟1秒调用Hook方法
    setTimeout(main, 3000);
});
