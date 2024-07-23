


function hookEncrypt(soName: string, funcAddr: number[]) {
    
    let moduleBase = Module.findBaseAddress(soName)
    for(let addr of funcAddr){
        Interceptor.attach(moduleBase.add(addr), {
            onEnter: function () {
            },
            onLeave: function (retval) {
                let str = retval.readCString()
                console.log("str = " + str + "; len = " + str.length);
            }
        });
    }

}