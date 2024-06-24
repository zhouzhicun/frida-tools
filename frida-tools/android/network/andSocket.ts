
import { HookFuncHandler } from "../../base/hookFuncHandle";

export namespace AndSocket {

    /*--------------------------------------  config ---------------------------------------------- */

    export let print_config = HookFuncHandler.FuncPrintType.func_name



    /*--------------------------------------  private ---------------------------------------------- */




    function jhexdump(array: any) {
        // var ptr = Memory.alloc(array.length);
        // for (var i = 0; i < array.length; ++i)
        //     Memory.writeS8(ptr.add(i), array[i]);
        // //console.log(hexdump(ptr, { offset: off, length: len, header: false, ansi: false }));
        // console.log(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
    }





    /*--------------------------------------  public ---------------------------------------------- */

    export function hook_socket() {
        hook_socket_address()
        hook_socket_stream()
        hook_ssl_socket_android8()
    }

    export function hook_socket_address() {

        Java.perform(function () {
            // java.net.InetSocketAddress.InetSocketAddress(java.net.InetAddress, int)
            Java.use('java.net.InetSocketAddress').$init.overload('java.net.InetAddress', 'int').implementation = function (addr: any, port: any) {

                var result = this.$init(addr, port)

                // new Utils.FuncHandler(get_config(), function(){
                //     console.log("[*] hook_func => java.net.InetSocketAddress.init(address, port)")
                // }, function(){
                //     console.log("addr =>", addr.toString(), "port =>", port)
                // }, function(){
                //     Utils.print_java_callstacks()
                // }).print()
        
                return result
            }
        })
    }


    export function hook_socket_stream() {

        Java.perform(function () {

            // java.net.SocketOutputStream.write
            // java.net.SocketOutputStream.socketWrite
            Java.use('java.net.SocketOutputStream').socketWrite.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                
                var result = this.socketWrite(bytearray1, int1, int2)

                let funcName = "java.net.SocketOutputStream.socketWrite([B, int, int)"
                let params = `result = ${result}, bytearray1 = ${bytearray1}, int1 = ${int1}, int2 = ${int2}`
    
                //以下代码固定，只需修改上面的funcName、params
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(HookFuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }

            // java.net.SocketInputStream.read
            // java.net.SocketInputStream.socketRead0
            Java.use('java.net.SocketInputStream').read.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                
                var result = this.read(bytearray1, int1, int2)

                let funcName = "java.net.SocketInputStream.socketRead0([B, int, int)"
                let params = `result = ${result}, bytearray1 = ${bytearray1}, int1 = ${int1}, int2 = ${int2}`
    
                //以下代码固定，只需修改上面的funcName、params
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(HookFuncHandler.logTips.funcParams + params)
                    jhexdump(bytearray1)
                    //var ByteString = Java.use("com.android.okhttp.okio.ByteString");
                    // console.log('contents: => ', ByteString.of(bytearray1).hex())
                }).print();


                return result
            }
        })

    }

    export function hook_ssl_socket_android8() {

        Java.perform(function () {

            // com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream.write
            Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream').write.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                var result = this.write(bytearray1, int1, int2)

                console.log('write result,bytearray1,int1,int2=>', result, bytearray1, int1, int2)

                var ByteString = Java.use("com.android.okhttp.okio.ByteString");
                console.log('contents: => ', ByteString.of(bytearray1).hex())

                return result
            }

            // com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream.read
            Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream').read.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                var result = this.read(bytearray1, int1, int2)

                console.log('read result,bytearray1,int1,int2=>', result, bytearray1, int1, int2)

                var ByteString = Java.use("com.android.okhttp.okio.ByteString");
                //console.log('contents: => ', ByteString.of(bytearray1).hex())
                jhexdump(bytearray1)


                return result
            }
        })
    }


}
