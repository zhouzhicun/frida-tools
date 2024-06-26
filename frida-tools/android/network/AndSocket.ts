
import { HookFuncHandler } from "../../base/HookFuncHandler.js";
import { StringUtils } from "../../base/StringUtils.js";

export namespace AndSocket {

    /*--------------------------------------  config ---------------------------------------------- */

    export let print_config = HookFuncHandler.FuncPrintType.func_name



    /*--------------------------------------  private ---------------------------------------------- */




    function dumpByteArr(array: any) {

        // var hexstr = StringUtils.bytesToHex(array)
        // console.log(hexstr)

        var ptr = Memory.alloc(array.length);
        var temp = ptr;
        for (var i = 0; i < array.length; ++i) {
            temp.add(i)
            temp.writeS8(array[i])
        }
        console.log(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
    }





    /*--------------------------------------  public ---------------------------------------------- */

    export function hook_socket() {
        hook_socket_address()
        hook_socket_stream()
        hook_ssl_socket_android8()
    }

    export function hook_socket_address() {

        Java.perform(function () {

            Java.use('java.net.InetSocketAddress').$init.overload('java.net.InetAddress', 'int').implementation = function (addr: any, port: any) {

                var result = this.$init(addr, port)

                let funcName = "java.net.InetSocketAddress.InetSocketAddress(java.net.InetAddress, int) "
                let params = ''
                params += "addr =>", addr.toString(), "port =>", port
    
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function () {
                    console.log(HookFuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }
        })
    }


    export function hook_socket_stream() {

        Java.perform(function () {


            Java.use('java.net.SocketOutputStream').socketWrite.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                
                var result = this.socketWrite(bytearray1, int1, int2)

                let funcName = "java.net.SocketOutputStream.socketWrite([B, int, int)"
                let params = `result = ${result}, bytearray1 = ${StringUtils.bytesToHex(bytearray1)}, int1 = ${int1}, int2 = ${int2}`
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(HookFuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }

            Java.use('java.net.SocketInputStream').read.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                
                var result = this.read(bytearray1, int1, int2)

                let funcName = "java.net.SocketInputStream.socketRead0([B, int, int)"
                let params = `result = ${result}, bytearray1 = ${StringUtils.bytesToHex(bytearray1)}, int1 = ${int1}, int2 = ${int2}`

                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(HookFuncHandler.logTips.funcParams + params)
                    dumpByteArr(bytearray1)
                }).print();


                return result
            }
        })

    }

    export function hook_ssl_socket_android8() {

        Java.perform(function () {


            Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream').write.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                
                var result = this.write(bytearray1, int1, int2)

                let funcName = "ConscryptFileDescriptorSocket$SSLOutputStream.write([B, int, int)"
                let params = `result = ${result}, bytearray1 = ${StringUtils.bytesToHex(bytearray1)}, int1 = ${int1}, int2 = ${int2}`

                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(HookFuncHandler.logTips.funcParams + params)
                    dumpByteArr(bytearray1)
                }).print();

                return result
            }


            Java.use('com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream').read.overload('[B', 'int', 'int').implementation = function (bytearray1: any, int1: any, int2: any) {
                
                var result = this.read(bytearray1, int1, int2)

                let funcName = "ConscryptFileDescriptorSocket$SSLInputStream.read([B, int, int)"
                let params = `result = ${result}, bytearray1 = ${StringUtils.bytesToHex(bytearray1)}, int1 = ${int1}, int2 = ${int2}`

                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(HookFuncHandler.logTips.funcParams + params)
                    dumpByteArr(bytearray1)
                }).print();


                return result
            }
        })
    }


}
