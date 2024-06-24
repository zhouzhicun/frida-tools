
import { HookFuncHandler } from "../../base/HookFuncHandler.js";

export namespace AndHttps {


    /*--------------------------------------  config ---------------------------------------------- */

    export let print_config = HookFuncHandler.FuncPrintType.func_name


    /*--------------------------------------  public ---------------------------------------------- */


    export function hook_https() {
        hook_url_connection()
        hook_retrofit()
        hook_okhttp3()

    }

    export function hook_url_connection() {

        Java.perform(function () {

            //hook java.net.URL
            var URL = Java.use('java.net.URL')
            URL.$init.overload('java.lang.String').implementation = function (urlstr: any) {

                var result = this.$init(urlstr)

                let funcName = "java.net.URL.init()"
                let params = ''
                params += 'url = '+ urlstr
    
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function () {
                    console.log(HookFuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }
            URL.openConnection.overload().implementation = function () {
                var result = this.openConnection()
     
                let funcName = "java.net.URL.openConnection()"
                let params = ''
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(HookFuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }

            var HttpURLConnectionImpl = Java.use('com.android.okhttp.internal.huc.HttpURLConnectionImpl')
            HttpURLConnectionImpl.setRequestProperty.implementation = function (key: any, value: any) {
                var result = this.setRequestProperty(key, value)


                let funcName = "com.android.okhttp.internal.huc.HttpURLConnectionImpl.setRequestProperty(String field, String newValue)"
                let params = ''
                params += `key = ${key}, value = ${value}`
    
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function () {
                    console.log(HookFuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }
        })
    }



    export function hook_retrofit() {

        Java.perform(function () {
            var RetrofitBuilder = Java.use("retrofit2.Retrofit$Builder")
            RetrofitBuilder.baseUrl.overload('java.lang.String').implementation = function (url: string) {

                var result = this.baseUrl(url);
                let funcName = "retrofit2.Retrofit$Builder.baseUrl(String url)"
                let params = ''
                params += `url = ${url}`
    
                new HookFuncHandler.JavaFuncHandler(print_config, funcName, function () {
                    console.log(HookFuncHandler.logTips.funcParams + params)
                }).print();

                return result;
            }
            RetrofitBuilder.baseUrl.overload('okhttp3.HttpUrl').implementation = function (url: string) {

                var result = this.baseUrl(url);
                let funcName = "retrofit2.Retrofit$Builder.baseUrl(HttpUrl url)"
                let params = ''
                params += `url = ${url}`
                return result;
            }
        })
    }


    export function hook_okhttp3() {

    }

}