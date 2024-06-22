
import { FuncHandler } from "./utils/funchandle.js";

export namespace Https {


    /*--------------------------------------  config ---------------------------------------------- */

    export let print_config = FuncHandler.FuncPrintType.func_name


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
                let params = 'url = '+ urlstr
    
                //以下代码固定，只需修改上面的funcName、params
                new FuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(FuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }
            URL.openConnection.overload().implementation = function () {
                var result = this.openConnection()
     
                let funcName = "java.net.URL.openConnection()"
                let params = ''
    
                //以下代码固定，只需修改上面的funcName、params
                new FuncHandler.JavaFuncHandler(print_config, funcName, function(){
                    console.log(FuncHandler.logTips.funcParams + params)
                }).print();

                return result
            }

            //hook com.android.okhttp.internal.huc.HttpURLConnectionImpl
            var HttpURLConnectionImpl = Java.use('com.android.okhttp.internal.huc.HttpURLConnectionImpl')
            HttpURLConnectionImpl.setRequestProperty.implementation = function (key: any, value: any) {
                var result = this.setRequestProperty(key, value)
                console.log('setRequestProperty => ', key, ':', value)
                return result
            }
        })
    }



    export function hook_retrofit() {

        Java.perform(function () {
            var RetrofitBuilder = Java.use("retrofit2.Retrofit$Builder")
            RetrofitBuilder.baseUrl.overload('java.lang.String').implementation = function (str: string) {
                console.log("Entering 1")
                var result = this.baseUrl(str);
                console.log("result,str=>", result, str)
                return result;
            }
            RetrofitBuilder.baseUrl.overload('okhttp3.HttpUrl').implementation = function (str: string) {
                console.log("Entering 1")
                var result = this.baseUrl(str);
                console.log("result,str=>", result, str)
                return result;
            }
        })
    }


    export function hook_okhttp3() {

    }

}