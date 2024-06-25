
网络相关的frida脚本来源于:
https://github.com/r0ysue/AndroidFridaBeginnersBook

## 注意事项
1.hook okhttp3的时候，如果调用 hook_okhttp3_interceptor_dex 进行hook，
需要先将 okhttplogging.dex 文件复制到手机的 /data/local/tmp/okhttp3logging.dex 目录。

2.objection批量hook：
objection -g com.jianshu.haruki explore -c "SocketInit.txt"