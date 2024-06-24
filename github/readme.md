
## frida_hook_libart
仓库地址：https://github.com/lasting-yang/frida_hook_libart

使用：
frida -U -f package_name -l hook_art.js
frida -U -f package_name -l hook_RegisterNatives.js
frida -U -f package_name -l hook_artmethod.js -o hook_artmethod.log


## Frida-Sigaction-Seccomp
仓库地址：https://github.com/LLeavesG/Frida-Sigaction-Seccomp
使用：
控制台窗口1（运行脚本）：frida -U -f com.moji.mjweather -l sigaction.js
控制台窗口2（查看日志）：adb shell logcat | grep native


