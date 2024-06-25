
IDA插件：
需要放置到 ida/plugins目录下.

IDA脚本：
执行方式有三种：
方式1(推荐)：IDA -> File -> Script File
选中脚本文件直接运行；修改脚本需要先在编辑器中修改好。支持脚本文件导入其他python文件。

方式2（推荐）：IDA -> File -> Script Command
选择导入脚本文件，然后点击Run运行；可支持脚本编辑，且支持脚本文件导入其他python文件。

方式3（不推荐）：复制脚本文件，粘贴到IDA底部的python输入栏.


工程模块化：
将公共逻辑封装起来，放到util目录下，其他脚本或者插件实现直接import进行复用。

