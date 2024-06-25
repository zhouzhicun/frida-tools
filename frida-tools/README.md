### How to compile & load

```sh
$ git clone git://github.com/oleavr/frida-agent-example.git
$ cd frida-agent-example/
$ npm install
$ frida -U -f com.example.android --no-pause -l _agent.js
```

### Development workflow

To continuously recompile on change, keep this running in a terminal:

```sh
$ npm run watch
```

And use an editor like Visual Studio Code for code completion and instant
type-checking feedback.



### 注意事项

运行的时候，建议在命令后面加上: -o xxx.log, 例如：
frida -U -f com.example.android --no-pause -l _agent.js -o xxx.log
原因:
将日志打印到 xxx.log文件中，因为直接打到控制台，可能日志顺序混乱，并且刷的太快导致没法看。


### 工程规范(待补充！！！)

