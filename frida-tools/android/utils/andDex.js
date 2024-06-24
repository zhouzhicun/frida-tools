/***
 * 由于ts文件格式下 Java.classFactory.loader 无法赋值，因此改为js文件。
 */


export function load_dex(path) {

    //例如动态加载 okhttp3logging.dex:  path = "/data/local/tmp/okhttp3logging.dex"
    Java.perform(function () {
        Java.openClassFile(path).load();
    });

}

/**
 * 已完成动态加载的情况下， hook指定Java类; 具体hook操作在callback函数中实现。
 * 
 * @param {*} clsName 类名
 * @param {*} callback 回调函数
 */
export function hook_dynamic_dex(clsName, callback) {

    Java.perform(function () {

        var oldLoader = null

        //1.枚举classLoader，找到加载指定class的classLoader
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    if (loader.findClass(clsName)) {
                        //重置loader
                        oldLoader = Java.classFactory.loader;
                        Java.classFactory.loader = loader;
                        console.log(loader);
                    }
                } catch (error) { }

            }, onComplete: function () {

            }
        });

        //2.对指定class进行hook
        callback()

        //3.还原loader
        Java.classFactory.loader = oldLoader

    });
}


/**
 * 解决dex不知何时加载的情况下，hook指定Java类; 具体hook操作在callback函数中实现。
 * 
 * @param {*} clsName 类名
 * @param {*} callback 回调函数
 */
export function hook_memory_dex_class_loader(callback) {

    const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
    InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (buff, loader) {

        this.$init(buff, loader);
        var oldLoader = Java.classFactory.loader;
        Java.classFactory.loader = this;
        callback();
        Java.classFactory.loader = oldLoader;
        return undefined;
    }
}
