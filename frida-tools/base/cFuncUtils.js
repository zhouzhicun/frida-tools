
/**
 * 
 * 由于ts的类型系统限制，parseFuncPrototype解析函数原型得到的returnType和paramTypes
 * 在创建NativeFunction和NativeCallback时会报错，因此该文件采用js实现。
 * 
 * libc函数列表：
 * https://gist.github.com/PewZ/8b473c2a6888c5c528635550d07c6186
 * 
 */


/**
 * 解析C函数原型，仅供参考
 * 返回：参数类型数组和返回值类型
 * 
*/
export function parseFuncPrototype(prototype) {
    
    const prototypeRegex = /(\S+)\s+(\S+)\s*\((.*?)\)/;

    const match = prototype.match(prototypeRegex);
    if (!match) {
        throw new Error(`Invalid C function prototype  ==> ${prototype} `);
    }

    let returnType = match[1];
    let functionName = match[2];
    if (returnType.indexOf('*') || functionName.indexOf('*')) {
        returnType = "pointer"
    }

    let paramTypes = match[3].split(',').map(param => {
        if (param.indexOf('*') != -1) {
            return 'pointer'
        } else {
            return param.trim().split(' ')[0]
        }
    });

    return [returnType, paramTypes]
}


