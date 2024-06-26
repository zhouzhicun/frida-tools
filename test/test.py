



###################################### 脚本逻辑 ################################################

def load_methods(clsName, methods):
    methodArr = methods.split("\n")
    result = []

    #1.解析方法
    for method in methodArr:
        method.strip()
        if len(method) == 0:
            continue
        
        print(f"method = {method}")
        index = method.find('(')
        if index == -1:
            continue
        print(f"index = {index}")
        name = method[0: index]
        sig = method[index:]
        result.append((name, sig))

    return result



###################################### 业务实现 ################################################


#只需要修改这两个参数即可，一个是类名，一个是方法列表。
className = "com.moji.tool.AlibabaMarkJNIUtils"
methods = '''
getBoot()Ljava/lang/String;
getUpdate()Ljava/lang/String;
'''


print("reslut = ", load_methods(className, methods))