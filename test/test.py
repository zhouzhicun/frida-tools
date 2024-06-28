



# ###################################### 脚本逻辑 ################################################

# def load_methods(clsName, methods):
#     methodArr = methods.split("\n")
#     result = []

#     #1.解析方法
#     for method in methodArr:
#         method.strip()
#         if len(method) == 0:
#             continue
        
#         print(f"method = {method}")
#         index = method.find('(')
#         if index == -1:
#             continue
#         print(f"index = {index}")
#         name = method[0: index]
#         sig = method[index:]
#         result.append((name, sig))

#     return result



# ###################################### 业务实现 ################################################


# #只需要修改这两个参数即可，一个是类名，一个是方法列表。
# className = "com.moji.tool.AlibabaMarkJNIUtils"
# methods = '''
# getBoot()Ljava/lang/String;
# getUpdate()Ljava/lang/String;
# '''


# print("reslut = ", load_methods(className, methods))




message = "helloworld"

# 初始化一个空字符串，用于存储消息的二进制表示
messageLength = ""

# 预处理
# 遍历消息中的每个字符
for char in range(len(message)):
    # 将每个字符转换为其ASCII值的8位二进制表示，并添加到messageLength字符串
    messageLength += '{0:08b}'.format(ord(message[char]))

print("len = ", messageLength)


# 保存当前的messageLength，稍后需要用到
temp = messageLength

# 在消息的二进制表示后面添加一个'1'
messageLength += '1'

print("len = ", messageLength)

# 添加'0'，直到消息的长度（以位为单位）模512等于448
while (len(messageLength) % 512 != 448):
    messageLength += '0'

print("len = ", messageLength)

# 添加一个64位的二进制数，表示原始消息的长度（以位为单位）
messageLength += '{0:064b}'.format(len(temp))


print("len = ", messageLength)






