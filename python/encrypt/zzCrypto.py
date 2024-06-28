

import hashlib
import hmac
import base64

# pip uninstall crypto
# pip uninstall pycryptodome
# pip install pycryptodome
from Crypto.Cipher import AES


import encryptUtils as eu

class ZZCrypto:

############################ Base系列: 支持base16,32, 64, 85  ############################

    @classmethod
    def base16_encode(cls, data):
        return eu.data_to_str(base64.b16encode(data))

    @classmethod
    def base32_encode(cls, data):
        return eu.data_to_str(base64.b32encode(data))

    @classmethod
    def base64_encode(cls, data):
        return eu.data_to_str(base64.b64encode(data))

    @classmethod
    def base85_encode(cls, data):
        return eu.data_to_str(base64.b85encode(data))
    


    @classmethod
    def base16_decode(cls, str):
        return base64.b16decode(eu.str_to_data(str))
    
    @classmethod
    def base32_decode(cls, str):
        return base64.b32decode(eu.str_to_data(str))
    
    
    @classmethod
    def base64_decode(cls, str):
        return base64.b64decode(eu.str_to_data(str))
    
    @classmethod
    def base85_decode(cls, str):
        return base64.b85decode(eu.str_to_data(str))
    


############################ sha系列  ############################

    #MD5：传入data, 返回字符串
    @classmethod
    def md5(cls, data):
        m = hashlib.md5()
        m.update(data)
        return m.hexdigest()
        
    @classmethod
    def sha1(cls, data):
        sha = hashlib.sha1()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha2_224(cls, data):
        sha = hashlib.sha224()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha2_256(cls, data):
        sha = hashlib.sha256()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha2_384(cls, data):
        sha = hashlib.sha384()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha2_512(cls, data):
        sha = hashlib.sha512()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha3_224(cls, data):
        sha = hashlib.sha3_224()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha3_256(cls, data):
        sha = hashlib.sha3_256()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha3_384(cls, data):
        sha = hashlib.sha3_384()
        sha.update(data)
        return sha.hexdigest()
    
    @classmethod
    def sha3_512(cls, data):
        sha = hashlib.sha3_512()
        sha.update(data)
        return sha.hexdigest()
    

############################ hmac系列  ############################

    @classmethod
    def hmac_md5(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.md5)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha1(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha1)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha2_224(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha224)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha2_256(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha256)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha2_384(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha384)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha2_512(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha512)
        return mac.hexdigest()
    

    @classmethod
    def hmac_sha3_224(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha3_224)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha3_256(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha3_256)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha3_384(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha3_384)
        return mac.hexdigest()
    
    @classmethod
    def hmac_sha3_512(cls, keyData, data):
        mac = hmac.new(keyData, data, hashlib.sha3_512)
        return mac.hexdigest()
    
    

    


# ####################################################################################

#     # AES加密方法, 传入data, 返回Base64字符串; 如果需要iv(),
#     @classmethod
#     def aes_encrypt(cls, keyData, plainData, mode=AES.MODE_ECB, ivData=None):
#         if ivData is not None:
#             ivData = pad_to_16_data(ivData)
#         aes = AES.new(pad_to_16_data(keyData), mode, iv=ivData)
#         encrypt_aes = aes.encrypt(pad_to_16_data(plainData))
#         encrypted_text = data_to_str(base64.encodebytes(encrypt_aes))
#         return encrypted_text

#     # AES解密方法: 传入data, 返回Base64字符串
#     @classmethod    
#     def aes_decrypt(cls, keyData, cipherData, mode=AES.MODE_ECB, ivData=None):
#         if ivData is not None:
#             ivData = pad_to_16_data(ivData)
#         aes = AES.new(pad_to_16_data(keyData), mode, iv=ivData) 
#         base64_decrypted = base64.decodebytes(pad_to_16_data(cipherData)) 
#         decrypted_text = data_to_str(aes.decrypt(base64_decrypted)).replace('\0', '')
#         return decrypted_text




##################################### 加解密demo #############################################



print("========================== base编码与反编码系列 ===============================")

strData = b"hello, world"

a16 = ZZCrypto.base16_encode(strData)
a32 = ZZCrypto.base32_encode(strData)
a64 = ZZCrypto.base64_encode(strData)
a85 = ZZCrypto.base85_encode(strData)
print("a16 = ", a16)
print("a32 = ", a32)
print("a64 = ", a64)
print("a85 = ", a85)

b16 = ZZCrypto.base16_decode(a16)
b32 = ZZCrypto.base32_decode(a32)
b64 = ZZCrypto.base64_decode(a64)
b85 = ZZCrypto.base85_decode(a85)
print("a16 = ", b16)
print("a32 = ", b32)
print("a64 = ", b64)
print("a85 = ", b85)

print("========================== sha系列 ===============================")



c1 = ZZCrypto.sha1(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha2_224(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha2_256(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha2_384(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha2_512(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha3_224(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha3_256(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha3_384(strData)
print("c1 = ", c1)
c1 = ZZCrypto.sha3_512(strData)
print("c1 = ", c1)

print("========================== hmac系列 ===============================")

keyData = b"123456"
strData = b"hello, world"

c1 = ZZCrypto.hmac_md5(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha1(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha2_224(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha2_256(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha2_384(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha2_512(keyData, strData)
print("c1 = ", c1)

c1 = ZZCrypto.hmac_sha3_224(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha3_256(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha3_384(keyData, strData)
print("c1 = ", c1)
c1 = ZZCrypto.hmac_sha3_512(keyData, strData)
print("c1 = ", c1)






