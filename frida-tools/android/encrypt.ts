



// import { FuncHandler } from "./utils/func_handle.js";
// import { ZZString } from "../base/std_string.js";


// export namespace Encrypt {

//     /*--------------------------------------  config ---------------------------------------------- */

//     export let print_config = FuncHandler.FuncPrintType.func_params


//     /*--------------------------------------  private  ---------------------------------------------- */

//     //加密模式
//     const MODE_ENCRYPT = 1;
//     const MODE_DECRYPT = 2;

//     //参数打印方式
//     const PRINT_MODE_STRING = 0x000001;
//     const PRINT_MODE_HEX = 0x000010;
//     const PRINT_MODE_BASE64 = 0x000100;

//     //获取加密模式描述
//     function getModeDesc(mode: number) {
//         let desc = ''
//         if (mode == MODE_ENCRYPT) {
//             desc = "init  | 加密模式\n"
//         }
//         else if (mode == MODE_DECRYPT) {
//             desc = "init  | 解密模式\n"
//         }
//         return desc

//     }

//     //获取bytes打印描述
//     function getParamsPrintDesc(bytes: number[], tip: string, mode: number) {

//         let desc = ''
//         if (mode & PRINT_MODE_STRING) {
//             desc += tip + "|str:" + ZZString.bytesToString(bytes) + "\n"
//         }
//         if (mode & PRINT_MODE_HEX) {
//             desc += tip + "|hex:" + ZZString.bytesToHex(bytes) + "\n"
//         }
//         if (mode & PRINT_MODE_BASE64) {
//             desc += tip + "|base64:" + ZZString.bytesToBase64(bytes) + "\n"
//         }
//         return desc
//     }


//     /*--------------------------------------  public  ---------------------------------------------- */

//     export function hook_encrypt() {

//         Java.perform(function () {


//             /************************** javax.crypto.spec.SecretKeySpec ***************************** */

//             var secretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
//             secretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (a, b) {

//                 var result = this.$init(a, b);

//                 let funcName = "javax.crypto.spec.SecretKeySpec.init([B, String)"
//                 let params = ''
//                 params += "算法名：" + b + "\n"
//                 params += getParamsPrintDesc(a, "密钥", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             /************************** javax.crypto.spec.DESKeySpec ***************************** */

//             var DESKeySpec = Java.use('javax.crypto.spec.DESKeySpec');
//             DESKeySpec.$init.overload('[B').implementation = function (a) {

//                 var result = this.$init(a);
//                 var bytes_key_des = this.getKey();

//                 let funcName = "javax.crypto.spec.DESKeySpec.init([B)"
//                 let params = ''
//                 params += getParamsPrintDesc(bytes_key_des, "des密钥", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();


//                 return result;
//             }

//             DESKeySpec.$init.overload('[B', 'int').implementation = function (a, b) {

//                 var result = this.$init(a, b);
//                 var bytes_key_des = this.getKey();

//                 let funcName = "javax.crypto.spec.DESKeySpec.init([B, int)"
//                 let params = ''
//                 params += getParamsPrintDesc(bytes_key_des, "des密钥", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             /************************** javax.crypto.Mac ***************************** */

//             var mac = Java.use('javax.crypto.Mac');
//             mac.getInstance.overload('java.lang.String').implementation = function (a) {

//                 var result = this.getInstance(a);

//                 let funcName = "javax.crypto.Mac.getInstance(string)"
//                 let params = ''
//                 params += "算法名：" + a + "\n"

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             mac.update.overload('[B').implementation = function (a) {

//                 this.update(a);

//                 let funcName = "javax.crypto.Mac.update(byte[] input)"
//                 let params = ''
//                 params += getParamsPrintDesc(a, "update input", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//             }


//             mac.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {

//                 this.update(a, b, c)

//                 let funcName = "javax.crypto.Mac.update(byte[] input, int offset, int len)"
//                 let params = ''
//                 params += getParamsPrintDesc(a, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += "offset = " + b + "\n"
//                 params += "len = " + c + "\n"

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();
//             }


//             mac.doFinal.overload().implementation = function () {

//                 var result = this.doFinal();

//                 let funcName = "javax.crypto.Mac.doFinal()"
//                 let params = ''
//                 params += getParamsPrintDesc(result, "doFinal结果", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();


//                 return result;
//             }


//             mac.doFinal.overload('[B').implementation = function (a) {

//                 var result = this.doFinal(a);


//                 let funcName = "javax.crypto.Mac.doFinal(byte[] input)"
//                 let params = ''
//                 params += getParamsPrintDesc(a, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += getParamsPrintDesc(result, "doFinal结果", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();


//                 return result;
//             }


//             /**************************  java.security.MessageDigest  ****************************** */

//             var md = Java.use('java.security.MessageDigest');
//             md.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (a, b) {

//                 let funcName = "java.security.MessageDigest.getInstance(String algorithm, String provider)"
//                 let params = ''
//                 params += "算法名：" + a + "\n"
//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return this.getInstance(a, b);
//             }


//             md.getInstance.overload('java.lang.String').implementation = function (a) {

//                 let funcName = "java.security.MessageDigest.getInstance(String algorithm)"
//                 let params = ''
//                 params += "算法名：" + a + "\n"
//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return this.getInstance(a);
//             }


//             md.update.overload('[B').implementation = function (a) {

//                 let funcName = "java.security.MessageDigest.update(byte[] input) "
//                 let params = ''
//                 params += getParamsPrintDesc(a, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return this.update(a);
//             }

//             md.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {

//                 let funcName = "java.security.MessageDigest.update(byte[] input, int offset, int len) "
//                 let params = ''
//                 params += getParamsPrintDesc(a, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += "offset = " + b + "\n"
//                 params += "len = " + c + "\n"

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return this.update(a, b, c);
//             }


//             md.digest.overload().implementation = function () {

//                 var result = this.digest();

//                 let funcName = "java.security.MessageDigest.digest()"
//                 let params = ''
//                 params += getParamsPrintDesc(result, "digest结果", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();
//                 return result;
//             }


//             md.digest.overload('[B').implementation = function (a) {

//                 var result = this.digest(a);

//                 let funcName = "java.security.MessageDigest.digest(byte[] input)"
//                 let params = ''
//                 params += getParamsPrintDesc(result, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += getParamsPrintDesc(result, "digest结果", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();


//                 return result;
//             }

//             /************************* javax.crypto.spec.IvParameterSpec ***************** */

//             var ivParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
//             ivParameterSpec.$init.overload('[B').implementation = function (a) {

//                 var result = this.$init(a);
//                 let funcName = "javax.crypto.spec.IvParameterSpec.init(byte[])"
//                 let params = ''
//                 params += getParamsPrintDesc(result, "iv向量", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();


//                 return result;
//             }

//             /******************************* javax.crypto.Cipher ******************************** */
//             var cipher = Java.use('javax.crypto.Cipher');
//             cipher.getInstance.overload('java.lang.String').implementation = function (a) {

//                 var result = this.getInstance(a);
//                 let funcName = "javax.crypto.Cipher.getInstance(String transformation) "
//                 let params = ''
//                 params += "模式填充:" + a + "\n"

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.Key').implementation = function (a, b) {

//                 var result = this.init(a, b);
//                 var bytes_key = b.getEncoded();

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Key security_key) "
//                 let params = ''
//                 params += getModeDesc(a)
//                 params += getParamsPrintDesc(bytes_key, "秘钥key", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.cert.Certificate').implementation = function (a, b) {

//                 var result = this.init(a, b);

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Certificate certificate) "
//                 let params = ''
//                 params += getModeDesc(a)
//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (a, b, c) {

//                 var result = this.init(a, b, c);
//                 var bytes_key = b.getEncoded();

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Key, AlgorithmParameterSpec)"
//                 let params = ''
//                 params += getModeDesc(a)
//                 params += getParamsPrintDesc(bytes_key, "秘钥key", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.cert.Certificate', 'java.security.SecureRandom').implementation = function (a, b, c) {

//                 var result = this.init(a, b, c);

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Certificate certificate, SecureRandom secureRandom)"
//                 let params = ''
//                 params += getModeDesc(a)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.Key', 'java.security.SecureRandom').implementation = function (a, b, c) {

//                 var result = this.init(a, b, c);
//                 var bytes_key = b.getEncoded();

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Key security_key, SecureRandom secureRandom) "
//                 let params = ''
//                 params += getModeDesc(a)
//                 params += getParamsPrintDesc(bytes_key, "秘钥key", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters').implementation = function (a, b, c) {

//                 var result = this.init(a, b, c);
//                 var bytes_key = b.getEncoded();

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Key security_key, AlgorithmParameters algorithmParameters) "
//                 let params = ''
//                 params += getModeDesc(a)
//                 params += getParamsPrintDesc(bytes_key, "秘钥key", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();
//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.Key', 'java.security.AlgorithmParameters', 'java.security.SecureRandom').implementation = function (a, b, c, d) {

//                 var result = this.init(a, b, c, d);
//                 var bytes_key = b.getEncoded();

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Key security_key, AlgorithmParameters, SecureRandom) "
//                 let params = ''
//                 params += getModeDesc(a)
//                 params += getParamsPrintDesc(bytes_key, "秘钥key", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec', 'java.security.SecureRandom').implementation = function (a, b, c, d) {

//                 var result = this.init(a, b, c, d);
//                 var bytes_key = b.getEncoded();

//                 let funcName = "javax.crypto.Cipher.init(int operation_mode, Key security_key, AlgorithmParameterSpec, SecureRandom) "
//                 let params = ''
//                 params += getModeDesc(a)
//                 params += getParamsPrintDesc(bytes_key, "秘钥key", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.update.overload('[B').implementation = function (a) {

//                 var result = this.update(a);
//                 let funcName = "javax.crypto.Cipher.update(byte[] input) "
//                 let params = ''
//                 params += getParamsPrintDesc(a, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.update.overload('[B', 'int', 'int').implementation = function (a, b, c) {

//                 var result = this.update(a, b, c);

//                 let funcName = "javax.crypto.Cipher.update(byte[] input, int inputOffset, int inputLen)"
//                 let params = ''
//                 params += getParamsPrintDesc(a, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += "offset = " + b + "\n"
//                 params += "len = " + c + "\n"

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             cipher.doFinal.overload().implementation = function () {

//                 var result = this.doFinal();
//                 let funcName = "javax.crypto.Cipher.doFinal()"
//                 let params = ''
//                 params += getParamsPrintDesc(result, "doFinal结果", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }

//             cipher.doFinal.overload('[B').implementation = function (a) {

//                 var result = this.doFinal(a);

//                 let funcName = "javax.crypto.Cipher.doFinal(byte[] input)"
//                 let params = ''
//                 params += getParamsPrintDesc(a, "input", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += getParamsPrintDesc(result, "doFinal结果", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }

//             /***************************** java.security.spec.X509EncodedKeySpec ********************************* */

//             var x509EncodedKeySpec = Java.use('java.security.spec.X509EncodedKeySpec');

//             x509EncodedKeySpec.$init.overload('[B').implementation = function (a) {

//                 var result = this.$init(a);

//                 let funcName = "java.security.spec.X509EncodedKeySpec.init(byte[] encoded_key)"
//                 let params = ''
//                 params += getParamsPrintDesc(a, "RSA密钥", PRINT_MODE_STRING | PRINT_MODE_HEX | PRINT_MODE_BASE64)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }


//             /********************************** java.security.spec.RSAPublicKeySpec ************************************ */

//             var rSAPublicKeySpec = Java.use('java.security.spec.RSAPublicKeySpec');
//             rSAPublicKeySpec.$init.overload('java.math.BigInteger', 'java.math.BigInteger').implementation = function (a, b) {

//                 var result = this.$init(a, b);

//                 let funcName = "java.security.spec.X509EncodedKeySpec.init(BigInteger modulus, BigInteger public_exponent) "
//                 let params = ''
//                 params += "RSA密钥 modulus:" + a.toString(16) + "\n"
//                 params += "RSA密钥 public_exponent:" + b.toString(16) + "\n"

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }

//             /***********************************  java.security.KeyPairGenerator ********************************* */

//             var KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
//             KeyPairGenerator.generateKeyPair.implementation = function () {

//                 var result = this.generateKeyPair();
//                 var bytes_private = result.getPrivate().getEncoded();
//                 var bytes_public = result.getPublic().getEncoded();

//                 let funcName = "java.security.KeyPairGenerator.generateKeyPair() "
//                 let params = ''
//                 params += getParamsPrintDesc(bytes_public, "公钥", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += getParamsPrintDesc(bytes_private, "私钥", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();

//                 return result;
//             }

//             KeyPairGenerator.genKeyPair.implementation = function () {

//                 var result = this.genKeyPair();

//                 var bytes_private = result.getPrivate().getEncoded();
//                 var bytes_public = result.getPublic().getEncoded();

//                 let funcName = "java.security.KeyPairGenerator.genKeyPair() "
//                 let params = ''
//                 params += getParamsPrintDesc(bytes_public, "公钥", PRINT_MODE_STRING | PRINT_MODE_HEX)
//                 params += getParamsPrintDesc(bytes_private, "私钥", PRINT_MODE_STRING | PRINT_MODE_HEX)

//                 new FuncHandler.JavaFuncHandler(print_config, funcName, function () {
//                     console.log(FuncHandler.logTips.funcParams + params)
//                 }).print();


//                 return result;
//             }
//         });

//     }

// }



