



    /******************* bytes 与 字符串 互转  ************************/

    //bytes转字符串
    function bytesToString(bytes) {
        return bytes.map(byte => String.fromCharCode(byte)).join('')
    }

    //字符串转bytes
     function stringToBytes(str) {
        return hexToBytes(stringToHex(str))
    }


    /******************* hex字符串 与 字符串 互转  ************************/


    //hex字符串转字符串
     function hexToString(hexStr) {
        let hex = hexStr.toString()
        let str = ''
        for (let i = 0; i < hex.length; i += 2) str += String.fromCharCode(parseInt(hex.substr(i, 2), 16))
        return str
    }

    //字符串转hex
     function stringToHex(str) {
        return str
            .split('')
            .map(function (c) {
                return ('0' + c.charCodeAt(0).toString(16)).slice(-2)
            })
            .join('')
    }



    /******************* hex字符串 与 bytes 互转  ************************/

    //hex字符串转bytes
     function hexToBytes(hexStr) {
        let bytes= [] 
        for (let c = 0; c < hexStr.length; c += 2) bytes.push(parseInt(hexStr.substr(c, 2), 16))
        return bytes
    }

    //bytes转hex字符串
     function bytesToHex(bytes) {
        return bytes.map(byte => ('00' + (byte & 0xFF).toString(16)).slice(-2)).join('')
    }


// var str = "hello world";

// console.log("str:", str);

// var bytes = stringToBytes(str);
// var hex = stringToHex(str);

// console.log(`stringToBytes = ${bytes}`)
// console.log(`stringToHex = ${hex}`)

// console.log(`bytesToHex = ${bytesToHex(bytes)}`)
// console.log(`bytesToString = ${bytesToString(bytes)}`)

// console.log(`hexToBytes = ${hexToBytes(hex)}`)
// console.log(`hexToString = ${hexToString(hex)}`)


// var base64 = btoa(bytesToString(bytes))
// console.log(`base64 = ${base64}`)

// var bytesaa = stringToBytes(atob(base64))
// console.log(`bytesaa = ${bytesaa}`)


var hex = "9511168d 393ceaee efb4ed6c 03c60941"
hex = hex.replace(/\s/g, '');
console.log("hex = ", hex)
for (let i = 0; i < hex.length; i += 8) {
    let subStr = hex.substring(i, i + 8);
    let hexNumber = parseInt(subStr, 16);
    console.log("sub = ", subStr, "hexNumber = ", hexNumber, "hex = ", hexNumber.toString(16));
}