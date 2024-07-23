

import struct
import codecs

def printFloat(bytes):
    hexfloat = ''.join(format(x, '02x') for x in byteArray)
    print(struct.unpack('<f', codecs.decode(hexfloat, 'hex_codec'))[0])

byteArray = [0x26, 0x00, 0x82, 0xc3]
byteArray = [0x00, 0x00, 0xa0, 0x42]
byteArray = [0xfa, 0x3f, 0x86, 0x43]
printFloat(byteArray)
