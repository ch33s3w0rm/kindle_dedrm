# Modified: most of the code was removed.

import binascii
try:
  import hashlib
  sha1 = hashlib.sha1
  del hashlib
except ImportError:  # No hashlib in Python 2.4.
  import sha
  sha1 = sha.sha
  del sha

global charMap1
global charMap3
global charMap4

charMap3 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
charMap4 = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"

def SHA1(message):
    ctx = sha1()
    ctx.update(message)
    return ctx.digest()

# Returns two bit at offset from a bit field
def getTwoBitsFromBitField(bitField,offset):
    byteNumber = offset // 4
    bitPosition = 6 - 2*(offset % 4)
    return ord(bitField[byteNumber]) >> bitPosition & 3

# Returns the six bits at offset from a bit field
def getSixBitsFromBitField(bitField,offset):
    offset *= 3
    value = (getTwoBitsFromBitField(bitField,offset) <<4) + (getTwoBitsFromBitField(bitField,offset+1) << 2) +getTwoBitsFromBitField(bitField,offset+2)
    return value

# 8 bits to six bits encoding from hash to generate PID string
def encodePID(hash):
    global charMap3
    PID = ""
    for position in range (0,8):
        PID += charMap3[getSixBitsFromBitField(hash,position)]
    return PID

def crc32(s):
    return (~binascii.crc32(s,-1))&0xFFFFFFFF

# convert from 8 digit PID to 10 digit PID with checksum
def checksumPid(s):
    global charMap4
    crc = crc32(s)
    crc = crc ^ (crc >> 16)
    res = s
    l = len(charMap4)
    for i in (0,1):
        b = crc & 0xff
        pos = (b // l) ^ (b % l)
        res += charMap4[pos%l]
        crc >>= 8
    return res


# old kindle serial number to fixed pid
def pidFromSerial(s, l):
    global charMap4
    crc = crc32(s)
    arr1 = [0]*l
    for i in xrange(len(s)):
        arr1[i%l] ^= ord(s[i])
    crc_bytes = [crc >> 24 & 0xff, crc >> 16 & 0xff, crc >> 8 & 0xff, crc & 0xff]
    for i in xrange(l):
        arr1[i] ^= crc_bytes[i&3]
    pid = ""
    for i in xrange(l):
        b = arr1[i] & 0xff
        pid+=charMap4[(b >> 7) + ((b >> 5 & 3) ^ (b & 0x1f))]
    return pid


# Parse the EXTH header records and use the Kindle serial number to calculate the book pid.
def getKindlePid(pidlst, rec209, token, serialnum):
    # Compute book PID
    pidHash = SHA1(serialnum+rec209+token)
    bookPID = encodePID(pidHash)
    bookPID = checksumPid(bookPID)
    pidlst.append(bookPID)

    # compute fixed pid for old pre 2.5 firmware update pid as well
    bookPID = pidFromSerial(serialnum, 7) + "*"
    bookPID = checksumPid(bookPID)
    pidlst.append(bookPID)

    return pidlst
