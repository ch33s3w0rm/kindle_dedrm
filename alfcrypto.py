#! /usr/bin/env python
# modified

import sys, os
import hmac
from struct import pack
import hashlib


# interface to needed routines libalfcrypto
def _load_libalfcrypto():
    import ctypes
    from ctypes import CDLL, byref, POINTER, c_void_p, c_char_p, c_int, c_long, \
        Structure, c_ulong, create_string_buffer, addressof, string_at, cast, sizeof

    pointer_size = ctypes.sizeof(ctypes.c_voidp)
    name_of_lib = None
    if sys.platform.startswith('darwin'):
        name_of_lib = 'libalfcrypto.dylib'
    elif sys.platform.startswith('win'):
        if pointer_size == 4:
            name_of_lib = 'alfcrypto.dll'
        else:
            name_of_lib = 'alfcrypto64.dll'
    else:
        if pointer_size == 4:
            name_of_lib = 'libalfcrypto32.so'
        else:
            name_of_lib = 'libalfcrypto64.so'
    
    libalfcrypto = sys.path[0] + os.sep + name_of_lib

    if not os.path.isfile(libalfcrypto):
        raise Exception('libalfcrypto not found')

    libalfcrypto = CDLL(libalfcrypto)

    c_char_pp = POINTER(c_char_p)
    c_int_p = POINTER(c_int)


    def F(restype, name, argtypes):
        func = getattr(libalfcrypto, name)
        func.restype = restype
        func.argtypes = argtypes
        return func

    # Pukall 1 Cipher
    # unsigned char *PC1(const unsigned char *key, unsigned int klen, const unsigned char *src,
    #                unsigned char *dest, unsigned int len, int decryption);

    PC1 = F(c_char_p, 'PC1', [c_char_p, c_ulong, c_char_p, c_char_p, c_ulong, c_ulong])

    # Topaz Encryption
    # typedef struct _TpzCtx {
    #    unsigned int v[2];
    # } TpzCtx;
    #
    # void topazCryptoInit(TpzCtx *ctx, const unsigned char *key, int klen);
    # void topazCryptoDecrypt(const TpzCtx *ctx, const unsigned char *in, unsigned char *out, int len);

    class TPZ_CTX(Structure):
        _fields_ = [('v', c_long * 2)]

    TPZ_CTX_p = POINTER(TPZ_CTX)
    topazCryptoInit = F(None, 'topazCryptoInit', [TPZ_CTX_p, c_char_p, c_ulong])
    topazCryptoDecrypt = F(None, 'topazCryptoDecrypt', [TPZ_CTX_p, c_char_p, c_char_p, c_ulong])

    class Pukall_Cipher(object):
        def __init__(self):
            self.key = None

        def PC1(self, key, src, decryption=True):
            self.key = key
            out = create_string_buffer(len(src))
            de = 0
            if decryption:
                de = 1
            rv = PC1(key, len(key), src, out, len(src), de)
            return out.raw

    class Topaz_Cipher(object):
        def __init__(self):
            self._ctx = None

        def ctx_init(self, key):
            tpz_ctx = self._ctx = TPZ_CTX()
            topazCryptoInit(tpz_ctx, key, len(key))
            return tpz_ctx

        def decrypt(self, data,  ctx=None):
            if ctx == None:
                ctx = self._ctx
            out = create_string_buffer(len(data))
            topazCryptoDecrypt(ctx, data, out, len(data))
            return out.raw

    print "Using Library AlfCrypto DLL/DYLIB/SO."
    return (Pukall_Cipher, Topaz_Cipher)


def _load_python_alfcrypto():

    class Pukall_Cipher(object):
        def __init__(self):
            self.key = None

        def PC1(self, key, src, decryption=True):
            sum1 = 0;
            sum2 = 0;
            keyXorVal = 0;
            if len(key)!=16:
                print "Bad key length!"
                return None
            wkey = []
            for i in xrange(8):
                wkey.append(ord(key[i*2])<<8 | ord(key[i*2+1]))
            dst = ""
            for i in xrange(len(src)):
                temp1 = 0;
                byteXorVal = 0;
                for j in xrange(8):
                    temp1 ^= wkey[j]
                    sum2  = (sum2+j)*20021 + sum1
                    sum1  = (temp1*346)&0xFFFF
                    sum2  = (sum2+sum1)&0xFFFF
                    temp1 = (temp1*20021+1)&0xFFFF
                    byteXorVal ^= temp1 ^ sum2
                curByte = ord(src[i])
                if not decryption:
                    keyXorVal = curByte * 257;
                curByte = ((curByte ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF
                if decryption:
                    keyXorVal = curByte * 257;
                for j in xrange(8):
                    wkey[j] ^= keyXorVal;
                dst+=chr(curByte)
            return dst

    class Topaz_Cipher(object):
        def __init__(self):
            self._ctx = None

        def ctx_init(self, key):
            ctx1 = 0x0CAFFE19E
            for keyChar in key:
                keyByte = ord(keyChar)
                ctx2 = ctx1
                ctx1 = ((((ctx1 >>2) * (ctx1 >>7))&0xFFFFFFFF) ^ (keyByte * keyByte * 0x0F902007)& 0xFFFFFFFF )
            self._ctx = [ctx1, ctx2]
            return [ctx1,ctx2]

        def decrypt(self, data,  ctx=None):
            if ctx == None:
                ctx = self._ctx
            ctx1 = ctx[0]
            ctx2 = ctx[1]
            plainText = ""
            for dataChar in data:
                dataByte = ord(dataChar)
                m = (dataByte ^ ((ctx1 >> 3) &0xFF) ^ ((ctx2<<3) & 0xFF)) &0xFF
                ctx2 = ctx1
                ctx1 = (((ctx1 >> 2) * (ctx1 >> 7)) &0xFFFFFFFF) ^((m * m * 0x0F902007) &0xFFFFFFFF)
                plainText += chr(m)
            return plainText

    print "Using slow Python AlfCrypto implementation."
    return (Pukall_Cipher, Topaz_Cipher)


Pukall_Cipher, Topaz_Cipher, is_slow = None, None, None

def load_crypto():
    """Initialize Pukall_Cipher and Topaz_Cipher.

    It is a no-op if called again.
    """
    global Pukall_Cipher, Topaz_Cipher, is_slow
    if Pukall_Cipher is not None:
      return
    cryptolist = (_load_libalfcrypto, _load_python_alfcrypto)
    for loader in cryptolist:
        try:
            Pukall_Cipher, Topaz_Cipher = loader()
            break
        except (ImportError, Exception), e:
            print '%s: %s: %s' % (loader.func_name, e.__class__.__name__, e)
            if loader == _load_python_alfcrypto:
                raise
    is_slow = loader == _load_python_alfcrypto
    assert Pukall_Cipher
    assert Topaz_Cipher
