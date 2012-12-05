#! /usr/bin/env python
# modified

# TODO: Use base64 or something more compact than hex.
#
# For your reference, see the source code in alfcrypto.c.
MACHINE32 = {
    'topazCryptoInit': 0x0,
    'topazCryptoDecrypt': 0x60,
    'PC1': 0xc0,
    'cmp': 0x1fa,
    'code':
    '5589e58b4510578b7d0c568b75085385c0c7069ee1ffca7e38b89ee1ffca31d2bb9ee1'
    'ffca8d76008946040fb6041789d9c1e90783c201c1eb020fafcb0fafc069c00720900f'
    '31c83b551089c3890675d75b5e5f5dc38d76008dbc27000000005589e58b55148b4508'
    '578b7d105685d2538b088b40047e4231d2eb068d74260089d989cb89cec1eb03c1e003'
    '31d88b5d0cc1ee0732041389cbc1eb020faff30fb6d80fafdb88041783c20189c869db'
    '0720900f31f33b551475c65b5e5f5dc3905531c089e557565383ec3c8b5d08837d0c10'
    '0f85f30000000fb60c430fb6544301c1e10809ca66895445d883c00183f80875e58b5d'
    '1885db0f84ae000000c745d40000000031f631db8db4260000000031c031ff31c96690'
    '0fb75445d88d343083c00169f6354e000031ca01de69ca354e000069da5a01000083c1'
    '0181e3ffff000081e1ffff000001de89ca81e6ffff000031f231d783f80875bd8b4d10'
    '8b55d40fb604118b4d1c85c9754c89c1c1e10801c131f8c1ef0831f80fb6f88d45d88d'
    '55e8908d74260066310883c00239d075f68b55d489f88b4d1488041183c20139551889'
    '55d40f8764ffffff8b451483c43c5b5e5f5dc39031f8c1ef0831f80fb6f889f9c1e108'
    '01f9ebb2a100000000c744240800000000c744240401000000890424e8fcffffffc745'
    '14000000008b451483c43c5b5e5f5dc35589e55383ec048b5d08833b0075038b5d0c8b'
    '0385c0742e5252ff7328ff7324ff7320ff731cff7318ff7314ff7310ff730cff7308ff'
    '7304ffd0c7030000000083c43089432c31c08b5dfcc9c3'.decode('hex'),
}
assert len(MACHINE32['code']) == 0x247

MACHINE64 = {
    'topazCryptoInit': 0x0,
    'topazCryptoDecrypt': 0x50,
    'PC1': 0xb0,
    'code':
    '85d2c7079ee1ffca7e3f83ea01b89ee1ffca4c8d44160189c10f1f8000000000894704'
    '0fb60689cac1ea07c1e9024883c6010fafd10fafc069c00720900f31d04c39c689c189'
    '0775d7f3c30f1f44000085c9448b078b47047e4d83e9014c8d4c0e01eb070f1f400041'
    '89c84489c1c1e0034489c7c1e903c1ef0731c832064489c1c1e9024883c6010faff90f'
    'b6c888024883c2010fafc94489c069c90720900f31f94c39ce75c1f3c30f1f80000000'
    '0041574889c831c941564155415455534883ec1883fe104989e40f8507010000900fb6'
    '340f0fb65c0f01c1e60809f36641891c0c4883c1024883f91075e34585c00f84ba0000'
    '004183e8014c8d6c24104989c64e8d7c000131db4531db0f1f40004c89e14d89e231ff'
    '31ed4531c00f1f00410fb7328d1c1f83c7014983c20269db354e00004431c64401db44'
    '69c6354e00004469de5a0100004183c0014181e3ffff00004181e0ffff00004401db44'
    '89c681e3ffff000031de31f583ff0875b14585c90fb63a754989fec1e60801fe31efc1'
    'ed0831ef81e7ff0000000f1f4400006631314883c1024c39e975f441883e4983c60148'
    '83c2014d39fe0f8560ffffff4883c4185b5d415c415d415e415fc39031efc1ed0831ef'
    '81e7ff00000089fec1e60801feebba488b3d00000000ba00000000be0100000031c0e8'
    '000000004883c41831c05b5d415c415d415e415fc3'.decode('hex'),
}
assert len(MACHINE64['code']) == 0x1ff

MACHINE64WIN = {
    'topazCryptoInit': 0x0,
    'topazCryptoDecrypt': 0x60,
    'PC1': 0xd0,
    'code':
    '4883ec084585c0c7019ee1ffca7e404183e801b89ee1ffca4e8d5402014189c1894104'
    '0fb6024589c841c1e80741c1e9024883c201450fafc10fafc069c00720900f4431c04c'
    '39d24189c1890175d14883c408c36666662e0f1f8400000000004883ec084585c9448b'
    '118b41047e544183e9014e8d5c0a01eb09660f1f4400004189ca4489d1c1e0034589d1'
    'c1e90341c1e90731c832024489d1c1e9024883c201440fafc90fb6c84188004983c001'
    '0fafc94489d069c90720900f4431c94c39da75bd4883c408c30f1f8400000000004157'
    '31c0415641554154555756534883ec3883fa108bb424a0000000448bb424a80000004c'
    '8d6c24200f850a010000900fb61c010fb6540101c1e30809da6641895405004883c002'
    '4883f81075e285f60f84b900000083ee014c8d6424304c89c84d8d7c310131ff31f666'
    '0f1f4400004c89ea4c89eb4531d231ed4531db66900fb70b418d3c3a4183c2014883c3'
    '0269ff354e00004431d901f74469d9354e000069f15a0100004183c30181e6ffff0000'
    '4181e3ffff000001f74489d981e7ffff000031f931cd4183fa0875b34585f6410fb618'
    '754d89d9c1e10801d931ebc1ed0831eb81e3ff000000660f1f44000066310a4883c202'
    '4c39e275f488184883c0014983c0014c39f80f8561ffffff4883c4384c89c85b5e5f5d'
    '415c415d415e415fc331ebc1ed0831eb81e3ff00000089d9c1e10801d9ebb7ff150000'
    '0000488d0d000000004c8d486041b810000000ba01000000e8000000004531c9ebb090'
    .decode('hex'),
}
assert len(MACHINE64WIN['code']) == 0x230

# interface to needed routines libalfcrypto
def _load_libalfcrypto():
    # Most of the magic here needs Python 2.6 or Python 2.7. It may work with
    # Python 2.5 as well if the ctypes package is installed, but that's not
    # tested.
    #
    # Tested on:
    #
    # * Linux i386
    # * Linux x86_64
    # * Mac OS X i386
    # * Mac OS X x86_64
    # * Windows XP i386
    # * Windows XP x86_64
    # * Windows 7 i386
    # * Windows 7 x86_64

    import os
    import sys

    ctypes = dl = None
    try:
      import ctypes
    except ImportError:
      try:
        import dl
        import struct
      except ImportError:
        raise ImportError('Neither ctypes nor dl found.')

    platform = sys.platform

    if ctypes:
      pointer_size = ctypes.sizeof(ctypes.c_voidp)
    else:
      pointer_size = struct.calcsize('P')

    try:
      arch = os.uname()[4]
    except AttributeError:  # platform == 'win32' doesn't have it.
      arch = 'unknown'

    # TODO: Maybe it runs on FreeBSD too. Try it.
    if (arch not in ('i386', 'i486', 'i586', 'i686', 'x86',
                     'unknown', 'x86_64', 'amd64') or
        platform not in ('linux', 'linux2', 'win', 'windows', 'win32', 'win64',
                         'darwin', 'darwin32', 'darwin64')):
      raise ImportError('Unsupported arch=%r platform=%r' % (arch, platform))
    if dl and pointer_size != 4:
      raise ImportError('Cannot use dl with pointer_size=%r, expecting 4' %
                        pointer_size)

    if pointer_size == 4:
      machine = MACHINE32
    elif platform.startswith('win'):
      # The Windows 64-bit calling conventions are different.
      # http://en.wikipedia.org/wiki/X86_calling_conventions#x86-64_calling_conventions
      machine = MACHINE64WIN
    else:
      machine = MACHINE64

    global m  # Don't free it until the alfcrypto module is freed.
    s = machine['code']
    if platform.startswith('win'):
      # MEM_COMMIT = 0x1000
      # MEM_RESERVE = 0x2000
      # MEM_RELEASE = 0x8000
      # PAGE_EXECUTE_READWRITE = 0x40
      class Releaser(object):
        __slots__ = ('p',)
        def __init__(self, p):
          self.p = int(p)
        def __del__(self):
          ctypes.windll.kernel32.VirtualFree(self.p, 0, 0x8000)
      # Allocate executable memory.
      #
      # This works as expected on Windows x86_64 as well, because each
      # argument is passed in a 64-bit register.
      vp = ctypes.windll.kernel32.VirtualAlloc(0, len(s), 0x3000, 0x40)
      m = Releaser(vp)
      ctypes.memmove(vp, s, len(s))
    elif dl:
      # dl is usually Linux i386. Not on Mac OS X 10.7 arch -32.
      # Not on Windows. Not on x86_64.
      import mmap
      # TODO: Report better exceptions here.
      d = dl.open(None)
      assert d.sym('mmap')
      assert d.sym('munmap')
      assert d.sym('memcpy')
      assert d.sym('qsort')
      # TODO: Call munmap later.
      class MmapReleaser(object):
        __slots__ = ('p', 'size')
        def __init__(self, p, size):
          self.p = int(p)
          self.size = int(size)
        def __del__(self):
          d.call('munmap', self.p, self.size)
      vp = d.call('mmap', 0, len(s),
                   mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                   mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
      assert vp != 0
      assert vp != -1
      m = MmapReleaser(vp, len(s))
      d.call('memcpy', vp, s, len(s))
      vp_cmp = vp + machine['cmp']

      def make_function(d, fp):
        if isinstance(fp, long):
          fp = int(fp)
        if not isinstance(fp, (str, int)):
          raise TypeError
        if isinstance(fp, int) and not fp:
          raise ValueError

        def call(*args):
          if isinstance(fp, str):
            return d.call(fp, *args)
          assert len(args) <= 10
          ary = [0] * 24
          ary[0] = fp
          for i, arg in enumerate(args):
            if isinstance(arg, str):
              arg = d.call('memcpy', arg, 0, 0)
            ary[i + 1] = arg
          arys = struct.pack('24i', *ary)  # This may fail with out-of-bounds.
          # Since we can't call an integer address (d.call(fp, ...)),
          # we call qsort and make it call us.
          d.call('qsort', arys, 2, 48, vp_cmp)
          return struct.unpack('i', arys[44 : 48])[0]

        return call
    elif not getattr(ctypes.c_char_p, 'from_buffer', None):
      # Method .from_buffer is missing in Python 2.5. Present in Python 2.6.
      import mmap
      class CtypesMmapReleaser(object):
        __slots__ = ('p', 'size')
        def __init__(self, p, size):
          self.p = int(p)
          self.size = int(size)
        def __del__(self):
          ctypes.pythonapi.munmap(self.p, self.size)
      vp = ctypes.pythonapi.mmap(0, len(s),
                   mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC,
                   mmap.MAP_PRIVATE | mmap.MAP_ANON, -1, 0)
      m = CtypesMmapReleaser(vp, len(s))
      ctypes.memmove(vp, s, len(s))
    else:
      import mmap
      # Allocate executable memory.
      m = mmap.mmap(-1, len(s), mmap.MAP_PRIVATE | mmap.MAP_ANON,
                    mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
      m.write(s)
      vp = ctypes.addressof(ctypes.c_char_p.from_buffer(m))

    if dl:
      PC1 = make_function(d, vp + machine['PC1'])
      topazCryptoInit = make_function(d, vp + machine['topazCryptoInit'])
      topazCryptoDecrypt = make_function(d, vp + machine['topazCryptoDecrypt'])
    else:
      c_char_pp = ctypes.POINTER(ctypes.c_char_p)

      def F(restype, name, argtypes):
        return ctypes.CFUNCTYPE(restype, *argtypes)(vp + machine[name])

      # Pukall 1 Cipher
      # unsigned char *PC1(const unsigned char *key, unsigned int klen, const unsigned char *src,
      #                unsigned char *dest, unsigned int len, int decryption);

      PC1 = F(ctypes.c_char_p, 'PC1', [ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_ulong])

      # Topaz Encryption
      # typedef struct _TpzCtx {
      #    unsigned int v[2];
      # } TpzCtx;
      #
      # void topazCryptoInit(TpzCtx *ctx, const unsigned char *key, int klen);
      # void topazCryptoDecrypt(const TpzCtx *ctx, const unsigned char *in, unsigned char *out, int len);

      class TPZ_CTX(ctypes.Structure):
        _fields_ = [('v', ctypes.c_int * 2)]

      TPZ_CTX_p = ctypes.POINTER(TPZ_CTX)
      topazCryptoInit = F(None, 'topazCryptoInit', [TPZ_CTX_p, ctypes.c_char_p, ctypes.c_ulong])
      topazCryptoDecrypt = F(None, 'topazCryptoDecrypt', [TPZ_CTX_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong])

    class Pukall_Cipher(object):
        def __init__(self):
            self.key = None

        def PC1(self, key, src, decryption=True):
            self.key = key
            de = 0
            if decryption:
                de = 1
            if dl:
              out = '\0' * max(len(src), 8)
              PC1(key, len(key), src, out, len(src), de)
              out = out[:len(src)]  # Fast, because no-op if out is long.
              return out
            else:
              out = ctypes.create_string_buffer(len(src))
              rv = PC1(key, len(key), src, out, len(src), de)
              return out.raw

    class Topaz_Cipher(object):
        def __init__(self):
            self._ctx = None

        def ctx_init(self, key):
            if dl:
              # Call `max' to prevent the Python compiler from inlining.
              tpz_ctx = self._ctx = '\0' * max(8, 8)
            else:
              tpz_ctx = self._ctx = TPZ_CTX()
            topazCryptoInit(tpz_ctx, key, len(key))
            return tpz_ctx

        def decrypt(self, data,  ctx=None):
            if ctx == None:
                ctx = self._ctx
            if dl:
              out = '\0' * max(len(data), 8)
              topazCryptoDecrypt(ctx, data, out, len(data))
              out = out[:len(data)]  # Fast, because no-op if out is long.
              return out
            else:
              out = ctypes.create_string_buffer(len(data))
              topazCryptoDecrypt(ctx, data, out, len(data))
              return out.raw

    print "Using inlined AlfCrypto machine code."
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
