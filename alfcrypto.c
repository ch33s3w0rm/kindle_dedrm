// Most of this file is copy-pasted from the alfcrypto sources.

typedef struct _TpzCtx {
   unsigned int v[2];
} TpzCtx;

//implementation of Pukall Cipher 1
unsigned char *PC1(const unsigned char *key, unsigned int klen, const unsigned char *src,
                   unsigned char *dest, unsigned int len, int decryption) {
    unsigned int sum1 = 0;
    unsigned int sum2 = 0;
    unsigned int keyXorVal = 0;
    unsigned short wkey[8];
    unsigned int i;
    if (klen != 16) {
        // fprintf(stderr, "Bad key length!\n");
        return (void*)0;
    }
    for (i = 0; i < 8; i++) {
        wkey[i] = (key[i * 2] << 8) | key[i * 2 + 1];
    }
    for (i = 0; i < len; i++) {
        unsigned int temp1 = 0;
        unsigned int byteXorVal = 0;
        unsigned int j, curByte;
        for (j = 0; j < 8; j++) {
            temp1 ^= wkey[j];
            sum2 = (sum2 + j) * 20021 + sum1;
            sum1 = (temp1 * 346) & 0xFFFF;
            sum2 = (sum2 + sum1) & 0xFFFF;
            temp1 = (temp1 * 20021 + 1) & 0xFFFF;
            byteXorVal ^= temp1 ^ sum2;
        }
        curByte = src[i];
        if (!decryption) {
            keyXorVal = curByte * 257;
        }
        curByte = ((curByte ^ (byteXorVal >> 8)) ^ byteXorVal) & 0xFF;
        if (decryption) {
            keyXorVal = curByte * 257;
        }
        for (j = 0; j < 8; j++) {
            wkey[j] ^= keyXorVal;
        }
        dest[i] = curByte;
    }
    return dest;
}

//
// Context initialisation for the Topaz Crypto
//
void topazCryptoInit(TpzCtx *ctx, const unsigned char *key, int klen) {
   int i = 0; 
   ctx->v[0] = 0x0CAFFE19E;
    
   for (i = 0; i < klen; i++) {
      ctx->v[1] = ctx->v[0]; 
      ctx->v[0] = ((ctx->v[0] >> 2) * (ctx->v[0] >> 7)) ^  
                  (key[i] * key[i] * 0x0F902007);
   }
}

//
// decrypt data with the context prepared by topazCryptoInit()
//
    
void topazCryptoDecrypt(const TpzCtx *ctx, const unsigned char *in, unsigned char *out, int len) {
   unsigned int ctx1 = ctx->v[0];
   unsigned int ctx2 = ctx->v[1];
   int i;
   for (i = 0; i < len; i++) {
      unsigned char m = in[i] ^ (ctx1 >> 3) ^ (ctx2 << 3);
      ctx2 = ctx1;
      ctx1 = ((ctx1 >> 2) * (ctx1 >> 7)) ^ (m * m * 0x0F902007);
      out[i] = m;
   }
}

// Trampoline for `import dl' and qsort.

struct Item {
  int (*f)(int, int, int, int, int, int, int, int, int, int);
  int g[10];
  int retval;
};

int cmp(struct Item *a, struct Item *b) {
  if (a->f == (void*)0) {
    a = b;
  }
  if (a->f != (void*)0) {
    a->retval = a->f(a->g[0], a->g[1], a->g[2], a->g[3], a->g[4], a->g[5], 
                     a->g[6], a->g[7], a->g[8], a->g[9]);
    a->f = (void*)0;
  }
  return 0;
}
