
/*******************************************************************************
 ******     Copyright (c) 2018--2023 OSR.Co.Ltd. All rights reserved.     ******
 *******************************************************************************/

#ifndef OSR_SM4_H_
#define OSR_SM4_H_

#include <stdint.h>

#define OSR_CTR_SM4
#define OSR_CFB_SM4
#define OSR_OFB_SM4

//#define RAND_DELAY

#ifdef RAND_DELAY
extern void GetRandU32(uint32_t random[], uint32_t wordLen);
#endif

typedef enum SM4_RET_CODE
{
    OSR_SM4Success = 0, 
    OSR_SM4BufferNull,
    OSR_SM4InputTooLong,
    OSR_SM4InputLenInvalid,
    OSR_SM4CryptInvalid,
    OSR_SM4InOutSameBuffer,
    OSR_SM4GCMCheckFail,
    OSR_SM4Attacked
} OSR_SM4_RET_CODE;

typedef enum SM4_CRYPT
{
    OSR_SM4_DECRYPT = 0,
    OSR_SM4_ENCRYPT
} OSR_SM4_CRYPT;

#ifdef __cplusplus
extern "C" {
#endif

OSR_SM4_RET_CODE OSR_SM4_Init(const uint8_t key[16]);

OSR_SM4_RET_CODE OSR_SM4_ECB(const uint8_t *in, uint32_t inByteLen,const uint8_t En_De, uint8_t *out);

OSR_SM4_RET_CODE OSR_SM4_CBC(const uint8_t *in, uint32_t inByteLen, const uint8_t iv[16],const uint8_t En_De, uint8_t *out);

#ifdef OSR_OFB_SM4
OSR_SM4_RET_CODE OSR_SM4_OFB(const uint8_t *in, uint32_t inByteLen, const uint8_t iv[16], uint8_t *out);
#endif

#ifdef OSR_CFB_SM4
OSR_SM4_RET_CODE OSR_SM4_CFB(const uint8_t *in, uint32_t inByteLen, const uint8_t iv[16], const uint8_t En_De, uint8_t *out);
#endif

#ifdef OSR_CTR_SM4
OSR_SM4_RET_CODE OSR_SM4_CTR(const uint8_t *in, uint32_t inByteLen, const uint8_t CTR[16], uint8_t *out);
#endif

OSR_SM4_RET_CODE OSR_SM4_Close(void);

OSR_SM4_RET_CODE OSR_SM4_Version(uint8_t version[4]);

OSR_SM4_RET_CODE SM4_encrypt(unsigned char *key, unsigned char *data, unsigned int dlen, unsigned char *cipher, unsigned int *clen);

OSR_SM4_RET_CODE SM4_decrypt(unsigned char *key, unsigned char *data, unsigned int dlen, unsigned char *out, unsigned int *olen);

#ifdef __cplusplus
}
#endif

#endif
