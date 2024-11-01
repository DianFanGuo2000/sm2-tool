/*******************************************************************************
 ******     Copyright (c) 2018--2023 OSR.Co.Ltd. All rights reserved.     ******
 *******************************************************************************/

#ifndef OSR_SM3_H_
#define OSR_SM3_H_

//#include <stdint.h>

#define OSR_HMAC_SM3

#define SM3_DIGEST_BYTELEN (32)

// Custom type definitions
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long uint64_t;

typedef enum SM3_RET_CODE
{
    OSR_SM3Success = 0, 
    OSR_SM3BufferNull,
    OSR_SM3InputTooLong
} OSR_SM3_RET_CODE;

typedef struct SM3_Ctx
{
    uint32_t count[2];  
    uint32_t hash[8];   
    uint32_t wbuf[16];
}OSR_SM3_Ctx;

typedef struct
{
    uint32_t K0[16];
    OSR_SM3_Ctx sm3_ctx[1];
} OSR_SM3_HMAC_CTX;

#ifdef __cplusplus
extern "C" {
#endif

OSR_SM3_RET_CODE OSR_SM3_Init(OSR_SM3_Ctx *ctx);

OSR_SM3_RET_CODE OSR_SM3_Process(OSR_SM3_Ctx *ctx, const uint8_t *message, uint32_t msgByteLen);

OSR_SM3_RET_CODE OSR_SM3_Done(OSR_SM3_Ctx *ctx, uint8_t digest[SM3_DIGEST_BYTELEN]);

OSR_SM3_RET_CODE OSR_SM3_Hash(const uint8_t *message, uint32_t msgByteLen, uint8_t digest[SM3_DIGEST_BYTELEN]);

OSR_SM3_RET_CODE OSR_SM3_Version(uint8_t version[4]);

#ifdef OSR_HMAC_SM3
OSR_SM3_RET_CODE OSR_SM3_HMAC_Init(OSR_SM3_HMAC_CTX *ctx, const uint8_t *key, uint32_t keyByteLen);

OSR_SM3_RET_CODE OSR_SM3_HMAC_Process(OSR_SM3_HMAC_CTX *ctx, const uint8_t *message, uint32_t msgByteLen);

OSR_SM3_RET_CODE OSR_SM3_HMAC_Done(OSR_SM3_HMAC_CTX *ctx, uint8_t mac[SM3_DIGEST_BYTELEN]);

OSR_SM3_RET_CODE OSR_SM3_HMAC(const uint8_t *key, uint32_t keyByteLen, const uint8_t *msg, uint32_t msgByteLen, uint8_t mac[SM3_DIGEST_BYTELEN]);

OSR_SM3_RET_CODE OSR_SM3_HMAC_Version(uint8_t version[4]);
#endif

#ifdef __cplusplus
}
#endif

#endif
