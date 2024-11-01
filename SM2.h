/*******************************************************************************
 ******     Copyright (c) 2018--2023 OSR.Co.Ltd. All rights reserved.     ******
 *******************************************************************************/
#ifndef OSR_SM2_H_
#define OSR_SM2_H_

//#include <stdint.h>
#include "RNG.h"
#include "SM3.h"

#define OSR_ExchangeKey_SM2

#define SM_MAX_ID_LEN 8191u
#define SM2_BYTELEN 32u 

typedef enum SM2_Exchange_Role
{
    OSR_SM2_Role_Receiver = 0,
    OSR_SM2_Role_Sender
} OSR_SM2_Exchange_Role;

typedef enum SM2_RET_CODE
{
    OSR_SM2Success = 0,
    OSR_SM2BufferNull,
    OSR_SM2InputLenInvalid,
    OSR_SM2PointHeadNot04,
    OSR_SM2PubKeyError,
    OSR_SM2NotInCurve,
    OSR_SM2IntegerTooBig,
    OSR_SM2ZeroALL,
    OSR_SM2DecryVerifyFailed,
    OSR_SM2VerifyFailed,
    OSR_SM2ExchangeRoleInvalid,
    OSR_SM2ZeroPoint,
    OSR_SM2InOutSameBuffer,
    OSR_SM2Attacked,
} OSR_SM2_RET_CODE;

#ifdef __cplusplus
extern "C" {
#endif

OSR_SM2_RET_CODE OSR_SM2_GetKey(uint8_t priKey[32], uint8_t pubKey[65]);

OSR_SM2_RET_CODE OSR_SM2_Sign(const uint8_t E[SM2_BYTELEN], const uint8_t priKey[SM2_BYTELEN], uint8_t signature[64]);

OSR_SM2_RET_CODE OSR_SM2_Verify(const uint8_t E[SM2_BYTELEN], const uint8_t pubKey[65], const uint8_t signature[64]);

OSR_SM2_RET_CODE OSR_SM2_Encrypt(const uint8_t *M, uint32_t MByteLen, const uint8_t pubKey[65], uint8_t tag, uint8_t *C, uint32_t *CByteLen);

OSR_SM2_RET_CODE OSR_SM2_Decrypt(const uint8_t *C, uint32_t CByteLen, const uint8_t priKey[SM2_BYTELEN], uint8_t tag, uint8_t *M, uint32_t *MByteLen);

OSR_SM2_RET_CODE OSR_SM2_GetZ(const uint8_t *ID, uint16_t byteLenofID, const uint8_t pubKey[65], uint8_t Z[SM3_DIGEST_BYTELEN]);

OSR_SM2_RET_CODE OSR_SM2_GetE(const uint8_t *M, uint32_t byteLen, const uint8_t Z[SM3_DIGEST_BYTELEN], uint8_t E[SM3_DIGEST_BYTELEN]);

#ifdef OSR_ExchangeKey_SM2
OSR_SM2_RET_CODE OSR_SM2_ExchangeKey(const uint8_t role, const uint8_t *dA, const uint8_t *PB, const uint8_t *rA, const uint8_t *RA, const uint8_t *RB, const uint8_t *ZA, const uint8_t *ZB, uint32_t kByteLen, uint8_t *KA, uint8_t *S1, uint8_t *SA);
#endif

OSR_SM2_RET_CODE OSR_SM2_Version(uint8_t version[4]);

#ifdef __cplusplus
}
#endif

#endif
