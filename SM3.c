/*******************************************************************************
 ******     Copyright (c) 2018--2023 OSR.Co.Ltd. All rights reserved.     ******
 *******************************************************************************/
#include <string.h>
#include "SM3.h"

static const uint32_t SM3_IV[8]= {0x7380166fu, 0x4914b2b9u, 0x172442d7u, 0xda8a0600u, 0xa96f30bcu, 0x163138aau, 0xe38dee4du, 0xb0fb0e4eu};
static const uint32_t SM3_T[2] = {0x79cc4519u, 0x7a879d8au};

#define SM3_MAC_IPAD  (0x36363636u)
#define SM3_MAC_IPAD_OPAD  (0x6a6a6a6au)

static uint32_t SM3_block_bitLen(const OSR_SM3_Ctx * ctx)
{
    return ctx->count[1] & 0x1FFu;
}

static void U32Small_to_U32Big(uint32_t out[], const uint32_t in[], uint8_t wordLen)
{
    uint8_t i;
    for (i = 0u; i < wordLen; i++)
    {
        out[i] = (in[i] >> 24u) | ((in[i] >> 8u) & 0x0000FF00u) | ((in[i] << 8u) & 0x00FF0000u) | (in[i] << 24u);
    }
}


static uint32_t SM3_ROTL(uint32_t const x, uint8_t n)
{
    return (x << n) | (x >> (32u - n));
}

static uint32_t SM3_P(uint32_t x, uint8_t m, uint8_t n)
{
    return x ^ SM3_ROTL(x,m) ^ SM3_ROTL(x,n);
}

static void SM3_block(OSR_SM3_Ctx * ctx, uint8_t wordLen)
{
    uint8_t i, j;
    uint32_t W[68], W_1, SS, TT1, TT2;
    uint32_t SM3_abcdefgh[8];

    for (i = 0u; i < 8u; i++)
    {
        SM3_abcdefgh[i] = ctx->hash[i];
    }

    U32Small_to_U32Big(W, ctx->wbuf, wordLen);
    if (wordLen == 14u)
    {
        W[14] = ctx->count[0];
        W[15] = ctx->count[1];
    }
    for (j = 16u; j <= 58u; j = (j + 6u))
    {
        for (i = j; i< (j + 3u); i++)
        {
            W_1 = W[i - 16u] ^ W[i - 9u] ^ SM3_ROTL(W[i - 3u], 15u);
            W[i] = SM3_P(W_1, 15u, 23u) ^ SM3_ROTL(W[i - 13u], 7u) ^ W[i - 6u];
            W_1 = W[i - 13u] ^ W[i - 6u] ^ SM3_ROTL(W[i], 15u);
            W[i + 3u] = SM3_P(W_1, 15u, 23u) ^ SM3_ROTL(W[i - 10u], 7u) ^ W[i - 3u];
        }
    }
    for (i = 64u; i < 68u; i++)
    {
        W_1 = W[i - 16u] ^ W[i - 9u] ^ SM3_ROTL(W[i - 3u], 15u);
        W[i] = SM3_P(W_1, 15u, 23u) ^ SM3_ROTL(W[i - 13u], 7u) ^ W[i - 6u];
    }

    for (i = 0u; i < 64u; i++)
    {
        W_1 = W[i] ^ W[i + 4u];

        if(i < 16u)
        {
            SS = SM3_ROTL(SM3_T[0] , i);
            TT1 = SM3_abcdefgh[0] ^ SM3_abcdefgh[1] ^ SM3_abcdefgh[2];
            TT2 = SM3_abcdefgh[4] ^ SM3_abcdefgh[5] ^ SM3_abcdefgh[6];
        }
        else
        {
            SS = SM3_ROTL(SM3_T[1], (i < 32u) ? i : (i - 32u));
            TT1 = ((SM3_abcdefgh[0] & SM3_abcdefgh[1]) | (SM3_abcdefgh[0] & SM3_abcdefgh[2]) | (SM3_abcdefgh[1] & SM3_abcdefgh[2]));
            TT2 = (SM3_abcdefgh[4] & SM3_abcdefgh[5]) | ((~SM3_abcdefgh[4]) & SM3_abcdefgh[6]);
        }

        SS += (SM3_abcdefgh[4] + SM3_ROTL(SM3_abcdefgh[0], 12u));
        SS = SM3_ROTL(SS, 7u);  /* SS1 */
        TT2 += (SS + SM3_abcdefgh[7] + W[i]);

        SS = SS ^ SM3_ROTL(SM3_abcdefgh[0], 12u); /* SS2 */
        TT1 += W_1 + SS + SM3_abcdefgh[3];

        SS=SM3_abcdefgh[0];
        SM3_abcdefgh[0] = TT1;
        SM3_abcdefgh[7] = SM3_abcdefgh[6];
        SM3_abcdefgh[6] = SM3_ROTL(SM3_abcdefgh[5], 19u);
        SM3_abcdefgh[5] = SM3_abcdefgh[4];
        SM3_abcdefgh[4] = SM3_P(TT2, 9u, 17u);
        SM3_abcdefgh[3] = SM3_abcdefgh[2];
        SM3_abcdefgh[2] = SM3_ROTL(SM3_abcdefgh[1], 9u);
        SM3_abcdefgh[1] = SS;
    }

    for(i = 0u; i < 8u; i++)
    {
        ctx->hash[i] ^= SM3_abcdefgh[i];
    }
}

OSR_SM3_RET_CODE OSR_SM3_Init(OSR_SM3_Ctx *ctx)
{
    uint8_t i;
    if (NULL == ctx)
    {
        return OSR_SM3BufferNull;
    }

    ctx->count[0] = 0;
    ctx->count[1] = 0;
    for (i = 0u; i < 8u; i++)
    {
        ctx->hash[i] = SM3_IV[i];
    }

    return OSR_SM3Success;
}

static OSR_SM3_RET_CODE SM3_Ctx_Update(OSR_SM3_Ctx * ctx, uint32_t curLen, const uint8_t * Message, uint32_t fillLen)
{
    uint8_t *pCtx = (uint8_t *)(ctx->wbuf) + curLen;
    uint32_t i;
    for (i = 0u; i < fillLen; i++)
    {
        pCtx[i] = Message[i];
    }
    i = fillLen << 3u;
    ctx->count[1] += i;
    if (ctx->count[1] < i)
    {
        ctx->count[0] += 1u;
        if (ctx->count[0] < 1u)
        {
            return OSR_SM3InputTooLong;
        }
    }
    return OSR_SM3Success;
}

OSR_SM3_RET_CODE OSR_SM3_Process(OSR_SM3_Ctx * ctx, const uint8_t * message, uint32_t msgByteLen)
{
    OSR_SM3_RET_CODE ret = OSR_SM3Success;
    uint32_t filllen, curlen, leftlen;
    const uint8_t *pMessage = message;
    if((NULL == ctx) || (NULL == pMessage))
    {
        return OSR_SM3BufferNull;
    }

    while(msgByteLen > 0u)
    {
        curlen = (SM3_block_bitLen(ctx)) >> 3u;                 
        leftlen = 64u - curlen;                                 
        filllen = (msgByteLen < leftlen) ? msgByteLen : leftlen;   
        ret = SM3_Ctx_Update(ctx, curlen, pMessage, filllen); 
        if(OSR_SM3Success != ret)
        {
            return ret;
        }
		
        pMessage = &pMessage[filllen];
        msgByteLen -= filllen;
        if(0u == SM3_block_bitLen(ctx))
        {
            SM3_block(ctx, 16u);
        }       
    }
    return ret;
}

OSR_SM3_RET_CODE OSR_SM3_Done(OSR_SM3_Ctx *ctx, uint8_t digest[SM3_DIGEST_BYTELEN])
{
    uint32_t tmp;
    uint32_t byteLen;
    uint8_t *pwbuf;
	
    if((NULL == ctx) || (NULL == digest))
    {
        return OSR_SM3BufferNull;
    }

    tmp = SM3_block_bitLen(ctx);
    byteLen = (tmp + 7u) >> 3u;
    tmp = tmp & 7u;

    if(0u != tmp)
    {
        *((uint8_t *)(ctx->wbuf) + byteLen - 1u) &= (uint8_t)(0xFFu << (7u - tmp));
        *((uint8_t *)(ctx->wbuf) + byteLen - 1u) |= (uint8_t)(0x1u << (7u - tmp));
    }
    else        
    {
        *((uint8_t *)(ctx->wbuf) + byteLen) = 0x80u;                        
        byteLen += 1u;
    }
    if (byteLen <= 56u)
    {
        tmp = 56u - byteLen;
    }
    else
    {
        tmp = 64u - byteLen;
    }
    pwbuf = (uint8_t *)(ctx->wbuf) + byteLen;
    while (0u != tmp)
    {
        tmp--;
        pwbuf[tmp] = 0;
    }

    if (byteLen > 56u)
    {
        SM3_block(ctx, 16u);
        for (tmp = 0; tmp < 14u; tmp++)
        {
            ctx->wbuf[tmp] = 0u;
        }
    }

    SM3_block(ctx, 14u);

    byteLen = 0u;
    for (tmp = 0u; tmp < 32u; tmp = tmp + 4u)
    {
        digest[tmp] = ((uint8_t)(ctx->hash[byteLen] >> 24u) & 0xffu);
        digest[tmp + 1u] = (uint8_t)(ctx->hash[byteLen] >> 16u) & 0xffu;
        digest[tmp + 2u] = (uint8_t)(ctx->hash[byteLen] >> 8u) & 0xffu;
        digest[tmp + 3u] = (uint8_t)ctx->hash[byteLen] & 0xffu;
        byteLen++;
    }
    //clean buffer
    for (byteLen = 0u; byteLen < 2u; byteLen++)
    {
        ctx->count[byteLen] = 0u;
    }
    for (byteLen = 0u; byteLen < 8u; byteLen++)
    {
        ctx->hash[byteLen] = 0u;
    }
    for (byteLen = 0u; byteLen < 16u; byteLen++)
    {
        ctx->wbuf[byteLen] = 0u;
    }
    return OSR_SM3Success;
}

OSR_SM3_RET_CODE OSR_SM3_Hash(const uint8_t * message, uint32_t msgByteLen, uint8_t digest[SM3_DIGEST_BYTELEN])
{
    OSR_SM3_RET_CODE ret;
    OSR_SM3_Ctx ctx;

    ret = OSR_SM3_Init(&ctx); 
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    ret = OSR_SM3_Process(&ctx, message, msgByteLen);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    ret = OSR_SM3_Done(&ctx, digest); 
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    return OSR_SM3Success;
}


OSR_SM3_RET_CODE OSR_SM3_Version(uint8_t version[4])
{
	version[0] = 0x01;   
	version[1] = 0x02;   
	version[2] = 0x01;   
	version[3] = 0x00;   

	return OSR_SM3Success;
}

#ifdef OSR_HMAC_SM3
static OSR_SM3_RET_CODE OSR_SM3_HMAC_Key_Update(uint32_t *K0, const uint8_t *key, uint32_t keyByteLen)
{
    uint8_t *pCtx = (uint8_t *)K0;
    uint32_t i;
    OSR_SM3_RET_CODE ret;
    if (keyByteLen <= 64u)
    {
        for (i = 0u; i < keyByteLen; i++)
        {
            pCtx[i] = key[i];
        }
        for (i = keyByteLen; i < 64u; i++)
        {
            pCtx[i] = 0u;
        }
    }
    else
    {
        ret = OSR_SM3_Hash(key, keyByteLen, pCtx);
        if (OSR_SM3Success != ret)
        {
            return ret;
        }
        for (i = 32u; i < 64u; i++)
        {
            pCtx[i] = 0u;
        }
    }
    for (i = 0u; i< 16u; i++)
    {
        K0[i] ^= SM3_MAC_IPAD;
    }
    return OSR_SM3Success;
}

OSR_SM3_RET_CODE OSR_SM3_HMAC_Init(OSR_SM3_HMAC_CTX *ctx, const uint8_t *key, uint32_t keyByteLen)
{
    OSR_SM3_RET_CODE ret;

    if ((NULL == ctx) || (NULL == key))
    {
        return OSR_SM3BufferNull;
    }

    ret = OSR_SM3_HMAC_Key_Update(ctx->K0, key, keyByteLen);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    ret = OSR_SM3_Init(ctx->sm3_ctx);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    return OSR_SM3_Process(ctx->sm3_ctx, (uint8_t *)(ctx->K0), 64);
}

OSR_SM3_RET_CODE OSR_SM3_HMAC_Process(OSR_SM3_HMAC_CTX *ctx, const uint8_t *message, uint32_t msgByteLen)
{
    return OSR_SM3_Process(ctx->sm3_ctx, message, msgByteLen);
}

OSR_SM3_RET_CODE OSR_SM3_HMAC_Done(OSR_SM3_HMAC_CTX *ctx, uint8_t mac[SM3_DIGEST_BYTELEN])
{
    uint32_t i;
    OSR_SM3_RET_CODE ret;
    if (NULL == ctx)
    {
        return OSR_SM3BufferNull;
    }
	
    ret = OSR_SM3_Done(ctx->sm3_ctx, mac);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    for (i = 0u; i < 16u; i++)
    {
        ctx->K0[i] ^= SM3_MAC_IPAD_OPAD;
    }

    ret = OSR_SM3_Init(ctx->sm3_ctx);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    ret = OSR_SM3_Process(ctx->sm3_ctx, (uint8_t *)(ctx->K0), 64);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    ret = OSR_SM3_Process(ctx->sm3_ctx, mac, 32);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    return OSR_SM3_Done(ctx->sm3_ctx, mac);
}

OSR_SM3_RET_CODE OSR_SM3_HMAC(const uint8_t *key, uint32_t keyByteLen, const uint8_t *msg, uint32_t msgByteLen, uint8_t mac[SM3_DIGEST_BYTELEN])
{
    OSR_SM3_HMAC_CTX ctx;
    OSR_SM3_RET_CODE ret;

    if ((NULL == key) || (NULL == msg) || (NULL == mac))
    {
        return OSR_SM3BufferNull;
    }

    ret = OSR_SM3_HMAC_Init(&ctx, key, keyByteLen);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }
    ret = OSR_SM3_Process(ctx.sm3_ctx, msg, msgByteLen);
    if(OSR_SM3Success != ret)
    {
        return ret;
    }

    return OSR_SM3_HMAC_Done(&ctx, mac);
}

OSR_SM3_RET_CODE OSR_SM3_HMAC_Version(uint8_t version[4])
{
	version[0] = 0x01;   
	version[1] = 0x02;   
	version[2] = 0x01;   
	version[3] = 0x00;   

	return OSR_SM3Success;
}
#endif
