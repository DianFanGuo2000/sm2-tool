/*******************************************************************************
 ******     Copyright (c) 2018--2023 OSR.Co.Ltd. All rights reserved.     ******
 *******************************************************************************/
#include <string.h>
#include "SM4.h"



static const uint32_t SM4_FK[4]  ={0xA3B1BAC6u, 0x56AA3350u, 0x677D9197u, 0xB27022DCu};
static const uint32_t SM4_CK[32] ={0x00070e15u, 0x1c232a31u, 0x383f464du, 0x545b6269u,
					   0x70777e85u, 0x8c939aa1u, 0xa8afb6bdu, 0xc4cbd2d9u,
					   0xe0e7eef5u, 0xfc030a11u, 0x181f262du, 0x343b4249u,
					   0x50575e65u, 0x6c737a81u, 0x888f969du, 0xa4abb2b9u,
					   0xc0c7ced5u, 0xdce3eaf1u, 0xf8ff060du, 0x141b2229u,
					   0x30373e45u, 0x4c535a61u, 0x686f767du, 0x848b9299u,
					   0xa0a7aeb5u, 0xbcc3cad1u, 0xd8dfe6edu, 0xf4fb0209u,
					   0x10171e25u, 0x2c333a41u, 0x484f565du, 0x646b7279u};

// SBox(a) = SBX[a]
static const uint8_t SM4_SBX[256]={0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
					   0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
					   0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
					   0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
					   0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
					   0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
					   0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
					   0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
					   0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
					   0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
					   0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
					   0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
					   0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
					   0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
					   0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
					   0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48};



static uint32_t SM4_rk[32];

static void U8Big_to_U32Big(uint32_t out[], const uint8_t in[])
{
    out[0] = in[3] | ((uint32_t)in[2] << 8u) | ((uint32_t)in[1] << 16u) | ((uint32_t)in[0] << 24u);
    out[1] = in[7] | ((uint32_t)in[6] << 8u) | ((uint32_t)in[5] << 16u) | ((uint32_t)in[4] << 24u);
    out[2] = in[11] | ((uint32_t)in[10] << 8u) | ((uint32_t)in[9] << 16u) | ((uint32_t)in[8] << 24u);
    out[3] = in[15] | ((uint32_t)in[14] << 8u) | ((uint32_t)in[13] << 16u) | ((uint32_t)in[12] << 24u);
}

#ifdef RAND_DELAY
static uint32_t SM4_Rand_Delay(void)
{
	uint32_t randbuf[4]={0};
	uint32_t i,j=0x5a5a;
	GetRandU32(randbuf, 4);
	for(i=0; i< (randbuf[1]&0x1f); i++)
	{
		j++;
	}
	if((j&0x01) == 1u)
	{
		j = randbuf[3]^randbuf[2];
	}
	else
	{
		j = randbuf[0]^randbuf[2];
		j = j^randbuf[3];
	}
	return j;
}
#endif

static void U32Big_to_U8Big(uint8_t out[], const uint32_t in[])
{
    uint8_t i;
    uint8_t j = 0u;
    for (i = 0u; i < 16u; i = i + 4u)
    {
        out[i] = ((uint8_t)(in[j] >> 24u) & 0xffu);
        out[i + 1u] = (uint8_t)(in[j] >> 16u) & 0xffu;
        out[i + 2u] = (uint8_t)(in[j] >> 8u) & 0xffu;
        out[i + 3u] = (uint8_t)in[j] & 0xffu;
        j++;
    }
}


static uint32_t SM4_ROTL(uint32_t x, uint8_t n)
{
    return (x << n) | (x >> (32u - n));
}

// Transformation tao
static uint32_t SM4_tao(uint32_t a)
{  
    uint8_t i, m;       
    uint32_t t = 0u; 

    for(i = 0u; i < 32u; i = i + 8u)
    {
        m = (uint8_t)(a >> i) & 0xffu;
        t |= (uint32_t)SM4_SBX[m] << i;
    }

    return t;
}

// Transformation T
static uint32_t SM4_T(uint32_t a)
{
    uint32_t t = SM4_tao(a);
    return (t) ^ SM4_ROTL(t, 2u) ^ SM4_ROTL(t, 10u) ^ SM4_ROTL(t, 18u) ^ SM4_ROTL(t, 24u);
}

// Transformation T1
static uint32_t SM4_T1(uint32_t a)
{
    uint32_t t = SM4_tao(a);
    return (t) ^ SM4_ROTL(t, 13u) ^ SM4_ROTL(t, 23u);
}

// SM4 Init: Key Expantions
OSR_SM4_RET_CODE OSR_SM4_Init(const uint8_t key[16])
{
    uint32_t K[4], Tmp, T;

    if(NULL == key)
    {
        return OSR_SM4BufferNull;
    }
    U8Big_to_U32Big(K, key);
    for(T = 0u; T < 4u; T++)
    {
        K[T] ^= SM4_FK[T];
    }

    Tmp =  K[2] ^ K[3];
    T = Tmp ^ K[1] ^ SM4_CK[0];
    SM4_rk[0] = K[0] ^ SM4_T1(T);
    T = Tmp ^ SM4_rk[0] ^  SM4_CK[1];
    SM4_rk[1] = K[1] ^ SM4_T1(T);
    
    Tmp = SM4_rk[0] ^ SM4_rk[1];
    T = Tmp ^ K[3] ^ SM4_CK[2];
    SM4_rk[2] = K[2] ^ SM4_T1(T);
    T = Tmp ^ SM4_rk[2] ^ SM4_CK[3];
    SM4_rk[3] = K[3] ^ SM4_T1(T);

    for(T = 0u; T <= 26u; T = T + 2u)
    {
        Tmp = SM4_rk[T + 2u] ^ SM4_rk[T + 3u];
        K[0] = Tmp ^ SM4_rk[T + 1u] ^ SM4_CK[T + 4u];
        SM4_rk[T + 4u] = SM4_rk[T] ^ SM4_T1(K[0]);

        K[0] = Tmp ^ SM4_rk[T + 4u] ^ SM4_CK[T + 5u];
        SM4_rk[T + 5u] = SM4_rk[T + 1u] ^ SM4_T1(K[0]);
    }
    return OSR_SM4Success;
}


static void SM4_En(const uint32_t Input[4], uint32_t Output[4])
{
    uint32_t X[28], T, i;
    
    i = Input[2] ^ Input[3];
    T = Input[1] ^ i ^ SM4_rk[0];
    X[0] = Input[0] ^ SM4_T(T);
    T = i ^ X[0] ^ SM4_rk[1];
    X[1] = Input[1] ^ SM4_T(T);

    i = X[0] ^ X[1];
    T = Input[3] ^ i ^ SM4_rk[2];
    X[2] = Input[2] ^ SM4_T(T);
    T = i ^ X[2] ^ SM4_rk[3];
    X[3] = Input[3] ^ SM4_T(T);

    for(i = 0u; i <= 22u; i = i + 2u)
    {
        T = X[i + 2u] ^ X[i + 3u];
        X[i + 4u] = X[i] ^ SM4_T(T ^ X[i + 1u] ^ SM4_rk[i + 4u]);
        X[i + 5u] = X[i + 1u] ^ SM4_T(T ^ X[i + 4u] ^ SM4_rk[i + 5u]);
    }

    T = X[26] ^ X[27];
    Output[3] = X[24] ^ SM4_T(T ^ X[25] ^ SM4_rk[28]);
    Output[2] = X[25] ^ SM4_T(T ^ Output[3] ^ SM4_rk[29]);
    T = Output[3] ^ Output[2];
    Output[1] = X[26] ^ SM4_T(T ^ X[27] ^ SM4_rk[30]);
    Output[0] = X[27] ^ SM4_T(T ^ Output[1] ^ SM4_rk[31]);
}

static void SM4_De(const uint32_t Input[4], uint32_t Output[4])
{
    uint32_t X[28], T, i;
	
    i = Input[2] ^ Input[3];
    T = Input[1] ^ i ^ SM4_rk[31];
    X[0] = Input[0] ^ SM4_T(T);
    T = i ^ X[0] ^ SM4_rk[30];
    X[1] = Input[1] ^ SM4_T(T);

    i = X[0] ^ X[1];
    T = Input[3] ^ i ^ SM4_rk[29];
    X[2] = Input[2] ^ SM4_T(T);
    T = i ^ X[2] ^ SM4_rk[28];
    X[3] = Input[3] ^ SM4_T(T);

    for(i = 0u; i <= 22u; i = i + 2u)
    {
        T = X[i + 2u] ^ X[i + 3u];
        X[i + 4u] = X[i] ^ SM4_T(T ^ X[i + 1u] ^ SM4_rk[27u - i]);
        X[i + 5u] = X[i + 1u] ^ SM4_T(T ^ X[i + 4u] ^ SM4_rk[26u - i]);
    }
    T = X[26] ^ X[27];
    Output[3] = X[24] ^ SM4_T(T ^ X[25] ^ SM4_rk[3]);
    Output[2] = X[25] ^ SM4_T(T ^ Output[3] ^ SM4_rk[2]);
    T = Output[3] ^ Output[2];
    Output[1] = X[26] ^ SM4_T(T ^ X[27] ^ SM4_rk[1]);
    Output[0] = X[27] ^ SM4_T(T ^ Output[1] ^ SM4_rk[0]);
}

// SM4 ECB Encryption/Decryption API
// Caution: in and out can be the same buffer 
OSR_SM4_RET_CODE OSR_SM4_ECB(const uint8_t *in, uint32_t inByteLen,const uint8_t En_De, uint8_t *out)
{
    uint32_t T1[4], i, count;


    if((NULL == in) || (NULL == out))
    {
        return OSR_SM4BufferNull;
    }

    // if the inByteLen is not a multiple of 16 or equals to 0, then refuse to compute.
    if((0u != (inByteLen & 0x0Fu)) || (0u == inByteLen))
    {
        return OSR_SM4InputLenInvalid;
    }
	
    if (En_De == 1u)
    {
    	count=0u;
#ifdef RAND_DELAY
    	(void)SM4_Rand_Delay();
#endif
        for(i = 0u; i < inByteLen; i += 16u)
        {
            U8Big_to_U32Big(T1, (const uint8_t *)(&(in[i])));
            count++;
            SM4_En(T1, T1);
            count++;
            U32Big_to_U8Big((uint8_t *)(&(out[i])), T1);
        }
        if((count == (inByteLen>>3u))&&(count == i>>3u))
        {
        	 return OSR_SM4Success;
        }
        else
        {
        	return OSR_SM4Attacked;
        }
    }
    else if (En_De == 0u)
    {
    	count=0u;
#ifdef RAND_DELAY
    	(void)SM4_Rand_Delay();
#endif
        for(i = 0u; i < inByteLen; i += 16u)
        {
            U8Big_to_U32Big(T1, (const uint8_t *)(&(in[i])));
            count++;
            SM4_De(T1, T1);
            count++;
            U32Big_to_U8Big((uint8_t *)(&(out[i])), T1);
        }
        if((count == (inByteLen>>3u))&&(count == (i>>3u)))
        {
        	 return OSR_SM4Success;
        }
        else
        {
        	return OSR_SM4Attacked;
        }
    }
    else
    {
        return OSR_SM4CryptInvalid;
    }
}


// SM4 CBC Encryption/Decryption API
// Caution: in and out can be the same buffer 
OSR_SM4_RET_CODE OSR_SM4_CBC(const uint8_t *in, uint32_t inByteLen, const uint8_t iv[16],const uint8_t En_De, uint8_t *out)
{
    uint8_t j;
    uint32_t T1[4], T2[4], InitVec[4], i, count;
    if ((NULL == in) || (NULL == iv) || (NULL == out))
    {
        return OSR_SM4BufferNull;
    }

    // if the inByteLen is not a multiple of 16 or equals to 0, then refuse to compute.
    if((0u != (inByteLen & 0x0Fu)) || (0u == inByteLen))
    {
        return OSR_SM4InputLenInvalid;
    }
    if (En_De == 1u)
    {
    	count = 0u;
        U8Big_to_U32Big(InitVec, iv);
#ifdef RAND_DELAY
    	(void)SM4_Rand_Delay();
#endif
        for(i = 0u; i < inByteLen; i += 16u)
        {
            U8Big_to_U32Big(T1, (const uint8_t *)(&(in[i])));
            for (j = 0u; j < 4u; j++)
            {
                T1[j] ^= InitVec[j];
            }
            count++;
            SM4_En(T1, InitVec);
            count++;
            U32Big_to_U8Big((uint8_t *)(&(out[i])), InitVec);
        }
        if((count == (inByteLen>>3u))&&(count == (i>>3u)))
        {
        	 return OSR_SM4Success;
        }
        else
        {
        	return OSR_SM4Attacked;
        }
    }
    else if (En_De == 0u)
    {
        U8Big_to_U32Big(InitVec, iv);
#ifdef RAND_DELAY
    	(void)SM4_Rand_Delay();
#endif
        count = 0u;
        for(i = 0u; i < inByteLen; i +=16u)
        {
            U8Big_to_U32Big(T1, (const uint8_t *)(&(in[i])));
            count ++;
            SM4_De(T1, T2);
            count ++;
            for (j = 0u; j < 4u; j++)
            {
                T2[j] ^= InitVec[j];
                InitVec[j] = T1[j];
            }
            U32Big_to_U8Big((uint8_t *)(&(out[i])), T2);
        }
        if((count == (inByteLen>>3u))&&(count == (i>>3u)))
        {
        	 return OSR_SM4Success;
        }
        else
        {
        	return OSR_SM4Attacked;
        }
    }
    else
    {
        return OSR_SM4CryptInvalid;
    }
}

#ifdef OSR_CFB_SM4
OSR_SM4_RET_CODE OSR_SM4_CFB(const uint8_t *in, uint32_t inByteLen, const uint8_t iv[16],const uint8_t En_De, uint8_t *out)
{
    uint8_t j;
    uint32_t T1[4], InitVec[4], i;
    if((NULL == in) || (NULL == iv) || (NULL == out))
    {
        return OSR_SM4BufferNull;
    }

    // if the inByteLen is not a multiple of 16, then refuse to computing.
    if((0u != (inByteLen & 0x0Fu)) || (0u == inByteLen))
    {
        return OSR_SM4InputLenInvalid;
    }

    U8Big_to_U32Big(InitVec, iv);
    if (En_De == 1u)
    {
        for (i = 0u; i < inByteLen; i += 16u)
        {
            SM4_En(InitVec, InitVec);
            U8Big_to_U32Big(T1, (const uint8_t *)(&(in[i])));
            for (j = 0u; j < 4u; j++)
            {
                InitVec[j] ^= T1[j];
            }
            U32Big_to_U8Big((uint8_t *)(&(out[i])), InitVec);
        }
        return OSR_SM4Success;
    }
    else if (En_De == 0u)
    {
        for (i = 0u; i < inByteLen; i += 16u)
        {
            SM4_En(InitVec, T1);
            U8Big_to_U32Big(InitVec, (const uint8_t *)(&(in[i])));
            for (j = 0u; j < 4u; j++)
            {
                T1[j] ^= InitVec[j];
            }
            U32Big_to_U8Big((uint8_t *)(&(out[i])), T1);
        }
        return OSR_SM4Success;
    }
    else
    {
        return OSR_SM4CryptInvalid;
    }
}
#endif

#ifdef OSR_OFB_SM4
OSR_SM4_RET_CODE OSR_SM4_OFB(const uint8_t *in, uint32_t inByteLen, const uint8_t iv[16], uint8_t *out)
{
    uint8_t j;
    uint32_t InitVec[4], i, t;
    if((NULL == in) || (NULL == iv) || (NULL == out))
    {
        return OSR_SM4BufferNull;
    }

    // if the inByteLen is not a multiple of 16, then refuse to computing.
    if((0u != (inByteLen & 0x0Fu)) || (0u == inByteLen))
    {
        return OSR_SM4InputLenInvalid;
    }

    U8Big_to_U32Big(InitVec, iv);
    for (i = 0u; i < inByteLen; i += 16u)
    {
        SM4_En(InitVec, InitVec);
        U32Big_to_U8Big((uint8_t *)(&(out[i])), InitVec);
        for (j = 0u; j < 16u; j++)
        {
            t = i + j;
            out[t] ^= in[t];
        }
    }
    return OSR_SM4Success;
}
#endif

#ifdef OSR_CTR_SM4
OSR_SM4_RET_CODE OSR_SM4_CTR(const uint8_t *in, uint32_t inByteLen, const uint8_t CTR[16], uint8_t *out)
{
    uint8_t j;
    uint8_t *p;
    uint32_t ByteLen = (inByteLen >> 4u) << 4u;
    uint32_t counter[4], T1[4], i, t;

    if((NULL == in) || (NULL == CTR) || (NULL == out))
    {
        return OSR_SM4BufferNull;
    }

    if (0u == inByteLen)
    {
        return OSR_SM4InputLenInvalid;
    }
    
    U8Big_to_U32Big(counter, CTR);
    for (i = 0u; i < ByteLen; i += 16u)
    {
        SM4_En(counter, T1);
        U32Big_to_U8Big((uint8_t *)(&out[i]), T1);
        for (j = 0u; j < 16u; j++)
        {
            t = i + j;
            out[t] ^= in[t];
        }
       
        for (j = 3u; j > 0u; j--)
        {
            counter[j] += 1u;
            if (counter[j] >= 1u)
            {
                break;
            }
        }
        if (0u == j)
        {
            counter[0] += 1u;
            if (counter[0] >= 1u)
            {
                continue;
            }
            else
            {            
                return OSR_SM4InputTooLong;
            }
        }
        
    }

    //last block processing
    ByteLen = inByteLen & 0x0Fu;
    p = (uint8_t *)(&counter);
    if (0u != ByteLen)
    {
        SM4_En(counter, T1);
        U32Big_to_U8Big(p, T1);
        for (j = 0u; j < ByteLen; j++)
        {
            t = i + j;
            out[t] = p[j] ^ in[t];
        }
    }
    return OSR_SM4Success;
}
#endif

OSR_SM4_RET_CODE OSR_SM4_Close(void)
{
    uint8_t i;

    for(i = 0u; i < 32u; i++)
    {
        SM4_rk[i] = 0u;
    }
    return OSR_SM4Success;
}

OSR_SM4_RET_CODE OSR_SM4_Version(uint8_t version[4])
{
	version[0] = 0x01;   
	version[1] = 0x02;   
	version[2] = 0x01;   
	version[3] = 0x00;   

	return OSR_SM4Success;
}

#define SM4_BLOCK_SIZE	16
OSR_SM4_RET_CODE SM4_encrypt(unsigned char *key, unsigned char *data, unsigned int dlen, unsigned char *cipher, unsigned int *clen)
{
	OSR_SM4_RET_CODE ret;
	OSR_SM4_CRYPT Mode_Enc = OSR_SM4_ENCRYPT;
	unsigned int chunk;
	unsigned char buf[SM4_BLOCK_SIZE] = {0};
	unsigned char iv[SM4_BLOCK_SIZE] = {0};
	ret = OSR_SM4_Init(key);
	if(OSR_SM4Success != ret)
		return ret;
	chunk = dlen - (dlen % SM4_BLOCK_SIZE);
	if(chunk == dlen)
		memset(buf, SM4_BLOCK_SIZE, SM4_BLOCK_SIZE);
	else
	{
		unsigned char bl = dlen - chunk;
		memcpy(buf, data+chunk, bl);
		memset(buf+bl, SM4_BLOCK_SIZE-bl, SM4_BLOCK_SIZE-bl);
	}
	//GetRandU8(iv, SM4_BLOCK_SIZE);
	memcpy(cipher, iv, SM4_BLOCK_SIZE);
	if(chunk)
	{
		ret = OSR_SM4_CBC(data, chunk, iv, Mode_Enc, cipher+SM4_BLOCK_SIZE);
		if(OSR_SM4Success != ret)
			return ret;
		memcpy(iv, cipher+chunk, SM4_BLOCK_SIZE);
	}
	ret = OSR_SM4_CBC(buf, SM4_BLOCK_SIZE, iv, Mode_Enc, cipher+chunk+SM4_BLOCK_SIZE);
	chunk += 2*SM4_BLOCK_SIZE;

	*clen = chunk;
	return ret;
}

OSR_SM4_RET_CODE SM4_decrypt(unsigned char *key, unsigned char *data, unsigned int dlen, unsigned char *out, unsigned int *olen)
{
	OSR_SM4_RET_CODE ret;
	OSR_SM4_CRYPT Mode_Enc = OSR_SM4_DECRYPT;
	unsigned char iv[SM4_BLOCK_SIZE];
	unsigned char padding;
	unsigned char *pos;
	unsigned int i;

	if(dlen < 2*SM4_BLOCK_SIZE)
		return OSR_SM4InputLenInvalid;

	ret = OSR_SM4_Init(key);
	if(OSR_SM4Success != ret)
		return ret;

	memcpy(iv, data, SM4_BLOCK_SIZE);

	dlen -= SM4_BLOCK_SIZE; //iv
	ret = OSR_SM4_CBC(data+SM4_BLOCK_SIZE, dlen, iv, Mode_Enc, out);
	if(OSR_SM4Success != ret)
		return ret;

	padding = out[dlen-1];
	if(padding > SM4_BLOCK_SIZE)
	{
		memset(out, 0, dlen);
		return OSR_SM4CryptInvalid;
	}

	pos = out+dlen-1;
	for(i = 0; i < padding; i++)
	{
		if(pos[0] != padding){
			memset(out, 0, dlen);
			return OSR_SM4CryptInvalid;
		}
		pos[0] = 0;
		pos--;
	}

	*olen = dlen - padding;

	return ret;
}
