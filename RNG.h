/*******************************************************************************
 ******     Copyright (c) 2014--2017 OSR.Co.Ltd. All rights reserved.     ****** 
 *******************************************************************************/
#ifndef OSR_RNG_H_
#define OSR_RNG_H_

//#include <stdint.h>

// Custom type definitions
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long uint64_t;

#ifdef __cplusplus
extern "C" {
#endif

void RandInit(uint32_t seed);

void GetRandU32(uint32_t random[], uint32_t wordLen);

void GetRandU8(uint8_t random[], uint32_t byteLen);
void print_buf_py(unsigned char buf[], unsigned int byteLen, char name[]);
#ifdef __cplusplus
}
#endif

#endif
