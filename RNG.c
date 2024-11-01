/*******************************************************************************
 ******     Copyright (c) 2014--2021 OSR.Co.Ltd. All rights reserved.     ****** 
 *******************************************************************************/
/*
# @Time    : 2021/8/25 17:08
# @Author  : 
# @Email   : xintai.huang@osr-tech.com
# @File    : RNG.c
# @Company : Open Security Research Inc.
*/
#include <stdio.h>
#include <stdlib.h>          //rand and srand function
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "RNG.h"

#ifdef LINUX
#define USE_LINUX_RANDOM
#else
#define USE_VX_RANDOM
#endif

void print_buf_py(unsigned char buf[], unsigned int byteLen, char name[])
{
	unsigned int i;

	printf("\r\n %s:\r\n",name);
	for(i=0; i<byteLen; i++)
	{
		printf("%02x", buf[i]);
	}
	
	printf("\r\n");
}

#ifdef USE_VX_RANDOM
unsigned char * arandom = {0};
static FILE *udv_fp = NULL;
void GetRandU32(unsigned int random[], unsigned int wordLen)
{
    char *filename = (char *)"/tffs/urandom.txt";
    int bytecount;

	if(!udv_fp){
		udv_fp = fopen(filename, "rb");
		if (!udv_fp) return;
	}

    bytecount = wordLen * 4;
	fread(random, sizeof(unsigned char), bytecount, udv_fp);
}

void GetRandU8(unsigned char random[], unsigned int wordLen)
{
    char *filename = (char *)"/tffs/urandom.txt";
    int bytecount;

	if(!udv_fp){
		udv_fp = fopen(filename, "rb");
		if (!udv_fp) return;
	}

    bytecount = wordLen;
	fread(random, sizeof(unsigned char), bytecount, udv_fp);
}
#else
void GetRandU32(unsigned int buffer[], unsigned int len)
{
	int fd; 
    ssize_t bytes_read;
 
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) 
	{
        perror("open");
        exit(EXIT_FAILURE);
    }
 
    bytes_read = read(fd, buffer, len*4);
    if (bytes_read == -1) 
	{
        perror("read");
        exit(EXIT_FAILURE);
    }
 
    close(fd);
 #if 0

    printf("Random bytes: ");
    for (int i = 0; i < bytes_read; ++i) 
	{
        printf("%02x ", buffer[i]);
    }
    printf("\n");
#endif

}

void GetRandU8(unsigned char buffer[], unsigned int len)
{
	int fd;
    //char buffer[10]; 
    ssize_t bytes_read;
 
    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }
 
    bytes_read = read(fd, buffer, len);
    if (bytes_read == -1) {
        perror("read");
        exit(EXIT_FAILURE);
    }
 
    close(fd);
 
    
    printf("Random bytes: ");
    for (int i = 0; i < bytes_read; ++i) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
}
#endif

