/******************************************************************************
 *File Name      :  codeHead.c
 *Copyright      :  Zhuzhou CRRC Times Electric Co.,Ltd. All Rights Reserved.
 *Create Date    :  2022/3/8
 *Description    :  get crc32 value.
 *
 *REV 1.0.0  liuyongyang   2012.02.10  File Create
 *REV 2.0.0  wlinlee   2023.09.26  modify crc to md5
 ******************************************************************************/

/*******************************************************************************
 *    Multi-Include-Prevent Start Section
 ******************************************************************************/
#ifndef _DRV_CODE_HEAD_H
#define _DRV_CODE_HEAD_H


// Custom type definitions
typedef unsigned char  uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int  uint32_t;
typedef unsigned long uint64_t;


/*******************************************************************************
 *    Debug switch Section
 ******************************************************************************/
//#define CHECKSUM_MD5
//#define MD5_LENGTH 16

#define CHECKSUM_SM2


/*******************************************************************************
 *    Include File Section
 ******************************************************************************/

/*******************************************************************************
 *    Global Macro Define Section
 ******************************************************************************/
#define MAX_FILE_NAME_LENGTH  (32)

#define MAX_FOLDER_NAME_LENGTH  (32)

#define CODE_HEAD_LENGTH    (0x00000100) 

#define FILEHEAD_VALID_FLAG   (0x5a5a5a5a)



/*******************************************************************************
 *    Global Structure Define Section
 ******************************************************************************/

typedef struct
{
    uint32_t ulValidFlag;                         /*是否有效的标志*/
    uint32_t ulVersion;                           /*大版本号*/
    uint8_t  ucFileName[MAX_FILE_NAME_LENGTH];    /*文件名*/
    uint32_t ulFpgaVersion;                       /*小版本号，可以用来存放FPGA版本*/
    uint32_t ulFileType;                          /*文件类型*/
#if defined(CHECKSUM_CRC32)
    uint32_t ulFileCrc;                           /*文件的CRC值*/
#elif defined(CHECKSUM_SM2)
	uint8_t ulFileSM2[64];						/*文件的SM2值*/
#elif defined(CHECKSUM_MD5)
    uint8_t ulFileMD5[16];                        /*文件的MD5值*/
#endif
    uint32_t ulOffset;                            /*文件头后面的文件的起始地址*/
    uint32_t ulFileLength;                        /*文件长度*/
    uint32_t ulFpgaLoadFlag;                      /*FPGA是否加载的标志*/
#if defined(CHECKSUM_SM2)
	uint16_t year;								/*文件生成时间：年*/
	uint8_t month;								/*文件生成时间：月*/
	uint8_t day;									/*文件生成时间：日*/
#elif defined(CHECKSUM_MD5)
	uint32_t ulBootromStartAddr;                  /*bootrom.bin存放的起始地址*/
    uint16_t year;                                /*文件生成时间：年*/
    uint8_t month;                                /*文件生成时间：月*/
    uint8_t day;                                  /*文件生成时间：日*/
    uint8_t weekDay;                              /*周日到周六:0-6*/
    uint8_t hour;                                 /*文件生成时间：时*/
    uint8_t minute;                               /*文件生成时间：分*/
    uint8_t second;                               /*文件生成时间：秒*/
#elif defined(CHECKSUM_CRC32)
		uint32_t ulBootromStartAddr;					/*bootrom.bin存放的起始地址*/
		uint16_t year;								/*文件生成时间：年*/
		uint8_t month;								/*文件生成时间：月*/
		uint8_t day;									/*文件生成时间：日*/
		uint8_t weekDay;								/*周日到周六:0-6*/
		uint8_t hour; 								/*文件生成时间：时*/
		uint8_t minute;								/*文件生成时间：分*/
		uint8_t second;								/*文件生成时间：秒*/
#endif
} CodeHeadInfo, *pCodeHeadInfo;



#if defined(CHECKSUM_CRC32)
typedef struct
{
    CodeHeadInfo HeadInfo;
    uint8_t ucReserve[CODE_HEAD_LENGTH - sizeof(CodeHeadInfo) - sizeof(uint32_t)];
    uint32_t ulHeadCRC;
} CodeHead, *pCodeHead;

#elif defined(CHECKSUM_SM2)

typedef struct
{
    CodeHeadInfo HeadInfo;
    uint8_t ucReserve[CODE_HEAD_LENGTH - sizeof(CodeHeadInfo)];
} CodeHead, *pCodeHead;


#elif defined(CHECKSUM_MD5)

typedef struct
{
    CodeHeadInfo HeadInfo;
    uint8_t ucReserve[CODE_HEAD_LENGTH - sizeof(CodeHeadInfo) - 16];
    uint8_t ulHeadMD5[16];
} CodeHead, *pCodeHead;

#endif


typedef struct {
#if defined(CHECKSUM_SM2)
    char  fileName[32];
#elif defined(CHECKSUM_MD5)
    char  fileName[32];
#elif defined(CHECKSUM_CRC32)
    char  fileName[32];
#endif
    uint32_t fileLength;
    uint32_t fileOffset;
#if defined(CHECKSUM_SM2)
	uint8_t fileSM2[16];						/*�ļ���SM2У��ֵ*/
#elif defined(CHECKSUM_MD5)
	uint8_t fileMd5[16];						/*�ļ���MD5У��ֵ*/
#endif

#if defined(CHECKSUM_CRC32)
	uint32_t reserved[4];
#elif defined(CHECKSUM_MD5)
	uint32_t reserved[4];
#elif defined(CHECKSUM_SM2)
	;
#endif

    
}FileInfo, *pFileInfo;
/*******************************************************************************
 *    Global Variable Declare Section
 ******************************************************************************/

/*******************************************************************************
 *    Global Prototype Declare Section
 ******************************************************************************/

/*******************************************************************************
 *    Multi-Include-Prevent End Section
 ******************************************************************************/
#endif


