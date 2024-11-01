
#include <fcntl.h>    // For O_* constants
#include <sys/mman.h> // For POSIX memory map functions
#include <sys/stat.h> // For mode constants
#include <unistd.h>   // For sysconf(_SC_PAGESIZE) and ssize_t
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>


#include "codeHead.h"
#include "SM2.h"


static char program_name[] = "sm2-tool";

static struct option long_options[] = {
    {"help", no_argument, 0, 'h'},
    {"verbose", no_argument, 0, 'v'},
    {"output", required_argument, 0, 'o'},
    {"trace", no_argument, 0, 't'},
    {"split", required_argument, 0, 'S'},
    {"verify", required_argument, 0, 'V'},
    {0, 0, 0, 0}
};

void usage(void)
{
    fprintf(stdout, "Usage: %s [options]\n",program_name);
    fprintf(stdout, "Options:\n");
    fprintf(stdout, "  -h, --help\t\t显示帮助信息\n");
    fprintf(stdout, "  -v, --verbose\t\t详细模式\n");
    fprintf(stdout, "  -o, --output\t是否输出日志文件\n");
    fprintf(stdout, "  -t, --trace\t\t是否在屏幕上显示测试过程与结果\n");
    fprintf(stdout, "  -S, --split\t验签并拆分子文件到当前目录\n");
    fprintf(stdout, "  -V, --verify\t验签\n");
}


uint8_t* open_file(const char *file_path) {
    // 以读写方式打开文件
    int fd = open(file_path, O_RDWR);
    if (fd == -1) {
        perror("Error opening file");
        return NULL;
    }

    // 获取文件大小
    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        perror("Error getting file size");
        close(fd);
        return NULL;
    }

    size_t len = sb.st_size; // 文件大小

    // 将文件内容映射到内存，设置为可读写
    uint8_t *buf = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (buf == MAP_FAILED) {
        perror("Error mapping file to memory");
        close(fd);
        return NULL;
    }

    close(fd); // 关闭文件描述符，因为映射已经建立
    return buf; // 返回指向映射区域的指针
}



// filesize 函数定义
// 参数 file_path 是文件路径
// 返回文件大小，如果出错返回 -1
off_t filesize(const char *file_path) {
    int fd = open(file_path, O_RDONLY); // 以只读方式打开文件
    if (fd == -1) {
        perror("Error opening file");
        return -1;
    }

    struct stat statbuf;
    if (fstat(fd, &statbuf) == -1) {
        // 错误处理
        perror("fstat failed");
        close(fd);
        return -1;
    }

    off_t size = statbuf.st_size;
    close(fd); // 获取文件大小后关闭文件
    return size;
}


void print_memory_region(const void *ptr, size_t size) {
    const unsigned char *p = (const unsigned char *)ptr;
    size_t i;
    
    printf("Memory region from %p to %p:\n", ptr, (void *)(ptr + size - 1));
    for (i = 0; i < size; ++i) {
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    if (size % 16 != 0) {
        printf("\n");
    }
}

// Function to verify the file using SM2 algorithm
/*
* Function: verify
* Description: Verifies the integrity of a file using the SM2 algorithm.
* Parameters:
*   file_path - The path to the file to be verified.
* Return value:
*   0 on success, -1 if the SM2 verification fails, -2 if there's an error in SM2_GetZ or SM2_GetE.
* Usage example:
*   int result = verify("/path/to/file");
*   if (result == 0) {
*       printf("File is verified successfully.\n");
*   } else {
*       printf("File verification failed.\n");
*   }
* Note: The file_path should be a valid path to a file.
*/
int verify(char *file_path) {
    uint8_t *buf = open_file(file_path); // Open the file and get the buffer
    if (buf == NULL) {
        printf("Failed to open file.\n");
        return -2;
    }

    //printf("%d\n",filesize(file_path));
    //print_memory_region(buf,filesize(file_path));

    //********************************Verification begins*******************************/
    // Read pubkey from txt file
    uint8_t pubKey[65] = {
        0x04, 0x87, 0x70, 0xEE, 0x02, 0x33, 0x9F, 0xE3, 0xD0,
        0xA6, 0x61, 0x7B, 0x7C, 0x50, 0x15, 0xA4, 0x2F,
        0xB3, 0x16, 0xC9, 0x52, 0x54, 0x97, 0x0D, 0x39,
        0x36, 0x7D, 0x4F, 0xB6, 0x4A, 0x2F, 0xFA, 0x2D,
        0x14, 0xED, 0xF3, 0xAC, 0x97, 0xC9, 0xF2, 0x63,
        0x4D, 0xF5, 0xA1, 0xA5, 0xEC, 0x31, 0xB1, 0xF0,
        0xAA, 0x5D, 0xF0, 0x7B, 0x1D, 0x41, 0xE4, 0xC8,
        0x33, 0xBC, 0x06, 0x68, 0xE8, 0xDD, 0xEB, 0x30
    }; // Public key buffer
    uint8_t ID[16] = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    uint16_t byteLenofID = 16; // Length of ID in bytes
    uint8_t z[32];
    uint8_t e[32];
    OSR_SM2_RET_CODE ret;

    // Cast the buffer to CodeHeadInfo structure
    CodeHeadInfo *pCodeHeadInfo = (CodeHeadInfo *)buf;
    // Verify if the VxWorks package is valid
    printf("pCodeHeadInfo->ulValidFlag = 0x%x \n", pCodeHeadInfo->ulValidFlag);
    printf("pCodeHeadInfo->ulVersion = %d \n", pCodeHeadInfo->ulVersion);
    printf("pCodeHeadInfo->ucFileName = %s \n", pCodeHeadInfo->ucFileName);
    printf("pCodeHeadInfo->ulFpgaVersion = %d \n", pCodeHeadInfo->ulFpgaVersion);
    printf("pCodeHeadInfo->ulFileType = %d \n", pCodeHeadInfo->ulFileType);
    printf("pCodeHeadInfo->ulFileSM2 = 0x");
    uint8_t ulFileSM2_bak[64];
    for (int j = 0; j < 64; j++) {
        printf("%02x", pCodeHeadInfo->ulFileSM2[j]);
        ulFileSM2_bak[j] = pCodeHeadInfo->ulFileSM2[j]; // backup the SM2 signature
        pCodeHeadInfo->ulFileSM2[j] = 0; // zero the SM2 signature
    }
    printf("\n");
    printf("pCodeHeadInfo->ulOffset = %d B (0x%x) \n", pCodeHeadInfo->ulOffset, pCodeHeadInfo->ulOffset);
    printf("pCodeHeadInfo->ulFileLength = %d B (0x%x) \n", pCodeHeadInfo->ulFileLength, pCodeHeadInfo->ulFileLength);
    printf("pCodeHeadInfo->Time = %d-%d-%d\n", pCodeHeadInfo->year, pCodeHeadInfo->month, pCodeHeadInfo->day);

    ret = OSR_SM2_GetZ(ID, byteLenofID, pubKey, z);

    if (OSR_SM2Success != ret) {
        printf("ERROR in SM2_GetZ\r\n");
        // 取消映射
        munmap(buf, filesize(file_path)); // filesize 需要你根据实际情况定义，或者使用其他方式获取文件大小
        return -2;
    }

    uint32_t targetFileLength = pCodeHeadInfo->ulFileLength;
    printf("targetFileLength is %d B (0x%x)\n", targetFileLength, targetFileLength);

    ret = OSR_SM2_GetE(buf, targetFileLength, z, e);
    if (OSR_SM2Success != ret) {
        printf("ERROR in SM2_GetE\r\n");
        // 取消映射
        munmap(buf, filesize(file_path)); // filesize 需要你根据实际情况定义，或者使用其他方式获取文件大小
        return -2;
    }
    for (int j = 0; j < 64; j++) {
        pCodeHeadInfo->ulFileSM2[j] = ulFileSM2_bak[j]; // recover the SM2 signature
    }

    ret = OSR_SM2_Verify(e, pubKey, pCodeHeadInfo->ulFileSM2);
    if (OSR_SM2Success != ret) {
        printf("ERROR in SM2_Verify, which verifies pCodeHeadInfo->ulFileSM2 with E value.\r\n");
        printf("    pCodeHeadInfo->ulFileSM2 = 0x");
        for (int j = 0; j < 64; j++) {
            printf("%02x", pCodeHeadInfo->ulFileSM2[j]);
        }
        printf("\n");
        printf("    E value for 0x%x ... 0x%x in bin file, whose length is %d B ==> ", 0, pCodeHeadInfo->ulFileLength, targetFileLength);

        for (int i = 0; i < 32; i++)
            printf("%02x", e[i]);

        printf("\n");
        printf("total file sm2 is wrong \n");


        // 取消映射
        munmap(buf, filesize(file_path)); // filesize 需要你根据实际情况定义，或者使用其他方式获取文件大小
        return -1;
    } else {
        printf("total file sm2 is correct \n");
    }
    // 取消映射
    munmap(buf, filesize(file_path)); // filesize 需要你根据实际情况定义，或者使用其他方式获取文件大小
    return 0;
}
/**
 * Writes the provided data to a file with the specified file name.
 *
 * @param data Pointer to the data to be written to the file.
 * @param length The length of the data to be written.
 * @param fileName The name of the file where the data will be written.
 *
 * @return None
 *
 * @example
 * uint8_t data[] = {0x01, 0x02, 0x03};
 * uint32_t length = sizeof(data);
 * const char *fileName = "example.bin";
 * download(data, length, fileName);
 *
 * @note This function assumes that the file name is a valid path and that the
 * data pointer is valid. It does not handle errors that may occur during file
 * writing, such as disk space issues or permission errors.
 */
void download(const uint8_t *data, uint32_t length, const char *fileName) {
    // Open the file in binary write mode
    FILE *file = fopen(fileName, "wb");
    if (file == NULL) {
        // If the file cannot be opened, print an error message and return
        perror("Error opening file");
        return;
    }

    // Write the data to the file
    uint32_t bytesWritten = fwrite(data, 1, length, file);
    if (bytesWritten < length) {
        // If the write operation was not successful, print an error message
        perror("Error writing to file");
    }

    // Close the file
    fclose(file);
}


/**
 * Splits a file into individual files based on the FileInfo structure
 * contained within the file.
 * 
 * @param file_path The path to the file to be split.
 * @return 0 on success, -1 if verification fails, -2 if file cannot be opened.
 * 
 * @example
 * int result = split("/path/to/file");
 * if (result == 0) {
 *     printf("File was successfully split.\n");
 * } else {
 *     printf("Failed to split file.\n");
 * }
 * 
 * @note This function assumes that the FileInfo structure is correctly
 * formatted and that the file path is valid. It also assumes that the
 * download function is properly implemented to handle file downloads.
 */
int split(char *file_path) {
    // File number (not used in this snippet)
    int filenum = 0;
    // Pointer to file information header
    FileInfo *pfilehead = NULL;    

    if(verify(file_path) < 0)
        return -1;

    uint8_t *buf = open_file(file_path); // Open the file and get the buffer
    if (buf == NULL) {
        printf("Failed to open file.\n");
        return -2;
    }

    // Extract the file number (an unsigned 32-bit integer) from the buffer after the code header length
    filenum = *(uint32_t *)(buf + CODE_HEAD_LENGTH);
    // Set the pointer to the FileInfo structure after the code header length and the file number
    pfilehead = (FileInfo *)(buf + CODE_HEAD_LENGTH + sizeof(uint32_t));
    printf("filenum is %d \n", filenum);


    // Iterate through all the files based on the file number
    for (int i = 0; i < filenum; i++) {
        printf("pfilehead's offset in file is 0x%x \n", (uint8_t *)pfilehead - buf);
        printf("pfilehead->fileName = %s \n", pfilehead->fileName);
        printf("pfilehead->fileLength = %d \n", pfilehead->fileLength);
        printf("pfilehead->fileOffset = 0x%x \n", pfilehead->fileOffset); 
        printf("pfilehead->fileSM2 = 0x");
        for (int j = 0; j < 16; j++) {
            printf("%02x", pfilehead->fileSM2[j]);
        }
        printf("\n");

        // Concatenate the file path with the directory path to form the full path
        char fullPath[1024] = {0};
        strcat(fullPath, file_path);
        char *lastSlash = strrchr(fullPath, '/');
        if (lastSlash != NULL) {
            *lastSlash = '\0'; // Remove the file name and keep the directory path
        }
        strcat(fullPath, "/");
        strcat(fullPath, pfilehead->fileName);

        download((uint8_t *)(buf + pfilehead->fileOffset), pfilehead->fileLength, fullPath);

        pfilehead = (FileInfo *)((uint8_t *)pfilehead + sizeof(FileInfo));
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int option_index = 0;
    int c;
    int verbose_flag=0; // 默认省略模式
    int trace_flag=0; //默认无回显
    char *log_file = NULL; // 默认不输出日志文件

    char ops[100]=""; // 操作选择记录表
    int ops_num=0; // 当前记录的操作数目

    char* file_path = NULL;


    // 解析输入，以收集数据、配置环境、记录操作序列
    while ((c = getopt_long(argc, argv, "vho:tS:V:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'h':
                usage();
                //exit(EXIT_SUCCESS);
                break;
            case 'v':
                verbose_flag=1;
                printf("Verbose mode\n");
                break;
            case 'o':
                log_file = optarg;
                printf("Output log file: %s\n", optarg);
                break;
            case 't':
                trace_flag=1;
                printf("Trace mode");
                break;
            case 'S':
                file_path = optarg;
                ops[ops_num]='S';
                ops_num++;
                break;
            case 'V':
                file_path = optarg;
                ops[ops_num]='V';
                ops_num++;
                break;
            case '?':
                printf("Unknown option: %c\n", optopt);
                break;
            default:
                printf("?? getopt returned character code 0%o ??\n", c);
                abort();
        }
    }

    for (int index = optind; index < argc; index++) {
        printf("Non-option argument %s\n", argv[index]);
    }


    if(file_path==NULL)
        exit(EXIT_FAILURE);


    // 根据操作记录情况，按照操作输入次序来执行相关函数
    for(int i=0;i<ops_num;i++){
        switch (ops[i]) {
            case 'S':    
                printf("split\n");
                split(file_path);
                break;
            case 'V':
                printf("verify\n");
                verify(file_path);
                break;
        }
    }

    return 0;
}