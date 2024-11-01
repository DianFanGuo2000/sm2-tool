/*******************************************************************************
 ******     Copyright (c) 2018--2023 OSR.Co.Ltd. All rights reserved.     ******
 *******************************************************************************/

#include <string.h>
#include "SM2.h"
#include <stdio.h>
#include <stdlib.h>

#define SM2_BITLEN  256u 
#define SM2_WORDLEN 8u
#define SM2_RADIX_WORDLEN 10u
#define RADIX_EXPO 28u
#define RADIX_MINUS1 0x0FFFFFFFu

typedef struct
{
    uint32_t x[SM2_RADIX_WORDLEN];
    uint32_t y[SM2_RADIX_WORDLEN];
}ECCP_POINT;

typedef struct
{
    uint32_t x[SM2_RADIX_WORDLEN];
    uint32_t y[SM2_RADIX_WORDLEN];
    uint32_t z[SM2_RADIX_WORDLEN];
}ECCP_JACOBIPOINT;

typedef struct
{
    uint32_t t0[SM2_RADIX_WORDLEN];
    uint32_t t1[SM2_RADIX_WORDLEN];
    uint32_t t2[SM2_RADIX_WORDLEN];
    uint32_t t3[SM2_RADIX_WORDLEN];
    uint32_t t4[SM2_RADIX_WORDLEN];
}ECCP_playground;


/*uint32_t little-endian with padding*/
static const uint32_t sm2p256v1_p[SM2_RADIX_WORDLEN] = {0x0FFFFFFF, 0x0FFFFFFF, 0x000000FF, 0x0FFFF000, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFE, 0x0000000F};
static const uint32_t sm2p256v1_a[SM2_RADIX_WORDLEN] = {0x0FFFFFFC, 0x0FFFFFFF, 0x000000FF, 0x0FFFF000, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFE, 0x0000000F};
static const uint32_t sm2p256v1_b[SM2_RADIX_WORDLEN] = {0x0D940E93, 0x0BCBD414, 0x0B8F92DD, 0x089F515A, 0x09A7F397, 0x04BCF650, 0x044D5A9E, 0x09D9F5E3, 0x08E9FA9E, 0x00000002};
static const uint32_t sm2p256v1_n[SM2_RADIX_WORDLEN] = {0x09D54123, 0x0BBF4093, 0x06052B53, 0x0DF6B21C, 0x0FFF7203, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFE, 0x0000000F};
static const uint32_t SM2_n_minus_1_padding[SM2_RADIX_WORDLEN] ={0x09D54122u, 0x0BBF4093u, 0x06052B53u, 0x0DF6B21Cu, 0x0FFF7203u, 0x0FFFFFFFu, 0x0FFFFFFFu, 0x0FFFFFFFu, 0x0FFFFFFEu, 0x0Fu};

static const uint32_t sm2p256v1_2n[SM2_RADIX_WORDLEN]= {0x13AA8246, 0x177E8126, 0x1C0A56A6, 0x1BED6437, 0x1FFEE406, 0x1FFFFFFE, 0x1FFFFFFE, 0x1FFFFFFE, 0x1FFFFFFC, 0x0000001E};
/* 2 ^(280) % n, uint32_t little-endian with padding*/
static const uint32_t sm2p256v1_n_residue_280[SM2_RADIX_WORDLEN-1]= {0x0D000000, 0x0C62ABED, 0x0C440BF6, 0x039FAD4A, 0x0C2094DE, 0x000008DF, 0x00000000, 0x00000000, 0x01000000};
/* 2 ^(256) % n, uint32_t little-endian with padding*/
static const uint32_t sm2p256v1_n_residue_256[SM2_RADIX_WORDLEN-1]= {0x062ABEDD, 0x0440BF6C, 0x09FAD4AC, 0x02094DE3, 0x00008DFC, 0x00000000, 0x00000000, 0x00000000, 0x00000001};

static const uint32_t sm2p256v1_2p[SM2_RADIX_WORDLEN]= {0x1FFFFFFE, 0x1FFFFFFE, 0x100001FE, 0x1FFFDFFF, 0x1FFFFFFE, 0x1FFFFFFE, 0x1FFFFFFE, 0x1FFFFFFE, 0x1FFFFFFC, 0x0000001E};
/* 2 ^(256) % p, uint32_t little-endian with padding*/
static const uint32_t sm2p256v1_p_residue_256[SM2_RADIX_WORDLEN-1]= {0x00000001, 0x00000000, 0x0FFFFF00, 0x00000FFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001};

static const ECCP_POINT SM2_COMB_iG[]={
    {{0x034C74C7, 0x05A45893, 0x060BE171, 0x00BBFF26, 0x09948FE3, 0x0466A39C, 0x095F9904, 0x01F19811, 0x02C4AE2C, 0x03},
     {0x0139F0A0, 0x0DF32E52, 0x0A474002, 0x0877CC62, 0x0153D0A9, 0x0E36B692, 0x0C59BDCE, 0x0F4F6779, 0x0C3736A2, 0x0B}},/*         +         + G     */
    {{0x016FBA8E, 0x04EE4FC0, 0x0947D4A6, 0x0811A60C, 0x0893A1B6, 0x02DB6393, 0x0B53E55D, 0x08426E35, 0x02555CEB, 0x08},/*		   +		  + 		 + [2^52]G +   */
     {0x0D101797, 0x0814CCF6, 0x0A436E31, 0x0C9AE8D5, 0x0D1E1DE1, 0x065D5B66, 0x0440CC3F, 0x07F46C33, 0x09189D43, 0x00}},
    {{0x05A242DD, 0x0E83BEA9, 0x07ECEE1F, 0x01ACC9A4, 0x0D818C77, 0x0BE6A2B0, 0x06625165, 0x0A82A0C5, 0x073C307C, 0x0D},/*		   +		  + 		 + [2^52]G + G  */
     {0x0DF565DA, 0x0688D92F, 0x044E7E38, 0x01DDE852, 0x0C5512DA, 0x0C75F9D4, 0x09B6A191, 0x04CB1C75, 0x0DE7BF2B, 0x00}},
    {{0x03513003, 0x0012B762, 0x0981FB57, 0x03D3A262, 0x07E0B9D5, 0x0CDE65C4, 0x02E59152, 0x0001294A, 0x0E923F46, 0x09},/*		   +		  + [2^104]G +		   +    */
     {0x0003ECB4, 0x07E821DE, 0x008B9A5C, 0x036FDB5C, 0x08D87A01, 0x0028AB28, 0x011F739B, 0x09E8E624, 0x0A787C83, 0x0B}},
    {{0x05001029, 0x059F3544, 0x0FBB51AE, 0x0E296483, 0x0EDCB6BF, 0x08E19529, 0x0F41951B, 0x01EB1DE7, 0x0FF1E824, 0x0D},/*		   +		  + [2^104]G +		   + G   */
     {0x07010535, 0x071C6882, 0x0E9CA385, 0x012E6DE9, 0x08739D43, 0x0C77C5D9, 0x02054289, 0x013FDFDA, 0x0DFB27FC, 0x03}},
    {{0x0E20B40D, 0x0CEB832F, 0x0FB3AC19, 0x06067331, 0x03FE74A6, 0x0E86ECA2, 0x021BABF4, 0x0EE138D2, 0x0DC54490, 0x0F},/*		   +		  + [2^104]G + [2^52]G +    */
     {0x05A8CDC8, 0x0834BC44, 0x06D956F9, 0x01D11CD3, 0x05AC5797, 0x0BF5118B, 0x0F3F7B50, 0x0343A558, 0x041A096A, 0x04}},
    {{0x0FA73272, 0x08587CF8, 0x0ADE40AF, 0x0C926063, 0x05F6A8EC, 0x0D1B74DE, 0x0C96D966, 0x04DFE1A2, 0x05348B34, 0x0C},/*		   +		  + [2^104]G + [2^52]G + G   */
     {0x086CE116, 0x0A30DDB6, 0x069315B0, 0x04F326B7, 0x03802BF8, 0x022B5B68, 0x0CE8F6C7, 0x02EFDB4C, 0x0A9FD3F6, 0x0A}},
    {{0x0290E444, 0x0FB5A4E3, 0x09EE1485, 0x0F530CC2, 0x02916F8F, 0x06271AB4, 0x0F836200, 0x0F24EE97, 0x0469B4D3, 0x00},/*		   + [2^156]G + 		 +		   +    */
     {0x06F2A337, 0x0C712975, 0x08D68D23, 0x056B50FA, 0x042A756F, 0x02F85A13, 0x0C9D0A9D, 0x09E2CB92, 0x0D1C6A91, 0x0E}},
    {{0x02C80626, 0x02A20980, 0x0556EBA9, 0x0DC4BB97, 0x09AEA621, 0x04137430, 0x0C0C1374, 0x0EC77691, 0x0302C5EC, 0x04},/*		   + [2^156]G + 		 +		   + G   */
     {0x0276DB9D, 0x05A604A4, 0x0ADDBB21, 0x03605360, 0x07CBB2B8, 0x00941F09, 0x02B7F4D2, 0x0F618AFA, 0x0E41A3D9, 0x02}},
    {{0x052FAC9D, 0x0C35E261, 0x04ACA450, 0x0375622E, 0x020DF536, 0x01698EC6, 0x05125422, 0x08CB051C, 0x0858C126, 0x0E},/*		   + [2^156]G + 		 + [2^52]G +     */
     {0x0EF93F5C, 0x0FE42967, 0x00F1CCA2, 0x00DBD02F, 0x0E7E34B4, 0x00FFF8BD, 0x025FC7DA, 0x06CFF20A, 0x004A53CD, 0x0A}},
    {{0x05F11789, 0x0FAB63E2, 0x059DC226, 0x0E723388, 0x0ACF9DE0, 0x0D2F97BC, 0x025F4DAC, 0x09756EFB, 0x0A9AA461, 0x00},/*		   + [2^156]G + 		 + [2^52]G + G    */
     {0x09F1066E, 0x0CDE6692, 0x0B172EC8, 0x0FD30074, 0x050854AB, 0x001EC439, 0x0A81CF47, 0x02C4A8A9, 0x0FC9A4F0, 0x02}},
    {{0x0E8C2939, 0x0F53F1AF, 0x08C6ED58, 0x04697B0F, 0x031674ED, 0x07BBE452, 0x0C26CDA0, 0x0996C638, 0x054C9FBB, 0x05},/*		   + [2^156]G + [2^104]G +		   +    */
     {0x03D94AA3, 0x0C405651, 0x0EC2F3F3, 0x0322683A, 0x0150DFC5, 0x0D35B62E, 0x0A874BED, 0x06642D35, 0x0D914171, 0x03}},
    {{0x0AF571DC, 0x02304B16, 0x0DDFE91C, 0x0AC1A209, 0x09416F3D, 0x0EFF7C55, 0x0B07A2A5, 0x0FAF2CE4, 0x05A7146E, 0x05},/*		   + [2^156]G + [2^104]G +		   + G   */
     {0x0D3EE627, 0x009BA5F7, 0x08809571, 0x0B60512E, 0x0CF2C8DB, 0x00A7EF38, 0x0E63B268, 0x09E530F7, 0x01112815, 0x05}},
    {{0x064341F9, 0x07EA80C2, 0x0D231412, 0x0306758F, 0x077A39FC, 0x02D459BD, 0x090C2EF5, 0x0C9680C0, 0x0EC9A58E, 0x02},/*		   + [2^156]G + [2^104]G + [2^52]G +       */
     {0x082F15F1, 0x096FA478, 0x02AF46AE, 0x034B3F2A, 0x00403B96, 0x0FEFE018, 0x035DA782, 0x0BBF84FD, 0x05AB56E9, 0x08}},
    {{0x042EE4CF, 0x0424EAA3, 0x044ACFB7, 0x0D9987E6, 0x0117B342, 0x0D45D67F, 0x0F5CC731, 0x0BF809C5, 0x05C50898, 0x0D},/*		   + [2^156]G + [2^104]G + [2^52]G + G   */
     {0x014A3C16, 0x0CB19D13, 0x004DC8F1, 0x046DE64B, 0x00BC49E3, 0x0D6783D3, 0x0543A0D3, 0x08C0028B, 0x0A585251, 0x09}},
    {{0x09D3C6C3, 0x07BC06B6, 0x0C057652, 0x08EBA956, 0x0CD70549, 0x0DC108E2, 0x048AF60D, 0x0FAB7D9E, 0x025CAB2F, 0x05},/*[2^208]G +		  + 		 +		   +   */
     {0x00382BBC, 0x06279CB6, 0x0BEA5487, 0x00465CA2, 0x02B835F8, 0x008B4726, 0x081CB757, 0x0787480A, 0x054D184A, 0x04}},
    {{0x0937E4D7, 0x01581040, 0x0E3DC626, 0x006B85EA, 0x09F2A5C3, 0x003DA1AC, 0x059100E7, 0x052AE3C2, 0x0EB0BE34, 0x0E},/*[2^208]G +		  + 		 +		   + G   */
     {0x0D037CD2, 0x02827CBC, 0x02AB8EAF, 0x0CC00B21, 0x028243AD, 0x0FBE8806, 0x0F857D88, 0x05DBCFFC, 0x0CB1C87C, 0x0B}},
    {{0x038F593E, 0x024A7AD0, 0x03878F82, 0x085D353E, 0x00C065F2, 0x03214D42, 0x051EFB3B, 0x016D251F, 0x0B81933F, 0x0E},/*[2^208]G +		  + 		 + [2^52]G +    */
     {0x0EB6B00B, 0x0B209323, 0x0FC9F14F, 0x0ADA9976, 0x03B1AD6C, 0x0F4405BA, 0x0CA0FCA5, 0x0B55CA2B, 0x0EF88A70, 0x0A}},
    {{0x09DCCBD3, 0x09E0C8BE, 0x034746BF, 0x06C254E6, 0x02EA5E73, 0x00AAC777, 0x0E4C038C, 0x0B44BEF6, 0x0EFC09D6, 0x0F},/*[2^208]G +		  + 		 + [2^52]G + G    */
     {0x04BE10C8, 0x0057FC33, 0x05697051, 0x0CF3D891, 0x0B3D74FA, 0x03A352F0, 0x06FDE74E, 0x00147A67, 0x03892742, 0x04}},
    {{0x02388847, 0x0D79A841, 0x02239181, 0x042C6362, 0x01D84D83, 0x040962BA, 0x0D0BB7CE, 0x0E6EB94D, 0x0A5F1D6C, 0x08},/*[2^208]G +		  + [2^104]G +		   +    */
     {0x01D831E0, 0x0E7D9C29, 0x066EE17A, 0x0C773D14, 0x021921E5, 0x0C79D5D0, 0x0C52C501, 0x0E1889F6, 0x0949AE56, 0x08}},
    {{0x07FB0540, 0x04CEA391, 0x00FB38B3, 0x0587E31E, 0x02ECF711, 0x0B015786, 0x051B2246, 0x00CC945A, 0x033FF494, 0x01},/*[2^208]G +		  + [2^104]G +		   + G   */
     {0x02405897, 0x0B5A1965, 0x05B910A7, 0x05DFF6FF, 0x01E771D5, 0x038F0961, 0x02F4188A, 0x0639ED76, 0x09EB1002, 0x0A}},
    {{0x0A503C8C, 0x0761566A, 0x0A10D2A5, 0x03170D34, 0x0B724880, 0x0A556F8F, 0x01B16792, 0x046AE5E2, 0x09AC40AB, 0x0F},/*[2^208]G +		  + [2^104]G + [2^52]G +     */
     {0x0A6D55FB, 0x0B28D5F0, 0x0A0B153B, 0x039062D1, 0x05CEF9DF, 0x08C93EDF, 0x012498E5, 0x07845DC3, 0x0ED12650, 0x08}},
    {{0x0AEDC515, 0x06165C35, 0x0C3A9A9B, 0x0595EAD9, 0x02B174D1, 0x024D9049, 0x00C0F558, 0x0D1AEEEE, 0x07A8083D, 0x0B},/*[2^208]G +		  + [2^104]G + [2^52]G + G    */
     {0x0A5E1679, 0x0A547271, 0x0D71A672, 0x07A8B3CF, 0x06B0C5ED, 0x0C52B49A, 0x0FDEB630, 0x07D99192, 0x092FDAF3, 0x03}},
    {{0x0724B5AB, 0x05D77237, 0x00149548, 0x0270F712, 0x0EB8B177, 0x04B23B6D, 0x003CD63F, 0x0FEE255F, 0x09D7F9E8, 0x0B},/*[2^208]G + [2^156]G + 		 +		   +     */
     {0x08FF29AB, 0x060EF331, 0x0234A669, 0x0AC66C85, 0x03BAA3BD, 0x01BA48E3, 0x04E0FE54, 0x0B3E0DB9, 0x0D2717AC, 0x0E}},
    {{0x08A0F54F, 0x0F01B020, 0x0310E17D, 0x05BC871D, 0x05E30D51, 0x0503BA94, 0x0A51932C, 0x0B56CEF1, 0x026F0095, 0x06},/*[2^208]G + [2^156]G + 		 +		   + G   */
     {0x003EAA14, 0x05F0BF03, 0x0BA49899, 0x08559F99, 0x01C020AC, 0x0947E6E7, 0x056731D7, 0x01447BEE, 0x0DCF6813, 0x07}},
    {{0x0F9DDB21, 0x0B6BC929, 0x0CC07B4B, 0x02AC0461, 0x0DF2105A, 0x0EC5E64C, 0x029A0D38, 0x0AAC3901, 0x0296E7B6, 0x0B},/*[2^208]G + [2^156]G + 		 + [2^52]G +     */
     {0x0ABB9821, 0x0D2258CA, 0x04C517F5, 0x0BD19579, 0x045733F1, 0x0ED6E149, 0x07A1A36F, 0x07158FCF, 0x01E6BEBB, 0x00}},
    {{0x085DF5E9, 0x09845EA1, 0x0800D95D, 0x0CC4ACC2, 0x06A95DFB, 0x0E4C8356, 0x0F090D5A, 0x022711EE, 0x09308636, 0x03},/*[2^208]G + [2^156]G + 		 + [2^52]G + G   */
     {0x0BF92062, 0x052F34B6, 0x088BDBFD, 0x0196089A, 0x0CAA3EE1, 0x0C90EFF0, 0x0D408378, 0x0F84F070, 0x09BCFB93, 0x01}},
    {{0x07AA44CD, 0x065D5DD3, 0x024D961F, 0x03F55683, 0x088132B2, 0x045BFAA5, 0x036E15E9, 0x02AD3B57, 0x05FDA78E, 0x00},/*[2^208]G + [2^156]G + [2^104]G +		   +     */
     {0x0DB1B5BC, 0x0DE92B80, 0x03B521C3, 0x017415A9, 0x0C2DEA08, 0x08A3C9B3, 0x0451C37B, 0x0296D6ED, 0x0131D72F, 0x03}},
    {{0x077F5324, 0x03B72835, 0x0D53D901, 0x0B5F0BB3, 0x05688610, 0x02868A20, 0x0E26E0FB, 0x063743AB, 0x018B1062, 0x08},/*[2^208]G + [2^156]G + [2^104]G +		   + G   */
     {0x041453A6, 0x044944F6, 0x05170647, 0x0D7D3DAB, 0x0674014F, 0x007E6504, 0x02C57B21, 0x06D37E0F, 0x017F4685, 0x0F}},
    {{0x01A33D48, 0x060C46D4, 0x0FD61150, 0x0015862F, 0x0C13E72E, 0x052BB4EA, 0x0EBE3C98, 0x08DFEF7B, 0x08EAB8AB, 0x05},/*[2^208]G + [2^156]G + [2^104]G + [2^52]G +      */
     {0x0FCA0696, 0x0F3DE66A, 0x02DB8CF9, 0x056A01A3, 0x07F8A4F4, 0x0D3B891B, 0x045FDB34, 0x06ED2552, 0x0E6A47DB, 0x0F}},
    {{0x0F1CF2D5, 0x06F5B44D, 0x0646C840, 0x00C4282E, 0x06EC8E4B, 0x0E5EF7B1, 0x0F893221, 0x0AE76E93, 0x082389BE, 0x02},/*[2^208]G + [2^156]G + [2^104]G + [2^52]G + G    */
     {0x0D0CA406, 0x023FDBC1, 0x0FB4A8CC, 0x0E9350AD, 0x0AC91CC7, 0x0813C09E, 0x07E14F24, 0x0710E14B, 0x09032EEA, 0x0C}},
};

#define Big_ModAdd_N(R,X,Y) ModAdd(R,X,Y, sm2p256v1_n_residue_256, sm2p256v1_n)
#define Big_ModSub_N(R,X,Y) ModSub(R,X,Y, sm2p256v1_2n, sm2p256v1_n_residue_256, sm2p256v1_n)
#define Big_ModMul_N(R,X,Y) ModMulN(R,X,Y, sm2p256v1_n_residue_280, sm2p256v1_n_residue_256, sm2p256v1_n)
#define Big_ModInv_N(R,X) ModInv(R,X, sm2p256v1_n)

#define Big_ModSq_P(R,X) ModSqP(R,X,sm2p256v1_p_residue_256, sm2p256v1_p)
#define Big_ModSub_P(R,X,Y) ModSub(R,X,Y,sm2p256v1_2p,sm2p256v1_p_residue_256, sm2p256v1_p)
#define Big_ModAdd_P(R,X,Y) ModAdd(R,X,Y,sm2p256v1_p_residue_256, sm2p256v1_p)
#define Big_ModMul_P(R,X,Y) ModMulP(R,X,Y,sm2p256v1_p_residue_256, sm2p256v1_p)
#define Big_ModInv_P(R,X) ModInv(R,X, sm2p256v1_p)

#if 1
void dump_mem1(uint8_t buf[], uint32_t byteLen, char name[])
{
        uint32_t i;

        printf("\r\n %s: ",name); fflush(stdout);
        for(i=0; i<byteLen; i++)
        {
                printf("0x%02x, ", buf[i]);
        }

        printf("\r\n");
}
#endif
static void uint32_t_Copy(uint32_t dst[], const uint32_t src[], uint32_t wordLen)
{
    while(0u != wordLen)
    {
        --wordLen;
        dst[wordLen] = src[wordLen];
    }
}

static void uint32_t_Clear(uint32_t a[], uint32_t wordLen)
{
    while(0u != wordLen)
    {
        a[--wordLen] = 0u;
    }
}

static uint32_t Big_ChkZero(const uint32_t a[], uint32_t wordLen)
{
    while(0u != wordLen)
    {
        if(0u != a[--wordLen])
        {
            return 0u;
        }
    }
    return 1u;
}

static uint32_t uint8_t_ChkZero(const uint8_t a[], uint32_t byteLen)
{
    while(0u != byteLen)		
    {
        if(0u != a[--byteLen])
        {
            return 0u;
        }
    }
    return 1u;
}

/* little-endian */
static uint32_t Big_Compare(const uint32_t a[], const uint32_t b[], uint32_t wordLen)
{
    while(0u != wordLen)		
    {    
        --wordLen;
        if(a[wordLen] > b[wordLen])
        {
            return 1u;
        }
        else if(a[wordLen] < b[wordLen])
        {
            return 2u;
        }
        else
        {
            continue;
        }
    }
    return 0u;
}

static void uint8_t_Rever(uint8_t out[], const uint8_t in[], uint32_t byteLen)
{
    uint32_t i;
    for(i = 0u; i < byteLen; i++)
    {
        out[i] = in[byteLen - 1u - i];
    }
}

/* r:result, 32 bytes uint8_t big-endian convert to uint32_t little-endian with padding */
static void uint8_t_Radix_Rever(uint32_t out[SM2_RADIX_WORDLEN], const uint8_t in[SM2_BYTELEN])
{
    uint32_t i, j;
    for(i = 0u; i < 8u; i = i + 2u)
    {
        j = (i >> 1) * 7u;   
        out[i] = in[31u - j] | ((uint32_t)in[30u - j] << 8) | ((uint32_t)in[29u - j] << 16) | (((uint32_t)in[28u - j] << 28) >> 4);
        out[i + 1u] = ((uint32_t)in[28u - j] >> 4) | ((uint32_t)in[27u - j] << 4) | ((uint32_t)in[26u - j] << 12) | ((uint32_t)in[25u - j] << 20);
    }
    out[8] = in[3] | ((uint32_t)in[2] << 8) | ((uint32_t)in[1] << 16) | (((uint32_t)in[0] << 28) >> 4);
    out[9] = (uint32_t)in[0] >> 4;
}

/* uint32_t little-endian with padding convert to 32 bytes uint8_t big-endian */
static void Radix_uint8_t_Rever(uint8_t out[SM2_BYTELEN], const uint32_t in[SM2_RADIX_WORDLEN])
{
    uint32_t i, j;
    for(i = 0u; i < 8u; i = i + 2u)
    {
        j = (i >> 1) * 7u;
        out[31u - j]  = (uint8_t)in[i] & 0xffu;
        out[30u - j]  = (uint8_t)(in[i] >> 8) & 0xffu;
        out[29u - j]  = (uint8_t)(in[i] >> 16) & 0xffu;
        out[28u - j]  = ((uint8_t)(in[i] >> 24) & 0x0fu) | ((uint8_t)(in[i + 1u] << 4) & 0xf0u);
        out[27u - j]  = (uint8_t)(in[i + 1u] >> 4) & 0xffu;
        out[26u - j]  = (uint8_t)(in[i + 1u] >> 12) & 0xffu;
        out[25u - j]  = (uint8_t)(in[i + 1u] >> 20) & 0xffu;
    }
    out[3] = (uint8_t)in[8] & 0xffu; 
    out[2] = (uint8_t)(in[8] >> 8) & 0xffu;
    out[1] = (uint8_t)(in[8] >> 16) & 0xffu; 
    out[0] = ((uint8_t)(in[8] >> 24) & 0x0fu) | ((uint8_t)(in[9] << 4) & 0xf0u);
}

/* uint32_t little-endian convert to uint32_t little-endian with padding */
static void Radix_uint32_t(uint32_t out[SM2_RADIX_WORDLEN], const uint32_t in[SM2_WORDLEN])
{
    uint32_t i;
    out[0] =  (in[0] <<  4) >> 4; 
    for(i = 1u; i < 7u; i++)
    {
        out[i] = ((in[i] << (4u * (i + 1u))) >> 4) | (in[i - 1u] >> (4u * (8u - i)));
    }
    out[7] = in[6] >> 4;
    out[8] = (in[7] << 4) >> 4; 
    out[9] = in[7] >> 28;
}

/* uint32_t little-endian with padding convert to uint32_t little-endian */
static void Radix_uint32_t_Rever(uint32_t out[SM2_WORDLEN], const uint32_t in[SM2_RADIX_WORDLEN])
{
    uint32_t i;
    for(i = 0u; i < 7u; i++)
    {
        out[i] =  (in[i] >> (4u * i)) | (in[i + 1u] << (28u - (4u * i)));
    }	
    out[7] = (in[8]) | (in[9] << 28);
}

static void specialcarry(uint32_t a[SM2_RADIX_WORDLEN], const uint32_t lower[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint8_t i;
    uint32_t t;

    for(i = 0u; i < 9u; i++)
    {
        a[i + 1u] += a[i] >> RADIX_EXPO;
        a[i] &= RADIX_MINUS1;
    }
  
    t = a[9] >> 4u;  
    while(0u != t)
    {
        a[9] &= 0x0fu;
        for(i = 0u; i < 9u; i++)
        {
            a[i] += t * lower[i];
            a[i + 1u] += a[i] >> RADIX_EXPO;
            a[i] &= RADIX_MINUS1;
        }
        t = a[9] >> 4u;
    }
  
    while(0u != i)
    {
        if(a[i] < module[i])
        {
            return;
        }
        else if(a[i] > module[i])
        {
            for(i = 0u; i < 9u; i++)
            {
                a[i] +=  lower[i];
                a[i + 1u] += a[i] >> RADIX_EXPO;
                a[i] &= RADIX_MINUS1;
            }
            a[9] = a[9] & 0x0fu;
            return;
        }
        else
        {
            i--;
        }
    }
    for (i = 0u; i < 10u; i++)
    {
        a[i] = 0u;
    }
}

/* r should be less than n-1 */
static void Big_AddOne(uint32_t a[SM2_RADIX_WORDLEN])
{
    uint32_t i;
    a[0] += 1u;
    for(i = 0u; i < 9u; i++)
    {
        a[i + 1u] += a[i] >> RADIX_EXPO;
        a[i] &= RADIX_MINUS1;
    }
}

static void ModAdd(uint32_t out[SM2_RADIX_WORDLEN], const uint32_t a[SM2_RADIX_WORDLEN], const uint32_t b[SM2_RADIX_WORDLEN], const uint32_t lower[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint32_t i;
    for(i = 0u; i < SM2_RADIX_WORDLEN; i++)
    {
        out[i] = a[i] + b[i];
    }
    specialcarry(out, lower, module);
}

/* r could be x or y */
static void ModSub(uint32_t out[SM2_RADIX_WORDLEN], const uint32_t a[SM2_RADIX_WORDLEN], const uint32_t b[SM2_RADIX_WORDLEN], const uint32_t p_2[SM2_RADIX_WORDLEN], const uint32_t lower[9] , const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint32_t i;
    for(i = 0u; i < SM2_RADIX_WORDLEN; i++)
    {
        out[i] = a[i] - b[i];
        out[i] += p_2[i];
    }
    specialcarry(out, lower, module);
}


static void mul(uint64_t out[19], const uint32_t a[SM2_RADIX_WORDLEN], const uint32_t b[SM2_RADIX_WORDLEN])
{
    uint32_t i,j;	
    out[0] = (uint64_t)a[0] * (uint64_t)b[0];
    for(i = 1u; i < SM2_RADIX_WORDLEN; i++)
    {
        out[i] = (uint64_t)a[0] * (uint64_t)b[i];
        out[i + 9u] = (uint64_t)a[9] * (uint64_t)b[i];
    }
    for(i = 1u; i < 9u; i++)
    {
        for(j = 0u; j < SM2_RADIX_WORDLEN ; j++)
        {
            out[i+j] += (uint64_t)a[i] * (uint64_t)b[j];
        }
    }
    out[9] += (uint64_t)a[9] * (uint64_t)b[0];
}

static void mulsq(uint64_t out[19], const uint32_t in[SM2_RADIX_WORDLEN])
{
    /* Product scanning */
    uint32_t i,j;
  
    out[18] = (uint64_t)in[9] * (uint64_t)in[9];
    for(i = 0u; i < 9u; i++)
    {
        j = i << 1;
        out[j] = (uint64_t)in[i] * (uint64_t)in[i];
        out[j + 1u] = 0u;
    }
    for(i = 0u; i < SM2_RADIX_WORDLEN; i++)
    {
        for(j = i + 1u; j < SM2_RADIX_WORDLEN; j++)
        {
            out[i+j] += ((uint64_t)in[i] * (uint64_t)in[j]) << 1;
        }
    }
}

static void red2(uint32_t out[SM2_RADIX_WORDLEN], uint64_t a[19], const uint32_t lower[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint8_t i;
    uint64_t t;
    for(i = 0u; i < 9u; i++)
    {
        t = a[i] >> RADIX_EXPO;
        a[i] &= RADIX_MINUS1;
        a[i + 1u] += t;
    }

    t = a[9] >> 4;
    while (0u != t)
    {
        a[9] = a[9] & 0x0fu;
        for (i = 0; i < 9u; i++)
        {
            a[i] += t * lower[i];
            a[i + 1u] += a[i] >> RADIX_EXPO;
            a[i] &= RADIX_MINUS1;
        }
        t = a[9] >> 4;
    }

    while(0u != i)
    {
        if (a[i] < module[i])
        {
            break;
        }
        else if (a[i] > module[i])
        {
            for (i = 0; i < 9u; i++)
            {
                a[i] += lower[i];
                a[i + 1u] += a[i] >> RADIX_EXPO;
                a[i] &= RADIX_MINUS1;
            }
            a[9] = a[9] & 0x0fu;
            break;
        }
        else
        {
            i--;
        }
    }
    if(0u != i)
    {
        for (i = 0u; i < 10u; i++)
        {
            out[i] = (uint32_t)a[i];
        }
    }
    else
    {
        for (i = 0u; i < 10u; i++)
        {
            out[i] = 0;
        }
    }
}

static void red1(uint64_t a[19], uint32_t low, uint32_t high, const uint32_t lower[9])
{
    uint32_t i,j;
    for(i = low; i < (high - 1u); i++)
    {
        a[i + 1u] += a[i] >> RADIX_EXPO;
        a[i] &= RADIX_MINUS1;
    }
    for(i = SM2_RADIX_WORDLEN; i < high; i++)
    {
        for(j = 0u; j < 9u; j++)
        {
            a[i - SM2_RADIX_WORDLEN + j] += a[i] * lower[j];
        }
        a[i] = 0u;
    }
}


static void red0(uint64_t a[19], uint32_t high, const uint32_t lower[9])
{
    uint32_t i, j;
    i = high - 2u;
    a[i + 1u] += a[i] >> RADIX_EXPO;
    a[i] &= RADIX_MINUS1;

    while(i < high)
    {
        if (0u != a[i])
        {
            for (j = 0u; j < 9u; j++)
            {
                a[i - SM2_RADIX_WORDLEN + j] += a[i] * lower[j];
            }
            a[i] = 0u;
        }
        i++;
    }
}

/* reduction after a multiplication */
static void mulred(uint32_t out[SM2_RADIX_WORDLEN], uint64_t a[19], const uint32_t lower_1[9], const uint32_t lower_2[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    red0(a, 19u, lower_1);
    red0(a, 18u, lower_1);
    red0(a, 17u, lower_1);
    red0(a, 16u, lower_1);
    red0(a, 15u, lower_1);
    red0(a, 14u, lower_1);
    red0(a, 13u, lower_1);
    red0(a, 12u, lower_1);
    red1(a, 9u, 11u, lower_1);
    red2(out, a, lower_2, module);
}

static void mulred_P(uint32_t out[SM2_RADIX_WORDLEN], uint64_t a[19], const uint32_t lower_2[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint32_t i;
    uint64_t tmp;
    for (i = 0u; i < 18u; i++)
    {
        a[i + 1u] += a[i] >> RADIX_EXPO;
        a[i] &= RADIX_MINUS1;
    }
    tmp = (a[10] << 24) + (a[11] << 20);
    tmp += (a[12] << 16) + (a[13] << 12);
    tmp += (a[15] << 5) + (a[16] << 1);

    a[0] += tmp + (a[14] << 8) + (a[18] << 25);

    tmp += (a[14] << 9) + (a[18] * (uint64_t)0x03000000);
    a[8] += tmp;

    tmp = a[17] << 1;
    tmp += (a[11] << 24) + (a[12] << 20);
    tmp += (a[13] << 16) + (a[14] << 12);
    tmp += (a[15] << 8) + (a[16] << 5);
    a[1] += tmp;

    tmp = a[15] * (uint64_t)0x0FFFF000;
    tmp += a[16] * (uint64_t)0x0FFFFF00;
    tmp += (a[17] << 5) + (a[18] << 1);
    a[2] += tmp;

    tmp = a[11] * (uint64_t)0x0FFFFFFF;
    tmp += (a[10] * (uint64_t)0x0FFFFFF0);
    tmp += (a[13] << 24) + (a[14] << 20);
    tmp += (a[15] * (uint64_t)0x0001FFFF);
    tmp += (a[16] * (uint64_t)0x00000FFF);
    tmp += (a[17] * (uint64_t)0x0FFFFF00);
    a[3] += tmp;

    tmp = a[11] * (uint64_t)0x0FFFFFFF;
    tmp += a[10] * (uint64_t)0x000000FF;
    tmp += a[17] * (uint64_t)0x00000FFF;
    tmp += (a[14] << 24) + (a[15] << 20);
    tmp += (a[16] << 17) + (a[18] << 8);
    a[4] += tmp;

    tmp = a[11] * (uint64_t)0x000000FF;
    tmp += (a[15] << 24) + (a[16] << 20);
    tmp += (a[17] << 17) + (a[18] << 12);
    a[5] += tmp;

    tmp = (a[12] << 8) + (a[16] << 24);
    tmp += (a[17] << 20) + (a[18] << 17);
    a[6] += tmp;

    tmp = (a[13] << 8) + (a[17] << 24);
    a[7] += tmp + (a[18] << 20);
    a[9] = a[9] + (a[17] << 1);

    red2(out, a, lower_2, module);
}

static void ModMulP(uint32_t out[SM2_RADIX_WORDLEN], const uint32_t a[SM2_RADIX_WORDLEN], const uint32_t b[SM2_RADIX_WORDLEN], const uint32_t lower_2[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint64_t t[19];
    mul(t, a, b);
    mulred_P(out, t, lower_2, module);
}

static void ModSqP(uint32_t out[SM2_RADIX_WORDLEN], const uint32_t in[SM2_RADIX_WORDLEN], const uint32_t lower_2[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint64_t t[19];
    mulsq(t, in);
    mulred_P(out, t, lower_2, module);
}

static void ModMulN(uint32_t out[SM2_RADIX_WORDLEN], const uint32_t a[SM2_RADIX_WORDLEN], const uint32_t b[SM2_RADIX_WORDLEN], const uint32_t lower_1[9], const uint32_t lower_2[9], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint64_t t[19];
    mul(t, a, b);
    mulred(out, t, lower_1, lower_2, module);
}

static uint32_t Get_WordLen(const uint32_t a[], uint32_t wordLen)
{
    while (0u != wordLen)
    {
        if (0u != a[--wordLen])
        {
            return (wordLen + 1u);
        }
    }
    return 0u;
}

static uint32_t Big_Div2(uint32_t a[], uint32_t aWordLen)
{
    uint32_t i;
    
    if (0u == aWordLen)
    {    
        return 0u;
    }

    for (i = 0u; i< (aWordLen - 1u); i++)
    {
        a[i] >>= 1u;
        a[i] |= (a[i + 1u] << 31u) >> 4u;
    }
    a[i] >>= 1u;

    if (0u == a[i])
    {    
        return i;
    }
    return aWordLen;
}

static uint8_t Big_Compare1(const uint32_t a[], uint32_t aWordLen, const uint32_t b[], uint32_t bWordLen)
{
    aWordLen = Get_WordLen(a, aWordLen);
    bWordLen = Get_WordLen(b, bWordLen);

    if (aWordLen > bWordLen)
    {
        return 1u;
    }
    else if (aWordLen < bWordLen)
    {
        return 2u;
    }
    else
    {
        while(0u != aWordLen)		
        {	 
            --aWordLen;
            if(a[aWordLen] > b[aWordLen])
            {
                return 1u;
            }
            else if(a[aWordLen] < b[aWordLen])
            {
                return 2u;
            }
            else
            {
                continue;
            }
        }
        return 0u;
    }
}

static uint32_t Big_Add(uint32_t a[], uint32_t aWordLen, const uint32_t b[], uint32_t bWordLen)
{
    uint32_t i;
    uint32_t maxWordLen, minWordLen;

    if (0u == bWordLen)
    {
        return aWordLen;
    }		

    if (aWordLen > bWordLen)
    {
        maxWordLen = aWordLen;
        minWordLen = bWordLen;
    }
    else
    {
        maxWordLen = bWordLen;
        minWordLen = aWordLen;
    }

    for(i = 0u; i < minWordLen; i++)
    {    
        a[i] = a[i] + b[i];
    }

    if (aWordLen < bWordLen)
    {
        uint32_t_Copy(&a[aWordLen], &b[aWordLen], bWordLen - aWordLen);
    }

    for(i = 0u; i < (maxWordLen - 1u); i++)
    {
        a[i + 1u] += a[i] >> RADIX_EXPO;
        a[i] &= RADIX_MINUS1;
    }
    minWordLen = a[maxWordLen - 1u] >> RADIX_EXPO;
    if (0u != minWordLen)
    {
        a[maxWordLen] = minWordLen;
        a[maxWordLen - 1u] &= RADIX_MINUS1;
        return (maxWordLen + 1u);
    }
    return maxWordLen;
}

static uint32_t Big_Sub1(uint32_t a[], uint32_t aWordLen, const uint32_t b[], uint32_t bWordLen)
{
    uint32_t i, carry;

    if (0u == bWordLen)
    {
        return aWordLen;
    }  
    
    carry = 0;
    for (i = 0; i < bWordLen; i++)
    {
        a[i] = a[i] + (0x10000000u - b[i]);
        if (a[i] < carry)
        {
            a[i] += 0x10000000u - carry;
            carry = 2u;
        }
        else if (a[i] < (0x10000000u + carry))
        {
            a[i] -= carry;
            carry = 1u;
        }
        else
        {
            a[i] -= (0x10000000u + carry);
            carry = 0u;
        }
    }

    for (; i<aWordLen; i++)
    {
        if (a[i] < carry)
        {
            a[i] += 0x10000000u - carry;
            carry = 1u;
        }
        else
        {
            a[i] -= carry;
            break;
        }
    }
    return Get_WordLen(a, aWordLen);
}

static uint32_t Big_Subb(const uint32_t a[], uint32_t aWordLen, uint32_t b[], uint32_t bWordLen)
{
    uint32_t i, carry;
    carry = 0u;	
    for (i = 0u; i < bWordLen; i++)
    {
        b[i] = a[i] + (0x10000000u - b[i]);
        if (b[i] < carry)
        {
            b[i] += 0x10000000u - carry;
            carry = 2u;
        }
        else if (b[i] < (0x10000000u + carry))
        {
            b[i] -= carry;
            carry = 1u;
        }
        else
        {
            b[i] -= (0x10000000u + carry);
            carry = 0;
        }
    }
    uint32_t_Copy(&b[bWordLen], &a[bWordLen], aWordLen - bWordLen);

    for (; i<aWordLen; i++)
    {
        if (b[i] < carry)
        {
            b[i] += 0x10000000u - carry;
            carry = 1u;
        }
        else
        {
            b[i] -= carry;
            break;
        }
    }
    return Get_WordLen(b, aWordLen);
}

static uint8_t Big_Sign_Add(uint32_t a[], uint8_t flag_a, uint32_t *aWordLen, const uint32_t b[], uint8_t flag_b, uint32_t bWordLen)
{
    if (flag_a == flag_b)    // a and b same signed
    {
        *aWordLen = Big_Add(a, *aWordLen, b, bWordLen);
    }
    else
    {
        if (Big_Compare1(a, *aWordLen, b, bWordLen) < 2u)    // |a|>=|b|
        {
            *aWordLen = Big_Sub1(a, *aWordLen, b, bWordLen);
        }
        else    // |a|<|b|
        {
            *aWordLen = Big_Subb(b, bWordLen, a, *aWordLen);
            return flag_b;
        }
    }
    return flag_a;
}

static uint8_t Big_Sign_Sub(uint32_t a[], uint8_t flag_a, uint32_t *aWordLen, uint32_t b[], uint8_t flag_b, uint32_t bWordLen)
{
    if(0u != (flag_a ^ flag_b)) // flag_a=0,flag_b=1 or flag_a=1,flag_b=0
    {
        *aWordLen = Big_Add(a, *aWordLen, b, bWordLen);
    }
    else
    {
        if (Big_Compare1(a, *aWordLen, b, bWordLen) < 2u) // |a|>=|b|
        {
            *aWordLen = Big_Sub1(a, *aWordLen, b, bWordLen);
        }
        else // |a|<|b|
        {
            *aWordLen = Big_Subb(b, bWordLen, a, *aWordLen);
            return (flag_b ^ 1u);
        }
    }
    return flag_a;
}

static void ModInv(uint32_t out[SM2_RADIX_WORDLEN], const uint32_t a[SM2_RADIX_WORDLEN], const uint32_t module[SM2_RADIX_WORDLEN])
{
    uint32_t u[SM2_RADIX_WORDLEN], v[SM2_RADIX_WORDLEN], x1[SM2_RADIX_WORDLEN], x2[SM2_RADIX_WORDLEN];
    uint32_t uWordLen, vWordLen, x1WordLen, x2WordLen;
    uint8_t flag_x1, flag_x2, flag;

    uint32_t xWordLen = Get_WordLen(a, SM2_RADIX_WORDLEN);

    uint32_t_Clear(u, SM2_RADIX_WORDLEN);
    uint32_t_Clear(v, SM2_RADIX_WORDLEN);
    uint32_t_Clear(x1, SM2_RADIX_WORDLEN);
    uint32_t_Clear(x2, SM2_RADIX_WORDLEN);

    //0:positive; 1: negative
    flag_x1=0;
    flag_x2=0;

    /* x1*x+y1*n=u, x2*x+y2*n=v*/
    uint32_t_Copy(u, a, xWordLen);
    uint32_t_Copy(v, module, SM2_RADIX_WORDLEN);
    x1[0] = 1;

    uWordLen=xWordLen;
    vWordLen=SM2_RADIX_WORDLEN;
    x1WordLen=1;
    x2WordLen=0;
	if((uWordLen == 1u) && (u[0] == 1u))
	{
        uint32_t_Clear(out, SM2_RADIX_WORDLEN);
		out[0] = 1u;
		return;
	}
    for(;;)
    {
        while(0u == (u[0] & 1u))
        {
            uWordLen = Big_Div2(u,uWordLen);
            if(0u != (x1[0] & 1u))
            {
                flag_x1 = Big_Sign_Add(x1, flag_x1, &x1WordLen, module, 0, SM2_RADIX_WORDLEN);
            }
            x1WordLen=Big_Div2(x1,x1WordLen);
        }

        while(0u == (v[0] & 1u))
        {
            vWordLen=Big_Div2(v,vWordLen);
            if(0u != (x2[0] & 1u))
            {
                flag_x2 = Big_Sign_Add(x2, flag_x2, &x2WordLen, module, 0, SM2_RADIX_WORDLEN);
            }
            x2WordLen=Big_Div2(x2,x2WordLen);
        }

        flag = Big_Compare1(u,uWordLen,v,vWordLen);
        if(flag == 1u) // u>v
        {
            uWordLen = Big_Sub1(u,uWordLen,v,vWordLen);
            flag_x1 = Big_Sign_Sub(x1, flag_x1, &x1WordLen, x2, flag_x2, x2WordLen);
        }
        else if(flag == 2u)         // u<v
        {
            vWordLen = Big_Sub1(v,vWordLen,u,uWordLen);
            flag_x2 = Big_Sign_Sub(x2,flag_x2,&x2WordLen,x1,flag_x1,x1WordLen);
        }
        else // u==v
        {
            while(Big_Compare1(x1, x1WordLen, module, SM2_RADIX_WORDLEN) == 1u)
            {
                x1WordLen = Big_Sub1(x1,x1WordLen, module,SM2_RADIX_WORDLEN);
            }		
            if(0u != flag_x1)
            {
                (void)Big_Subb(module,SM2_RADIX_WORDLEN,x1,x1WordLen);
            }		
            if((uWordLen == 1u) && (u[0] == 1u))
            {
                uint32_t_Copy(out, x1, SM2_RADIX_WORDLEN);  //not U32_Copy(xinv, x1, x1WordLen); to avoid the case that high part all zero
            }
            break;
        }
    }
}

static void ECCP_Point2Char(uint8_t *c, const ECCP_POINT *P)
{
    c[0] = 0x04u;
    Radix_uint8_t_Rever(&c[1], P->x);  
    Radix_uint8_t_Rever(&c[1u + SM2_BYTELEN], P->y);  
}

static void ECCP_Char2Point(ECCP_POINT *P, const uint8_t *c)
{
    uint8_t_Radix_Rever(P->x, &c[1]);        
    uint8_t_Radix_Rever(P->y, &c[1u + SM2_BYTELEN]);  
}

/* 0(k is in [1,n-1]); other(k equals 0 or k >= n) */
static OSR_SM2_RET_CODE ECCP_IntegerCheck(const uint32_t k[], const uint32_t n[], uint32_t wordLen)
{
    if(1u == Big_ChkZero(k, wordLen)) 
    {
        return OSR_SM2ZeroALL;
    }
    else if(2u != Big_Compare(k, n, wordLen)) 
    {
        return OSR_SM2IntegerTooBig;
    }
    else
    {
        return OSR_SM2Success;
    }
}

static void ECCP_Point2JacobiPoint(ECCP_JACOBIPOINT *Pout, const ECCP_POINT *Pin)
{
    uint32_t_Copy(Pout->x, Pin->x, SM2_RADIX_WORDLEN);
    uint32_t_Copy(Pout->y, Pin->y, SM2_RADIX_WORDLEN);
    uint32_t_Clear(Pout->z, SM2_RADIX_WORDLEN);
    Pout->z[0] = 1u;
} 

static OSR_SM2_RET_CODE ECCP_JacobiPoint2Point(ECCP_POINT *Pout, const ECCP_JACOBIPOINT *Pin, ECCP_playground *playground)
{
    if(1u == Big_ChkZero(Pin->z,SM2_RADIX_WORDLEN))
    {
        return OSR_SM2ZeroALL;
    }
    Big_ModInv_P(playground->t0, Pin->z);
    Big_ModSq_P(playground->t1, playground->t0);
    Big_ModMul_P(Pout->x, Pin->x, playground->t1);
    Big_ModMul_P(playground->t1, playground->t1, playground->t0);
    Big_ModMul_P(Pout->y, Pin->y, playground->t1);
    return OSR_SM2Success;
}

/* a = -3 */
static void ECCP_JacobiPoint_Double(ECCP_JACOBIPOINT *Pin, ECCP_playground *playground)
{
    if(1u == Big_ChkZero(Pin->z,SM2_RADIX_WORDLEN))
    {
        return;
    }
    Big_ModSq_P(playground->t0, Pin->x);          /* XX =X^2    */
    Big_ModSq_P(playground->t1, Pin->y);          /* YY = Y^2   */
    Big_ModSq_P(playground->t2, playground->t1);           /* YYYY = YY^2  */
    Big_ModSq_P(playground->t3, Pin->z);                   /* ZZ = Z^2    */
    Big_ModAdd_P(playground->t4, Pin->x, playground->t1);  /*  X1 + YY    */
    Big_ModAdd_P(Pin->z, Pin->y, Pin->z);
    Big_ModSq_P(Pin->z, Pin->z);            /* Z = (Y +Z)^2    */
    Big_ModAdd_P(playground->t1, playground->t1, playground->t3);    /* t1 = YY + ZZ    */
    Big_ModSub_P(Pin->z, Pin->z, playground->t1);        /* Z = (Y+Z)^2 - YY - ZZ    */
    Big_ModSq_P(playground->t4, playground->t4);         /* (X1 + YY)^2    */
    Big_ModSub_P(playground->t4, playground->t4, playground->t0);        /* (X1 + YY)^2 - XX    */
    Big_ModSub_P(playground->t4, playground->t4, playground->t2);        /* (X1 + YY)^2 - XX - YYYY   */
    Big_ModAdd_P(playground->t4, playground->t4, playground->t4);        /* 2*(X1 + YY)^2 - XX - YYYY   */
    Big_ModSq_P(playground->t3, playground->t3);        /* t3 = ZZ^2    */
    Big_ModSub_P(playground->t3, playground->t0, playground->t3);        /* t3 = xx - ZZ^2    */
    Big_ModAdd_P(playground->t0, playground->t3, playground->t3);
    Big_ModAdd_P(playground->t3, playground->t0, playground->t3);        /* 3*(XX - ZZ^2);    */
    Big_ModSq_P(Pin->x, playground->t3);        /* X = t3 ^ 2    */
    Big_ModSub_P(Pin->x, Pin->x, playground->t4);         
    Big_ModSub_P(Pin->x, Pin->x, playground->t4);        /* X = t3^2 - 2*t4    */
    Big_ModSub_P(Pin->y, playground->t4, Pin->x);         
    Big_ModMul_P(Pin->y, Pin->y, playground->t3);         
    Big_ModAdd_P(playground->t2, playground->t2, playground->t2);       
    Big_ModAdd_P(playground->t2, playground->t2, playground->t2);       
    Big_ModAdd_P(playground->t2, playground->t2, playground->t2);       
    Big_ModSub_P(Pin->y, Pin->y, playground->t2);        
}
  
static void ECCP_Jacobi_Affine_Point_Add(ECCP_JACOBIPOINT *Pin, const ECCP_POINT *Pin2, ECCP_playground *playground)
{
    if(1u == Big_ChkZero(Pin->z, SM2_RADIX_WORDLEN))
    {
        uint32_t_Copy(Pin->x, Pin2->x, SM2_RADIX_WORDLEN);
        uint32_t_Copy(Pin->y, Pin2->y, SM2_RADIX_WORDLEN);
        Pin->z[0] = 1u;
        return;
    }
    
    Big_ModSq_P(playground->t0, Pin->z);            /* playground[0]=Z1Z1= Z1^2    */
    Big_ModMul_P(playground->t1, Pin2->x, playground->t0);    /* playground[1]=U2= X2*Z1^2    */
    Big_ModMul_P(playground->t2, Pin2->y, Pin->z);            /* Y2*Z1    */
    Big_ModMul_P(playground->t2, playground->t2, playground->t0);        /* playground[2]=S2= Y2*Z1*Z1^2    */
    
    if(0u == Big_Compare(playground->t1, Pin->x, SM2_RADIX_WORDLEN))
    {
        if(0u == Big_Compare(playground->t2, Pin->y, SM2_RADIX_WORDLEN))
        {
            ECCP_JacobiPoint_Double(Pin,playground);
        }
        else
        {
            uint32_t_Clear(Pin->z, SM2_RADIX_WORDLEN);
        }
        return;
    }
    
    Big_ModSub_P(playground->t2, playground->t2, Pin->y);        /* R8 = S2-Y1    */
    Big_ModAdd_P(playground->t2, playground->t2, playground->t2);        /* t2 = r = 2*(S2-Y1)    */
    Big_ModSub_P(playground->t3, playground->t1, Pin->x);        /* t3 = H    */
    Big_ModSq_P(playground->t4, playground->t3);            /* t4 = HH    */
    Big_ModAdd_P(playground->t1, playground->t4, playground->t4); 
    Big_ModAdd_P(playground->t4, playground->t4, playground->t0);        /* t4 = Z1Z1 + HH    */
    Big_ModAdd_P(Pin->z, Pin->z,  playground->t3);     /* Z1 + H    */
    Big_ModSq_P(Pin->z, Pin->z);             
    Big_ModSub_P(Pin->z, Pin->z, playground->t4);            /* (Z1 + H)^2 - Z1Z1 - HH    */
    Big_ModAdd_P(playground->t1, playground->t1, playground->t1);        /* t1 = I= 4*HH  */
    Big_ModMul_P(playground->t0, playground->t3, playground->t1);        /* t0 = J = H*J  */
    Big_ModMul_P(playground->t3, Pin->x, playground->t1);        /* t3 = v = X1 * I    */
    Big_ModAdd_P(Pin->x, playground->t3, playground->t3);            /* 2*v    */
    Big_ModAdd_P(Pin->x, Pin->x, playground->t0);            /* J + 2*v    */
    Big_ModSq_P(playground->t1, playground->t2);            /* t1 = r^2    */
    Big_ModSub_P(Pin->x, playground->t1, Pin->x);            /* X = X3 = r^2 - J - 2*v    */
    Big_ModSub_P(playground->t3, playground->t3, Pin->x);            /* t3 = V-X3    */
    Big_ModMul_P(playground->t3, playground->t3, playground->t2);        /* t3 = r*(V-X3)    */
    Big_ModMul_P(playground->t0, playground->t0, Pin->y);            /* Y1*J    */
    Big_ModAdd_P(playground->t0, playground->t0, playground->t0);        /* t0 =    2*Y1*J    */
    Big_ModSub_P(Pin->y, playground->t3, playground->t0);        /* Y1 = Y3 = r*(V-X3) - 2*Y1 *J    */
}

/* Function:  ECC GF(p) test point P in or not in the curve
 * Parameters:
 *     P ----------- input, affine point
 * Return: 1(in the curve); 0(not in the curve)
 * Caution:
 */
static uint32_t ECCP_TestPoint(const ECCP_POINT *P)
{
    uint32_t tmp[SM2_RADIX_WORDLEN], tmp2[SM2_RADIX_WORDLEN];
    Big_ModSq_P(tmp, P->x);                      /* tmp=x^2        */ 
    Big_ModMul_P(tmp, tmp, P->x);                /* tmp=x^3        */
    Big_ModMul_P(tmp2, sm2p256v1_a, P->x);       /* tmp=a*x        */
    Big_ModAdd_P(tmp, tmp2, tmp);                /* tmp=a*x+x^3    */
    Big_ModAdd_P(tmp, sm2p256v1_b, tmp);         /* tmp=a*x+x^3+b  */
    Big_ModSq_P(tmp2, P->y);                     /* tmp2=y^2    */
    return Big_Compare(tmp, tmp2, SM2_RADIX_WORDLEN);
}

/* a:little-endian */
static uint32_t Get_BitLen(const uint32_t a[])
{
    uint32_t i, j, s;
    for(i = SM2_WORDLEN - 1u; i > 0u; i--)
    {
        s = 0x80000000u;
        for(j = 32u; j > 0u; j--)
        {
            if(0u != (s & a[i]))
            {
                return ((uint32_t)i << 5) + (uint32_t)j;
            }
            s >>= 1u;
        }
    }
	s = 0x80000000u;
    for(j = 32u; j > 0u; j--)
    {
        if(0u != (s & a[0]))
        {
            return j;
        }
        s >>= 1u;
    }
    return 0u;
}

/* Function: get aimed bit value of big integer a
 * Parameters:
 *     a ----------- big integer a
 *     bitLen ------ aimed bit location
 * Return: 
 *     bit value of aimed bit
 * Caution:
 *     1. make sure bitLen > 0
 */
static uint32_t Get_BitValue(const uint32_t a[], uint32_t bitLen)
{
    bitLen--;
    if(0u != (a[(bitLen) >> 5u] & ((uint32_t)1u << (bitLen & 31u))))
    {
        return 1u;
    }
    else
    {
        return 0u;
    }
}

/* Function:  get bit value of uint32_t big integer for COMB method
 * Parameters:
 *     a ----------- uint32_t big integer
 *     aBitLen ----- bit length of a
 *     bitLen ------ bit location, begins from 1.
 * Return: 0(the bit value is 0); 1(the bit value is 1)
 * Caution:
 */
static uint32_t ECCP_Comb_Get_BitValue(const uint32_t a[], uint32_t aBitLen, uint32_t bitLen)
{
    if (bitLen > SM2_BITLEN)
    {
        return 0u;
    }
    else if (bitLen > aBitLen)
    {
        return 0u;
    }
    else
    {
        return Get_BitValue(a, bitLen);
    }
}

/* k is little-endian */
static void ECCP_PointMul(ECCP_POINT *Q, const uint32_t k[], const ECCP_POINT *P)
{
    uint32_t j;
    ECCP_playground playground;
    ECCP_JACOBIPOINT Jcb_Point;
    
    uint32_t_Copy(Jcb_Point.x, P->x, SM2_RADIX_WORDLEN);
    uint32_t_Copy(Jcb_Point.y, P->y, SM2_RADIX_WORDLEN);
    uint32_t_Clear(Jcb_Point.z, SM2_RADIX_WORDLEN);
    Jcb_Point.z[0] = 1u;
    j = Get_BitLen(k);  
    while(0u != (--j)) 
    {
        ECCP_JacobiPoint_Double(&Jcb_Point, &playground);
        if(0u != Get_BitValue(k,j))
        {
            ECCP_Jacobi_Affine_Point_Add(&Jcb_Point, P, &playground);
        }
    }	
    (void)ECCP_JacobiPoint2Point(Q, &Jcb_Point, &playground);   /* if Jcb_Point is O */
}

static void ECCP_PointMul_G(ECCP_POINT *Q, const uint32_t *k)
{
    uint32_t i, j, kBitLen;
    uint32_t index = 0;	
    ECCP_playground playground;
    ECCP_JACOBIPOINT Jcb_Point;
    
    kBitLen = Get_BitLen(k);    
    for(i = 0; i < 52u; i++)
    {
        index = 0;
        for(j = 0; j < 5u; j++)
        {
            index <<= 1;
            index |= ECCP_Comb_Get_BitValue(k, kBitLen, ((5u - j) * 52u) - i);        
        }
        if(0u != index)
        {
            break;
        }
    }
    ECCP_Point2JacobiPoint(&Jcb_Point, &SM2_COMB_iG[index - 1u]); 
    i++;
    for(;i < 52u; i++)
    {
        ECCP_JacobiPoint_Double(&Jcb_Point, &playground);

        index = 0;
        for(j = 0; j < 5u; j++)
        {
            index <<= 1;
            index |= ECCP_Comb_Get_BitValue(k, kBitLen, ((5u - j) * 52u) - i);          
        }
        if(0u != index)
        {
            ECCP_Jacobi_Affine_Point_Add(&Jcb_Point, &SM2_COMB_iG[index-1u], &playground);
        }
    }
    (void)ECCP_JacobiPoint2Point(Q, &Jcb_Point, &playground);    /* if Jcb_Point is O */
}


 //P = tmp * P2  + s * P1
static OSR_SM2_RET_CODE ECCP_Point_Mul_Shamir(ECCP_POINT *P1, const ECCP_POINT *P2, const uint32_t tmp[], const uint32_t s[])
{
    int8_t i,j;
    uint32_t d;
    ECCP_playground playground;
    ECCP_JACOBIPOINT Jcb_Point;
    ECCP_POINT Q;
    const ECCP_POINT *pPoint[3];
    
    uint32_t_Copy(Jcb_Point.x, P1->x, SM2_RADIX_WORDLEN);
    uint32_t_Copy(Jcb_Point.y, P1->y, SM2_RADIX_WORDLEN);
    uint32_t_Clear(Jcb_Point.z, SM2_RADIX_WORDLEN);
    Jcb_Point.z[0] = 1u;	

    ECCP_Jacobi_Affine_Point_Add(&Jcb_Point, P2, &playground);
    (void)ECCP_JacobiPoint2Point(&Q, &Jcb_Point, &playground);

    uint32_t_Clear(Jcb_Point.x, SM2_RADIX_WORDLEN);
    uint32_t_Clear(Jcb_Point.y, SM2_RADIX_WORDLEN);
    uint32_t_Clear(Jcb_Point.z, SM2_RADIX_WORDLEN);
    Jcb_Point.x[0] = 1;
    Jcb_Point.y[0] = 1;
	
    pPoint[0] = P1;
    pPoint[1] = P2;
    pPoint[2] = &Q;

    for (i = 7; i >= 0; i--) 
    {
        for (j = 31; j >= 0; j--)
        {
            d = (((tmp[i] >> (uint8_t)j ) << 1u) & 0x2u) | ((s[i] >> (uint8_t)j) & 0x1u);
            ECCP_JacobiPoint_Double(&Jcb_Point, &playground);
            if (0u != d)
            {
                ECCP_Jacobi_Affine_Point_Add(&Jcb_Point, pPoint[d - 1u], &playground);
            }
        }
    }
    return ECCP_JacobiPoint2Point(P1, &Jcb_Point, &playground);   //if Jcb_Point is O
}



/* Function: C = A XOR B
 * Parameters:
 * Return: 
 * Caution:
 */
static void SM2_XOR(uint8_t *C, const uint8_t *A, const uint8_t *B, uint32_t byteLen) 
{
    while(0u != byteLen)
    {
        --byteLen;
        C[byteLen] = A[byteLen] ^ B[byteLen];
    }
}

/* Function: Generate Z value = SM3(bitLenofID||ID||a||b||Gx||Gy||Px||Py)
 * Parameters:
 *     ID     -------- User ID
 *     byteLenofID --- byte length of ID, less than 2^13
 *     pubKey -------- public key, 65 bytes
 *     Z      -------- Z value, 32 bytes
 * Return: 
 *     0(all OK); else(error)
 * Caution:
 *     1. bit length of ID must less than 2^16, thus byte lenth must less than 2^13
 */
OSR_SM2_RET_CODE OSR_SM2_GetZ(const uint8_t *ID, uint16_t byteLenofID, const uint8_t pubKey[65], uint8_t Z[SM3_DIGEST_BYTELEN])
{
    uint8_t tmp[2];
    OSR_SM3_Ctx md[1];

    if((NULL == ID) || (NULL == pubKey) || (NULL == Z))
    {
        return OSR_SM2BufferNull;
    }
    if(byteLenofID > SM_MAX_ID_LEN)
    {
        return OSR_SM2InputLenInvalid;
    }
#if 1
    if(0x04u != pubKey[0])
    {
        return OSR_SM2PointHeadNot04;
    }
#endif
    byteLenofID <<= 3u;
    tmp[1] = (uint8_t)byteLenofID & 0xFFu;
    tmp[0] = (uint8_t)(byteLenofID >> 8) & 0xFFu;
    byteLenofID >>= 3u;

    (void)OSR_SM3_Init(md);	
    (void)OSR_SM3_Process(md, tmp, 2);
    (void)OSR_SM3_Process(md, ID, byteLenofID);
    Radix_uint8_t_Rever(Z, sm2p256v1_a);
    (void)OSR_SM3_Process(md, Z, SM2_BYTELEN);	
    Radix_uint8_t_Rever(Z, sm2p256v1_b);
    (void)OSR_SM3_Process(md, Z, SM2_BYTELEN);		
    Radix_uint8_t_Rever(Z, SM2_COMB_iG[0].x);
    (void)OSR_SM3_Process(md, Z, SM2_BYTELEN);	
    Radix_uint8_t_Rever(Z, SM2_COMB_iG[0].y);
    (void)OSR_SM3_Process(md, Z, SM2_BYTELEN);
#if 1
    (void)OSR_SM3_Process(md, &pubKey[1], SM2_BYTELEN << 1u);
#endif
    //(void)OSR_SM3_Process(md, pubKey, SM2_BYTELEN << 1u);
    (void)OSR_SM3_Done(md, Z);	
    return OSR_SM2Success;
}

/* Function: Generate E value = SM3(Z||M)
 * Parameters:
 *     M      -------- Message
 *     byteLen ------- byte length of M
 *     Z      -------- Z value, 32 bytes
 *     E      -------- E value, 32 bytes
 * Return: 
 *     0(all OK); else(error)
 * Caution:
 */
OSR_SM2_RET_CODE OSR_SM2_GetE(const uint8_t *M, uint32_t byteLen, const uint8_t Z[SM3_DIGEST_BYTELEN], uint8_t E[SM3_DIGEST_BYTELEN])
{
    OSR_SM3_Ctx md[1];

    if((NULL == M) || (NULL == Z) || (NULL == E))
    {
        return OSR_SM2BufferNull;
    }

    (void)OSR_SM3_Init(md);
    (void)OSR_SM3_Process(md, Z, 32u);
    (void)OSR_SM3_Process(md, M, byteLen);
    (void)OSR_SM3_Done(md, E);

    return OSR_SM2Success;
}

/* Function: SM2 KDF(Key Derivation Function)
 * Parameters:
 *     Z      -------- input key
 *     zByteLen --- -- byte length of Z
 *     K      -------- output key
 *     kByteLen --- -- byte length of K
 * Return: 
 * Caution:
 */
static void SM2_KDF(const uint8_t *Z , uint32_t zByteLen, uint8_t *K, uint32_t kByteLen)
{
    uint8_t Hash[SM3_DIGEST_BYTELEN];
    uint32_t i, t;
    uint32_t count = 1u;   
    OSR_SM3_Ctx md[1];

    t = kByteLen >> 5; 
    for(i = 0u; i < t; i++)
    {
        (void)OSR_SM3_Init(md);
        (void)OSR_SM3_Process(md, Z, zByteLen);
        Hash[0] = (uint8_t)(count >> 24u);
        Hash[1] = (uint8_t)(count >> 16u);
        Hash[2] = (uint8_t)(count >> 8u);
        Hash[3] = (uint8_t)count;		
        (void)OSR_SM3_Process(md, Hash, 4u);        
        (void)OSR_SM3_Done(md, &(K[i << 5u]));
        count++;
    }

    if(0u != (kByteLen & 0x1fu))
    {
        (void)OSR_SM3_Init(md);
        (void)OSR_SM3_Process(md, Z, zByteLen);
        Hash[0] = (uint8_t)(count >> 24u);
        Hash[1] = (uint8_t)(count >> 16u);
        Hash[2] = (uint8_t)(count >> 8u);
        Hash[3] = (uint8_t)count;
        (void)OSR_SM3_Process(md, Hash, 4u);
        (void)OSR_SM3_Done(md, Hash);
        (void)memcpy(&(K[t << 5u]), Hash, kByteLen & 0x1Fu);
    }
}

OSR_SM2_RET_CODE OSR_SM2_GetKey(uint8_t priKey[SM2_BYTELEN], uint8_t pubKey[65])
{
	uint32_t k[SM2_WORDLEN];
    ECCP_POINT Q;
	
    if((NULL == priKey) || (NULL == pubKey))
    {
        return OSR_SM2BufferNull;
    }

    /* make sure 0 < k < n-1, namely k in [1,n-2] */
    do
    {
        GetRandU32(k, SM2_WORDLEN);
        Radix_uint32_t(Q.x, k);
    }while(OSR_SM2Success != ECCP_IntegerCheck(Q.x, SM2_n_minus_1_padding, SM2_RADIX_WORDLEN));

    /* get public key Q = kG */
    ECCP_PointMul_G(&Q, k);

    /* little-endian to big-endian */
    uint8_t_Rever(priKey, (uint8_t *)k, SM2_BYTELEN);
    ECCP_Point2Char(pubKey, &Q);

    return OSR_SM2Success;
}

OSR_SM2_RET_CODE OSR_SM2_Sign(const uint8_t E[SM2_BYTELEN], const uint8_t priKey[SM2_BYTELEN], uint8_t signature[64])
{
    OSR_SM2_RET_CODE flag;
    uint32_t k[SM2_WORDLEN];
    uint32_t tmp[SM2_RADIX_WORDLEN], dA[SM2_RADIX_WORDLEN];
    ECCP_POINT P;

    if((NULL == E) || (NULL == priKey) || (NULL == signature))
    {
        return OSR_SM2BufferNull;
    }

    /* make sure dA in [1, n-2]	*/
    uint8_t_Radix_Rever(tmp, priKey);	
    flag = ECCP_IntegerCheck(tmp, SM2_n_minus_1_padding, SM2_RADIX_WORDLEN);
    if(OSR_SM2Success != flag)
    {
        return flag;
    }

    Big_AddOne(tmp);
    Big_ModInv_N(dA, tmp);

    uint8_t_Radix_Rever(tmp, E);
    if(2u != Big_Compare(tmp, sm2p256v1_n, SM2_RADIX_WORDLEN))  
    {
        Big_ModSub_N(tmp, tmp, sm2p256v1_n);
    }

    for( ; ; ) 
    {
        GetRandU32(k, SM2_WORDLEN);
        Radix_uint32_t(P.y, k);
        if(OSR_SM2Success != ECCP_IntegerCheck(P.y, sm2p256v1_n, SM2_RADIX_WORDLEN))
        {
            continue;
        }
        ECCP_PointMul_G(&P, k);                               /* P = kG */
        if(2u != Big_Compare(P.x, sm2p256v1_n, SM2_RADIX_WORDLEN))  /* if px >= n, then get px mod n */
        {
            Big_ModSub_N(P.x, P.x, sm2p256v1_n);
        }

        Big_ModAdd_N(P.x, tmp, P.x);                   /* Px = (e+Px) mod n    */
        if(1u == Big_ChkZero(P.x, SM2_RADIX_WORDLEN))  /* make sure r not Zero */
        {
            continue;
        }
        Radix_uint32_t(tmp, k);
        Big_ModAdd_N(tmp, tmp, P.x);                  /* tmp = r + k */
        if(1u == Big_ChkZero(tmp, SM2_RADIX_WORDLEN)) /* make sure r+k != n */
        {
            continue;
        }
        Big_ModMul_N(tmp, tmp, dA); /* (1+dA)^(-1) * (k+r) */
        Big_ModSub_N(tmp, tmp, P.x);
        if(1u == Big_ChkZero(tmp, SM2_RADIX_WORDLEN)) 
        {
            continue;
        }
        else
        {
            break;       
        }
    }
    Radix_uint8_t_Rever(signature, P.x);
    Radix_uint8_t_Rever(&signature[SM2_BYTELEN], tmp);
    return OSR_SM2Success;
}

OSR_SM2_RET_CODE OSR_SM2_Verify(const uint8_t E[SM2_BYTELEN], const uint8_t pubKey[65], const uint8_t signature[64])
{
    OSR_SM2_RET_CODE flag;
    uint32_t tmp[SM2_WORDLEN];
    uint32_t rr[SM2_RADIX_WORDLEN], s[SM2_RADIX_WORDLEN];
    ECCP_POINT P;
    const ECCP_POINT *pG = &(SM2_COMB_iG[0]);
    if((NULL == E) || (NULL == pubKey) || (NULL == signature))
    {
        return OSR_SM2BufferNull;
    }

    if(0x04u != pubKey[0])
    {
        return OSR_SM2PointHeadNot04;
    }

    /* make sure r in [1, n-1] */
    uint8_t_Radix_Rever(rr, signature);
    flag = ECCP_IntegerCheck(rr, sm2p256v1_n, SM2_RADIX_WORDLEN);
    if(OSR_SM2Success != flag)
    {
        return flag;
    }

    uint8_t_Radix_Rever(s, &signature[SM2_BYTELEN]);	
    flag = ECCP_IntegerCheck(s, sm2p256v1_n, SM2_RADIX_WORDLEN);  /* make sure s in [1, n-1] */
    if(OSR_SM2Success != flag)
    {
        return flag;
    }

    Big_ModAdd_N(s, s, rr);                        /* s = r+s mod n      */
    if(1u == Big_ChkZero(s, SM2_RADIX_WORDLEN))   /* t can not be Zero  */
    {
        return OSR_SM2ZeroALL;
    }

    ECCP_Char2Point(&P, pubKey);
    if(0u != ECCP_TestPoint(&P))      /* make sure pubKey valid */
    {   
        return OSR_SM2PubKeyError;
    }  

    uint8_t_Rever((uint8_t *)tmp, &signature[SM2_BYTELEN], SM2_BYTELEN);

    Radix_uint32_t_Rever(s, s);
    flag = ECCP_Point_Mul_Shamir(&P, pG, tmp, s); //P = tmp * G + s * P
    if(OSR_SM2Success != flag)
    {
        return OSR_SM2NotInCurve;
    }
    uint8_t_Radix_Rever(s, E);
    if(2u != Big_Compare(s, sm2p256v1_n, SM2_RADIX_WORDLEN))  
    {
        Big_ModSub_N(s, s, sm2p256v1_n);
    }
	
    Big_ModAdd_N(s, s, P.x); 	   /* r = (e+Px) mod n */
	
    if(0u == Big_Compare(s, rr, SM2_RADIX_WORDLEN))
    {
        return OSR_SM2Success;
    }
    else
    {		
        return OSR_SM2VerifyFailed;
    }
}

void swapC2C3(uint8_t *C, uint32_t MByteLen)
{
	uint8_t *C2 = NULL;
	uint8_t C3[SM2_BYTELEN] = {0};

	C2 = (uint8_t *)malloc(MByteLen);
	memcpy(C2, C + (2u * SM2_BYTELEN) + 1u, MByteLen);
	memcpy(C3, C + (2u * SM2_BYTELEN) + 1u + MByteLen, SM2_BYTELEN);

	memcpy(C + (2u * SM2_BYTELEN) + 1u, C3, SM2_BYTELEN);
	memcpy(C + (2u * SM2_BYTELEN) + 1u + SM2_BYTELEN, C2, MByteLen);

	//dump_mem1(C2, MByteLen, "SM2 C2");
	//dump_mem1(C3, SM2_BYTELEN, "SM2 C3");
}
void swapC3C2(uint8_t *C, uint32_t MByteLen)
{
	uint8_t *C2 = NULL;
	uint8_t C3[SM2_BYTELEN] = {0};

	C2 = (uint8_t *)malloc(MByteLen);
	memcpy(C3, C + (2u * SM2_BYTELEN) + 1u, SM2_BYTELEN);
	memcpy(C2, C + (2u * SM2_BYTELEN) + 1u + SM2_BYTELEN, MByteLen);

	memcpy(C + (2u * SM2_BYTELEN) + 1u, C2, MByteLen);
	memcpy(C + (2u * SM2_BYTELEN) + 1u + MByteLen, C3, SM2_BYTELEN);

	//dump_mem1(C2, MByteLen, "SM2 C2");
	//dump_mem1(C3, SM2_BYTELEN, "SM2 C3");
}
OSR_SM2_RET_CODE OSR_SM2_Encrypt(const uint8_t *M, uint32_t MByteLen, const uint8_t pubKey[65], uint8_t tag, uint8_t *C, uint32_t *CByteLen) 
{
    uint8_t *C2, tmp[64];
    ECCP_POINT Ps;
    OSR_SM3_Ctx md[1];

    if((NULL == M) || (NULL == pubKey) || (NULL == C) || (NULL == CByteLen))
    {
        return OSR_SM2BufferNull;
    }

    if(0u == MByteLen) 
    {
        return OSR_SM2InputLenInvalid;
    }

    if(0x04u != pubKey[0])
    {
        return OSR_SM2PointHeadNot04;
    }

    if(M == C)
    {
        return OSR_SM2InOutSameBuffer;
    }

    for( ; ; ) 
    {
        GetRandU32(md[0].wbuf, SM2_WORDLEN);
        Radix_uint32_t(Ps.x, md[0].wbuf);
        if(OSR_SM2Success != ECCP_IntegerCheck(Ps.x, sm2p256v1_n, SM2_RADIX_WORDLEN))
        {
            continue;
        }
										
        ECCP_PointMul_G(&Ps, md[0].wbuf); 				 /* Ps = kG */
        ECCP_Point2Char(C, &Ps); 					 /* get C1  */

	//dump_mem1(C, 65, "SM2 C1");
		
        ECCP_Char2Point(&Ps, pubKey);
        if(0u != ECCP_TestPoint(&Ps))
        {	
            return OSR_SM2NotInCurve;
        }
        (void)ECCP_PointMul(&Ps, md[0].wbuf, &Ps);		     /* Ps = k(Pb) */
        if(0u == tag)
        {
            C2 = &C[(2u * SM2_BYTELEN) + 1u];
        }
        else
        {
            C2 = &C[(3u * SM2_BYTELEN) + 1u];
        }
        Radix_uint8_t_Rever(tmp, Ps.x); 
        Radix_uint8_t_Rever(tmp + SM2_BYTELEN, Ps.y);
        SM2_KDF(tmp, 2u * SM2_BYTELEN, C2, MByteLen);
        if(1u == uint8_t_ChkZero(C2, MByteLen))
        {
            continue;
        }
        else
        {
            SM2_XOR(C2, M, C2, MByteLen);		     /* get C2  */
	    // dump_mem1(C2, MByteLen, "SM2 C2");
	    //dump_mem1(C, (2u * SM2_BYTELEN) + 1u+MByteLen, "SM2 C1 C2");
            (void)OSR_SM3_Init(md);
            (void)OSR_SM3_Process(md, tmp, SM2_BYTELEN);
            (void)OSR_SM3_Process(md, M, MByteLen);
            (void)OSR_SM3_Process(md, tmp + SM2_BYTELEN, SM2_BYTELEN);
            /* get C3  */
            if(0u == tag)
            {
                C2 = &C[(2u * SM2_BYTELEN) + 1u + MByteLen];
            }
            else
            {
                C2 = &C[(2u * SM2_BYTELEN) + 1u];
            }
            (void)OSR_SM3_Done(md, C2);
            *CByteLen = MByteLen + (3u * SM2_BYTELEN) + 1u;
	    swapC2C3(C, MByteLen);
            return OSR_SM2Success;
        }
    }
}

/* Function: SM2 Decryption
 * Parameters:
 *     C           ------ ciphertext, CByteLen bytes, big-endian
 *     CByteLen    ------ byte length of C, make sure MByteLen>97
 *     priKey[32]  ------ private key, 32 bytes, big-endian
 *     M           ------ plaintext, MByteLen bytes, big-endian
 *     MByteLen    ------ byte length of M, thus CByteLen-97
 * Return: 
 *     0(all OK); else(error)
 * Caution:
 *     1. must be called after SM2_Init();
 *     2. M and C can not be the same buffer
 */
OSR_SM2_RET_CODE OSR_SM2_Decrypt(const uint8_t *C, uint32_t CByteLen, const uint8_t priKey[SM2_BYTELEN], uint8_t tag, uint8_t *M, uint32_t *MByteLen)
{
    OSR_SM3_Ctx md[1];
    ECCP_POINT Ps;
    uint8_t tmp[64];
    const uint8_t *C2;
    OSR_SM2_RET_CODE flag;
    uint32_t byteLen; 

    if((NULL == C) || (NULL == priKey) || (NULL == M) || (NULL == MByteLen))
    {
        return OSR_SM2BufferNull;
    }
    if(0x04u != C[0])
    {
        return OSR_SM2PointHeadNot04;
    }
    if(CByteLen <= ((3u * SM2_BYTELEN) + 1u))    
    {
        return OSR_SM2InputLenInvalid;
    }
    if(M == C)
    {
        return OSR_SM2InOutSameBuffer;
    }
    
    byteLen = CByteLen - (1u + (3u * SM2_BYTELEN));
 
    swapC3C2(C, byteLen);

    ECCP_Char2Point(&Ps, C);
    if(0u != ECCP_TestPoint(&Ps))          /* make sure C1 in Curve */
    {
        return OSR_SM2NotInCurve;
    }

    uint8_t_Radix_Rever(md[0].wbuf, priKey);
    flag = ECCP_IntegerCheck(md[0].wbuf, SM2_n_minus_1_padding, SM2_RADIX_WORDLEN);
    if(OSR_SM2Success != flag)
    {
        return flag;
    }
    uint8_t_Rever((uint8_t *)(md[0].hash), priKey, SM2_BYTELEN);
    (void)ECCP_PointMul(&Ps, md[0].hash, &Ps);    /* Ps = dB(C1)=dB(kG)=k(dB(G))=k(PB) */
    if(0u != ECCP_TestPoint(&Ps))
    {
        return OSR_SM2NotInCurve;
    }

    Radix_uint8_t_Rever(tmp, Ps.x); 
    Radix_uint8_t_Rever(tmp + SM2_BYTELEN, Ps.y);
    SM2_KDF(tmp, 2u * SM2_BYTELEN, M, byteLen);	
    if(0u != uint8_t_ChkZero(M, byteLen))
    {
        return OSR_SM2ZeroALL;
    }
    if(0u == tag)
    {
        SM2_XOR(M, &C[(2u * SM2_BYTELEN) + 1u], M, byteLen);
    }
    else
    {
        SM2_XOR(M, &C[(3u * SM2_BYTELEN) + 1u], M, byteLen);
    }
    (void)OSR_SM3_Init(md);
    (void)OSR_SM3_Process(md, tmp, SM2_BYTELEN);
    (void)OSR_SM3_Process(md, M, byteLen);
    (void)OSR_SM3_Process(md, tmp + SM2_BYTELEN, SM2_BYTELEN);
    (void)OSR_SM3_Done(md, tmp);	
    if(0u == tag)
    {
        C2 = &C[(2u * SM2_BYTELEN) + 1u + byteLen];
    }
    else
    {
        C2 = &C[(2u * SM2_BYTELEN) + 1u];
    }

    if(0 != memcmp(tmp, C2, SM2_BYTELEN))
    {
        return OSR_SM2DecryVerifyFailed;
    }
    else
    {
        *MByteLen = byteLen;
        return OSR_SM2Success;
    }
}

#ifdef OSR_ExchangeKey_SM2
/* 16 bytes uint8_t big-endian convert to uint32_t little-endian with padding */
static void uint8_t_Radix_Rever_1(uint32_t out[SM2_RADIX_WORDLEN], const uint8_t in[16])
{
    uint32_t i, j;
    for(i = 0u; i < 4u; i = i + 2u)
    {
        j = (i >> 1) * 7u;
        out[i] = in[15u - j] | ((uint32_t)in[14u - j] << 8) | ((uint32_t)in[13u - j] << 16) | (((uint32_t)in[12u - j] << 28) >> 4);
        out[i + 1u] = ((uint32_t)in[12u - j] >> 4) | ((uint32_t)in[11u - j] << 4) | ((uint32_t)in[10u - j] << 12) | ((uint32_t)in[9u - j] << 20);
    }
    out[4] = in[1] | ((uint32_t)in[0] << 8);
    for(i = 5u; i < SM2_RADIX_WORDLEN; i++)
    {
        out[i] = 0u;
    }
}

/* Function: SM2 Key Exchange
 * Parameters:
 *     role        ------ 1 - sender, 0 - receiver
 *     dA[32]      ------ sender's private key
 *     PB[65]      ------ sender's public key
 *     rA[32]      ------ sender's temporary private key
 *     RA[65]      ------ sender's temporary public key
 *     RB[65]      ------ receiver's temporary public key
 *     ZA[32]      ------ sender's Z_value
 *     ZB[32]      ------ receiver's Z_value
 *     kByteLen    ------ key bytelen, should be less than (2^32 - 1)bit
 *     KA[kByteLen]------ key
 *     S1[32]      ------ sender's S1 or receiver's SB
 *     SA[32]      ------ sender's SA or receiver's S2
 * Return: 
 *     0(all OK); else(error)
 * Caution:
 *     1. S1 should be equal to SB, S2 should be equal to SA. 
 */
OSR_SM2_RET_CODE OSR_SM2_ExchangeKey(const uint8_t role, const uint8_t *dA, const uint8_t *PB, const uint8_t *rA, const uint8_t *RA, const uint8_t *RB, const uint8_t *ZA, const uint8_t *ZB, uint32_t kByteLen, uint8_t *KA, uint8_t *S1, uint8_t *SA)
{
    uint32_t tA[SM2_RADIX_WORDLEN];  
    uint8_t U[128];
    ECCP_POINT U_point1, U_point2;
    OSR_SM3_Ctx md[1];
    OSR_SM2_RET_CODE flag;
	
    if((NULL == dA) || (NULL == PB) || (NULL == rA) || (NULL == RA) || (NULL == RB))
    {
        return OSR_SM2BufferNull;
    }

    if((NULL == ZA) || (NULL == ZB) || (NULL == KA) || (NULL == S1) || (NULL == SA))
    {
        return OSR_SM2BufferNull;
    }

    if((0x04u != PB[0]) || (0x04u != RB[0]))
    {
        return OSR_SM2PointHeadNot04;
    }

    if((0u != role) && (1u != role))
    {
        return OSR_SM2ExchangeRoleInvalid;
    }

    if(0u == kByteLen)
    {
        return OSR_SM2InputLenInvalid;
    }

    uint8_t_Radix_Rever_1(md[0].wbuf, &RA[17]);     /* for 0x04    */
    md[0].wbuf[4] |= 0x8000u;                  /* for w = 127 */

    uint8_t_Radix_Rever(tA, rA);
    flag = ECCP_IntegerCheck(tA, SM2_n_minus_1_padding, SM2_RADIX_WORDLEN);
    if(OSR_SM2Success != flag)
    {
        return flag;
    }
    Big_ModMul_N(tA, md[0].wbuf, tA);  /* tA = x1*rA mod n */                                           
    uint8_t_Radix_Rever(md[0].wbuf, dA);
    flag = ECCP_IntegerCheck(md[0].wbuf, SM2_n_minus_1_padding, SM2_RADIX_WORDLEN);
    if(OSR_SM2Success != flag)
    {
        return flag;
    }
    Big_ModAdd_N(tA, tA, md[0].wbuf);  /* tA = (dA + x1*rA) mod n */

    uint8_t_Radix_Rever_1(md[0].wbuf, &RB[17]);     /* for 0x04    */
    md[0].wbuf[4] |= 0x8000u;                  /* for w = 127 */

    ECCP_Char2Point(&U_point1, RB);
    if(0u != ECCP_TestPoint(&U_point1))
    {
        return OSR_SM2NotInCurve;
    }
    Big_ModMul_N(md[0].wbuf, md[0].wbuf, tA); // x1 = x1*tA mod n
    Radix_uint32_t_Rever(md[0].wbuf, md[0].wbuf);	
    Radix_uint32_t_Rever(tA, tA);
    ECCP_Char2Point(&U_point2, PB);
    if (OSR_SM2ZeroALL == ECCP_Point_Mul_Shamir(&U_point1, &U_point2, tA, md[0].wbuf)) //P = tA * Pb + x1 * Rb
    {
        return OSR_SM2ZeroPoint;
    }

    Radix_uint8_t_Rever(U,  U_point1.x);
    Radix_uint8_t_Rever(U+SM2_BYTELEN,  U_point1.y);
    if(1u == role)   /* sender */
    {
        (void)memcpy(&U[SM2_BYTELEN * 2u], ZA, SM2_BYTELEN);		
        (void)memcpy(&U[SM2_BYTELEN * 3u], ZB, SM2_BYTELEN);
    }
    else                              /* receiver */
    {
        (void)memcpy(&U[SM2_BYTELEN * 2u], ZB, SM2_BYTELEN);
        (void)memcpy(&U[SM2_BYTELEN * 3u], ZA, SM2_BYTELEN);
    }

    SM2_KDF(U, SM2_BYTELEN * 4u, KA, kByteLen);  

    (void)OSR_SM3_Init(md);
    (void)OSR_SM3_Process(md, U, SM2_BYTELEN);
    if(1u == role)
    {
        (void)OSR_SM3_Process(md, ZA, SM2_BYTELEN);
        (void)OSR_SM3_Process(md, ZB, SM2_BYTELEN);
        (void)OSR_SM3_Process(md, &RA[1], SM2_BYTELEN << 1u);
        (void)OSR_SM3_Process(md, &RB[1], SM2_BYTELEN << 1u);
    }
    else
    {
        (void)OSR_SM3_Process(md, ZB, SM2_BYTELEN);
        (void)OSR_SM3_Process(md, ZA, SM2_BYTELEN);
        (void)OSR_SM3_Process(md, &RB[1], SM2_BYTELEN << 1u);
        (void)OSR_SM3_Process(md, &RA[1], SM2_BYTELEN << 1u);
    }
    (void)OSR_SM3_Done(md, S1);

    (void)memcpy(&U[SM2_BYTELEN * 2u], S1, SM2_BYTELEN);
    U[SM2_BYTELEN - 1u] = 0x03u;
    (void)OSR_SM3_Init(md);
    (void)OSR_SM3_Process(md, &U[SM2_BYTELEN - 1u], (SM2_BYTELEN * 2u) + 1u);
    if(1u == role)
    {
        (void)OSR_SM3_Done(md, SA);
    }
    else
    {
        (void)OSR_SM3_Done(md, S1);
    }

    U[SM2_BYTELEN - 1u] = 0x02u;
    (void)OSR_SM3_Init(md);
    (void)OSR_SM3_Process(md, &U[SM2_BYTELEN - 1u], (SM2_BYTELEN * 2u) + 1u);
    if(1u == role)
    {
        (void)OSR_SM3_Done(md, S1);
    }
    else
    {
        (void)OSR_SM3_Done(md, SA);
    }

    return OSR_SM2Success;
}
#endif


OSR_SM2_RET_CODE OSR_SM2_Version(uint8_t version[4])
{
	version[0] = 0x01;   
	version[1] = 0x02;   
	version[2] = 0x01;   
	version[3] = 0x00;  

	return OSR_SM2Success;
}
