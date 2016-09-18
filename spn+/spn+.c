
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include "..\gmp.h"
#include "spn+.h"

Key spn_Key;	//SPN密钥结构
unsigned char spn_Sub[SBOX_LENGTH], spn_rSub[SBOX_LENGTH];	//S, P盒置换LUT
unsigned char spn_Per[sBits * sNum], spn_rPer[sBits * sNum];	//S, P盒逆置换

//AES-S盒替换
const unsigned char spn_Sub_default[256] =
{
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};
//默认的P置换
const unsigned char spn_Per_default[sBits * sNum] = 
{ 
	0x08, 0x11, 0x1A, 0x23, 0x2C, 0x35, 0x3E, 0x09,
	0x10, 0x19, 0x22, 0x2B, 0x34, 0x3D, 0x00, 0x12,
	0x1B, 0x24, 0x2D, 0x36, 0x3F, 0x01, 0x0A, 0x1D,
	0x21, 0x2E, 0x37, 0x3C, 0x02, 0x0B, 0x13, 0x20,
	0x28, 0x33, 0x38, 0x03, 0x0C, 0x14, 0x18, 0x30, 
	0x31, 0x39, 0x04, 0x0D, 0x15, 0x1F ,0x26, 0x29,
	0x3A, 0x05, 0x0E, 0x16, 0x1C, 0x3B, 0x06, 0x0F,
	0x07, 0x17, 0x1E, 0x25, 0x27, 0x2A, 0x2F, 0x32
};

//配置默认的S盒P盒
int spn_Init()
{
	spn_SetSub((unsigned char*)spn_Sub_default);
	spn_SetPer((unsigned char*)spn_Per_default);
	return 0;
}

//配置SPN网络的轮密钥
int spn_SetKey(MainKey inputKey)
{
	mpz_init(spn_Key.initKey);
	mpz_set(spn_Key.initKey, inputKey);
	KeyGen(&spn_Key);
	return 0;
}

//SPN轮密钥编排算法
int KeyGen(Key* key)
{
	int round;
	mpz_t temp;
	mpz_init(temp);
	mpz_set(temp, key->initKey);
	for (round = 0; round <= RoundNum; round++) {
		mpz_tdiv_q_2exp(temp, key->initKey, RoundNum * 4 - round * 4);
		mpz_export(&(key->roundKey[round]), NULL, -1, sizeof(unsigned long long), 0, 0, temp);
	}
	mpz_clear(temp);
	return 0;
}

//配置input指向缓冲区为SPN的S盒
int spn_SetSub(unsigned char* input)
{
	int i;
	for (i = 0; i < pow(2, sBits); i++)
		spn_Sub[i] = input[i];
	//调用reverse导出S盒的逆替换
	reverse(spn_Sub, spn_rSub, SBOX_LENGTH);
	return 0;
}

//配置input指向缓冲区为SPN的P盒
int spn_SetPer(unsigned char* input)
{
	int i;
	for (i = 0; i < sBits * sNum; i++)
		spn_Per[i] = input[i];
	//调用reverse导出P盒的逆替换
	reverse(spn_Per, spn_rPer, sBits * sNum);
	return 0;
}

//对input的数据进行P盒置换
spn_Text Permutation(spn_Text input, unsigned char* per)
{
	spn_Text bitmask, output = 0;
	int i;
	for (i = 0, bitmask = 0x1; i < sBits * sNum; i++) {
		if ((per[i] - i) >= 0)
			output = output | ((input & bitmask) << (per[i] - i));
		else
			output = output | ((input & bitmask) >> (i - per[i]));
		bitmask = bitmask * 2;
	}
	return output;
}

//对input的数据进行S盒替换
spn_Text Substitution(spn_Text input, unsigned char* sub)
{
	int i;
	unsigned char temp;
	spn_Text output = 0;
	for (i = 0; i < sNum; i++) {
		temp = SBox((input >> sBits * i) & 0xff, sub) ;
		output = ((spn_Text)temp << (sBits * i)) | output;
	}
	return output;
}

//单字节的S盒替换
//使用LUT快速实现
char SBox(unsigned char input, unsigned char* sub)
{
	return sub[input];
}

//导出origianl中length长度变换的逆变换
//变换结果写入已分配空间的reversed
//可用于SPN结构的S盒与P盒
void reverse(unsigned char* original, unsigned char* reversed, int length)
{
	int i;
	for (i = 0; i < length; i++)
		reversed[original[i]] = i;
}

//SPN网络底层元数据加密
spn_Text spn_Encrypt_raw(spn_Text *plain, spn_Text *cypher)
{
	int round;
	spn_Text temp;
	temp = *plain;
	for (round = 0; round < RoundNum - 1; round++) {
		temp = temp ^ spn_Key.roundKey[round];
		temp = Substitution(temp, spn_Sub);
		temp = Permutation(temp, spn_Per);
	}
	temp = temp ^ spn_Key.roundKey[round++];
	temp = Substitution(temp, spn_Sub);
	temp = temp ^ spn_Key.roundKey[round];
	*cypher = temp;
	return temp;
}

//SPN网络底层元数据解密
spn_Text spn_Decrypt_raw(spn_Text *plain, spn_Text *cypher)
{
	int round = RoundNum;
	spn_Text temp;
	temp = *cypher;
	temp = temp ^ spn_Key.roundKey[round--];
	temp = Substitution(temp, spn_rSub);
	for ( ; round > 0; round--) {
		temp = temp ^ spn_Key.roundKey[round];
		temp = Permutation(temp, spn_rPer);
		temp = Substitution(temp, spn_rSub);
	}
	temp = temp ^ spn_Key.roundKey[round];
	*plain = temp;
	return temp;
}

//CBC模式下SPN网络一次元数据加密
void spn_Encrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect)
{
	spn_Text temp;
	temp = *plain ^ *vect;
	spn_Encrypt_raw(&temp, cypher);
}

//CBC模式下SPN网络一次元数据解密
void spn_Decrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect)
{
	spn_Text temp;
	spn_Decrypt_raw(&temp, cypher);
	*plain = temp ^ *vect;
}

//CBC模式的文件加密
int spn_Encrypt_cbc(FILE *fp, FILE *efp, MainKey sessionKey, spn_Text *initVect)
{
	clock_t t1, t2;
	unsigned long long i, size, rblock;
	spn_Text plain, cypher, vect;

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);	//文件大小 (字节数)
	rewind(fp);	//还原文件指针

	i = 0;
	plain = 0;
	spn_SetKey(sessionKey);	
	vect = *initVect;
	printf("加密开始>>>\n");
	t1 = clock();	//开始计时
	while (fread(&plain, sizeof(spn_Text), 1, fp)) {
		#ifdef FILE_SHOW_STATUS
			printf("\r--------%.2lf%%--------", ((double)i * sizeof(spn_Text) / size) * 100);
		#endif
		spn_Encrypt_cbc_raw(&plain, &cypher, &vect);
		if (fwrite(&cypher, sizeof(spn_Text), 1, efp) == 0) {
			printf("加密数据写入失败.\n");
			return 2;
		}
		plain = 0;
		vect = cypher;
		i++;
	}
	//当存在短块时进行短块处理
	//采用pkcs#7 v1.5标准填充
	//rblock记录要填充的字节数
	rblock = sizeof(spn_Text) - (int)(size - i * sizeof(spn_Text));
	if (rblock) {
		for (i = 1; i <= rblock; i++) {
			plain = plain ^ (rblock << (8 * (sizeof(spn_Text) - i)));
		}
	}
	else {
		//满块时额外填充一块0xffff...
		plain = -1;
	}
	spn_Encrypt_cbc_raw(&plain, &cypher, &vect);
	if (fwrite(&cypher, sizeof(spn_Text), 1, efp) == 0) {
		printf("加密<短块>数据写入失败.\n");
		return 2;
	}
	t2 = clock();	//结束计时
	printf("\r--------100%%--------");
	printf("\n文件加密完毕.\n");
	printf("本次加密耗时 : %ld ms\n", t2 - t1);
	return 0;
}

//CBC模式的文件解密
int spn_Decrypt_cbc(FILE *fp, FILE *dfp, MainKey sessionKey, spn_Text *initVect)
{
	clock_t t1, t2;
	char pad;
	unsigned long long i, size, hpos;
	spn_Text plain, cypher, vect;

	hpos = ftell(fp);	//文件头位置(会话参数)
	fseek(fp, 0, SEEK_END);
	size = ftell(fp) - hpos;	//文件大小 (分组长度)
	fsetpos(fp, &hpos);	//还原文件指针

	i = 1;
	plain = 0;
	spn_SetKey(sessionKey);
	vect = *initVect;
	printf("解密开始>>>\n");
	t1 = clock();	//开始计时
	while (i * sizeof(spn_Text) < size) {
		fread(&cypher, sizeof(spn_Text), 1, fp);
		#ifdef FILE_SHOW_STATUS
			printf("\r--------%.2lf%%--------", ((double)i * sizeof(spn_Text) / size) * 100);
		#endif
		spn_Decrypt_cbc_raw(&plain, &cypher, &vect);
		if (fwrite(&plain, sizeof(spn_Text), 1, dfp) == 0) {
			printf("解密数据写入失败.\n");
			return 2;
		}
		vect = cypher;
		i++;
	}
	//当i<size时进行短块处理
	//采用pkcs#7 v1.5标准填充
	//rblock记录多出的字节数
	fread(&cypher, sizeof(spn_Text), 1, fp);
	spn_Decrypt_cbc_raw(&plain, &cypher, &vect);
	pad = (spn_Text)0xff & (plain >> 56);
	if (pad < sizeof(spn_Text)) {
		for (i = 1; i <= pad; i++) {
			plain = plain ^ ((spn_Text)pad << (8 * (sizeof(spn_Text) - i)));
		}
		if (fwrite(&plain, sizeof(spn_Text) - pad, 1, dfp) == 0) {
			printf("解密<短块>数据写入失败.\n");
			return 2;
		}
	}
	t2 = clock();	//结束计时
	printf("\r--------100%%--------");
	printf("\n文件解密完毕.\n");
	printf("本次解密耗时 : %ld ms\n", t2 - t1);
	return 0;
}

//以CBC模式生成指定字节大小的二进制密文数据
//用于随机性检测
int mgen()
{
	FILE *fp;
	long int i, size, max;
	spn_Text plain, cypher, vect;
	plain = 0;
	srand((unsigned int)time(NULL));
	vect = rand() * rand() * rand() % 0xffffffffffffffff;
	if ((fp = fopen("spn2.dat", "wb")) == NULL) {
		printf("Error creating file.\n");
		getchar();
		return 1;
	}
	printf("CBC模式初始向量:%llx\n", vect);
	printf("导出数据文件大小 (mb) : ");
	scanf("%ld", &size);
	max = size * 1024 * 1024 * 8 / (sBits * sNum);
	for (i = 0; i < max; i++) {
		//printf("\r--------%.1f%%--------", ((double)i/max)*100);
		spn_Encrypt_cbc_raw((spn_Text*)&i, &cypher, &vect);
		fwrite(&cypher, sizeof(spn_Text), 1, fp);
		vect = cypher;
	}
	printf("\n数据导出完毕.");
	fclose(fp);
	getchar();
	return 0;
}

int spn_test()
{
	int i, op = 1;
	MainKey inputKey;
	spn_Text plain, cypher;
	gmp_randstate_t state;	//GMP随机数状态
	mpz_init(inputKey);
	spn_Init();
	while (op) {
		printf("增强SPN测试程序\n");
		printf("-------------------\n");
		printf("1.随机生成SPN主密钥 %d bit\n", SPN_KEY_LENGTH);
		printf("2.使用SPN 加密\n");
		printf("3.导出测试文件\n");
		printf("0.返回上级菜单\n");
		scanf("%d", &op);
		getchar();
		if (op > 3) {
			printf("错误操作项.\n");
			getchar();
			continue;
		}
		else if (op == 0) {
			return 0;
		}
		switch (op) {
		case 1:
			gmp_randinit_lc_2exp_size(state, 128);	//设置随机数状态state
			gmp_randseed_ui(state, (unsigned long)time(NULL));
			mpz_urandomb(inputKey, state, SPN_KEY_LENGTH);	//生成随机数num
			gmp_printf("Main Key %d bit : %Zx\n", SPN_KEY_LENGTH, inputKey);
			spn_SetKey(inputKey);
			for (i = 0; i <= RoundNum; i++)
				printf("> roundKey[%d] = %#llx\n", i + 1, spn_Key.roundKey[i]);
			break;
		case 2:
			printf("明文输入 (64 bit): ");
			scanf("%llx", &plain);
			getchar();
			printf("加密后密文 (64 bit): %#llx \n", spn_Encrypt_raw(&plain, &cypher));
			printf("解密后明文 (64 bit): %#llx ", spn_Decrypt_raw(&plain, &cypher));
			break;
		case 3:
			mgen();
			break;
		}
		getchar();
	}
	getchar();
	return 0;
}