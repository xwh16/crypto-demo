
#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include"spn.h"

//默认的S盒替换
const unsigned char spn_Sub_default[sBits * sNum] = { 0xe, 0x4, 0xd, 0x1,
												0x2, 0xf, 0xb, 0x8,
												0x3, 0xa, 0x6, 0xc,
												0x5, 0x9, 0x0, 0x7 };
//默认的P置换
const unsigned char spn_Per_default[sBits * sNum] = { 0x0, 0x4, 0x8, 0xc,
												0x1, 0x5, 0x9, 0xd,
												0x2, 0x6, 0xa, 0xe,
												0x3, 0x7, 0xb, 0xf };
Key *spn_Key;
unsigned char *spn_Sub, *spn_Per, *spn_rSub, *spn_rPer;

int spn_Init()
{
	spn_Key = (Key*)malloc(sizeof(Key));
	spn_Sub = (unsigned char*)malloc(sizeof(unsigned char) * pow(2, sBits));
	spn_rSub = (unsigned char*)malloc(sizeof(unsigned char) * pow(2, sBits));
	spn_Per = (unsigned char*)malloc(sizeof(unsigned char) * pow(2, sBits));
	spn_rPer = (unsigned char*)malloc(sizeof(unsigned char) * pow(2, sBits));
	spn_SetSub((unsigned char*)spn_Sub_default);
	spn_SetPer((unsigned char*)spn_Per_default);
	return 0;
}

int spn_Destroy()
{
	free(spn_Key);
	free(spn_Sub);
	free(spn_rSub);
	free(spn_Per);
	free(spn_rPer);
	return 0;
}

int spn_SetKey(MainKey input)
{
	spn_Key->initKey = input;
	KeyGen(spn_Key);
	return 0;
}

static int KeyGen(Key* key)
{
	int round;
	for (round = 0; round <= RoundNum; round++) {
		key->roundKey[round] = key->initKey >> ((RoundNum - round) * 4);
	}
	return 0;
}

int spn_SetSub(unsigned char* buffer)
{
	int i, j;
	for (i = 0; i < pow(2, sBits); i++) {
		for (j = i + 1; j < pow(2, sBits); j++) {
			if (buffer[i] == buffer[j])
				return 1;
		}
	}
	for (i = 0; i < pow(2, sBits); i++)
		spn_Sub[i] = buffer[i];
	reverse(spn_Sub, spn_rSub);
	return 0;
}

int spn_SetPer(unsigned char* buffer)
{
	int i, j;
	for (i = 0; i < pow(2, sBits); i++) {
		for (j = i + 1; j < pow(2, sBits); j++) {
			if (buffer[i] == buffer[j])
				return 1;
		}
	}
	for (i = 0; i < pow(2, sBits); i++)
		spn_Per[i] = buffer[i];
	reverse(spn_Per, spn_rPer);
	return 0;
}

void reverse(unsigned char* original, unsigned char* reversed)
{
	int i;
	for (i = 0; i < pow(2, sBits); i++)
		reversed[original[i]] = i;
}

spn_Text Permutation(spn_Text input, unsigned char* per)
{
	unsigned short output = 0;
	int i, bits;
	for (i = 0, bits = 0x1; i < sBits * sNum; i++) {
		if ((per[i] - i) >= 0)
			output = output | ((input & bits) << (per[i] - i));
		else
			output = output | ((input & bits) >> (i - per[i]));
		bits = bits * 2;
	}
	return output;
}

spn_Text Substitution(spn_Text input, unsigned char* sub)
{
	unsigned short output;
	output = ((SBox((input >> 12) & 0xf, sub) & 0xf) << 12) |
		((SBox((input >> 8) & 0xf, sub) & 0xf) << 8) |
		((SBox((input >> 4) & 0xf, sub) & 0xf) << 4) |
		((SBox(input & 0xf, sub) & 0xf));
	return output;
}

unsigned char SBox(unsigned char input, unsigned char* sub)
{
	return sub[input];
}

spn_Text spn_Encrypt_raw(spn_Text *plain, spn_Text *cypher)
{
	int round;
	spn_Text temp;
	temp = *plain;
	for (round = 0; round < RoundNum - 1; round++) {
		temp = temp ^ spn_Key->roundKey[round];
		temp = Substitution(temp, spn_Sub);
		temp = Permutation(temp, spn_Per);
	}
	temp = temp ^ spn_Key->roundKey[round++];
	temp = Substitution(temp, spn_Sub);
	temp = temp ^ spn_Key->roundKey[round];
	*cypher = temp;
	return temp;
}

spn_Text spn_Decrypt_raw(spn_Text *plain, spn_Text *cypher)
{
	int round = RoundNum;
	spn_Text temp;
	temp = *cypher;
	temp = temp ^ spn_Key->roundKey[round--];
	temp = Substitution(temp, spn_rSub);
	for ( ; round > 0; round--) {
		temp = temp ^ spn_Key->roundKey[round];
		temp = Permutation(temp, spn_rPer);
		temp = Substitution(temp, spn_rSub);
	}
	temp = temp ^ spn_Key->roundKey[round];
	*plain = temp;
	return temp;
}

spn_Text spn_Encrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect)
{
	spn_Text temp;
	temp = *plain ^ *vect;
	spn_Encrypt_raw(&temp, cypher);
}

spn_Text spn_Decrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect)
{
	spn_Text temp;
	spn_Decrypt_raw(&temp, cypher);
	*plain = temp ^ *vect;
}

int mgen()
{
	int m;
	long int i, size, max;
	FILE *fp;
	spn_Text plain, cypher, vect;
	plain = 0;
	vect = 0x1f56;
	if ((fp = fopen("spn1.dat", "wb")) == NULL) {
		printf("Error creating file.\n");
		getchar();
		return 1;
	}
	printf("CBC模式初始向量:%hx\n", vect);
	printf("导出数据文件大小 (mb) : ");
	scanf("%ld", &size);
	max = size * 1024 * 1024 * 8 / (sBits * sNum);
	for (i = 0; i < max; i++) {
		//printf("\r--------%.1f%%--------", ((double)i/max)*100);
		spn_Encrypt_cbc_raw(&plain, &cypher, &vect);
		fwrite(&cypher, sizeof(spn_Text), 1, fp);
		vect = cypher;
	}
	printf("\n数据导出完毕.");
	fclose(fp);
	getchar();
	return 0;
}
