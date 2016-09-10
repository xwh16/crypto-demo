
#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<math.h>
#include"spn.h"

//默认的S盒替换
const mapping spn_Sub_default[sBits * sNum] = { 0xe, 0x4, 0xd, 0x1,
												0x2, 0xf, 0xb, 0x8,
												0x3, 0xa, 0x6, 0xc,
												0x5, 0x9, 0x0, 0x7 };
//默认的P置换
const mapping spn_Per_default[sBits * sNum] = { 0x0, 0x4, 0x8, 0xc,
												0x1, 0x5, 0x9, 0xd,
												0x2, 0x6, 0xa, 0xe,
												0x3, 0x7, 0xb, 0xf };
Key spn_Key;
mapping spn_Sub[sBits * sNum], spn_Per[sBits * sNum],
		spn_rSub[sBits * sNum], spn_rPer[sBits * sNum];

int spn_Init()
{
	spn_SetSub((mapping*)spn_Sub_default);
	spn_SetPer((mapping*)spn_Per_default);
	return 0;
}

int spn_SetKey(MainKey input)
{
	spn_Key.initKey = input;
	KeyGen(&spn_Key);
	return 0;
}

int KeyGen(Key* key)
{
	int round;
	for (round = 0; round <= RoundNum; round++) {
		key->roundKey[round] = key->initKey >> ((RoundNum - round) * 4);
	}
	return 0;
}

int spn_SetSub(mapping* input)
{
	int i;
	for (i = 0; i < pow(2, sBits); i++)
		spn_Sub[i] = input[i];
	reverse(spn_Sub, spn_rSub);
	return 0;
}

int spn_SetPer(mapping* input)
{
	int i;
	for (i = 0; i < pow(2, sBits); i++)
		spn_Per[i] = input[i];
	reverse(spn_Per, spn_rPer);
	return 0;
}

spn_Text Permutation(spn_Text input, mapping* per)
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

spn_Text Substitution(spn_Text input, mapping* sub)
{
	unsigned short output;
	output = ((SBox((input >> 12) & 0xf, sub) & 0xf) << 12) |
		((SBox((input >> 8) & 0xf, sub) & 0xf) << 8) |
		((SBox((input >> 4) & 0xf, sub) & 0xf) << 4) |
		((SBox(input & 0xf, sub) & 0xf));
	return output;
}

mapping SBox(mapping input, mapping* sub)
{
	return sub[input];
}

void reverse(mapping* original, mapping* reversed)
{
	int i;
	for (i = 0; i < pow(2, sBits); i++)
		reversed[original[i]] = i;
}

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

void spn_Encrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect)
{
	spn_Text temp;
	temp = *plain ^ *vect;
	spn_Encrypt_raw(&temp, cypher);
}

void spn_Decrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect)
{
	spn_Text temp;
	spn_Decrypt_raw(&temp, cypher);
	*plain = temp ^ *vect;
}

int mgen()
{
	long int i, round;
	FILE *fp;
	spn_Text plain, cypher, vect;
	plain = 0;
	vect = 0x1f56;
	printf("Data size (mb) : ");
	scanf("%ld", &round);
	fp = fopen("test.dat", "wb");
	for (i = 0; i < round * 1024 * 1024 * 8 / (sBits * sNum); i++) {
		spn_Encrypt_cbc_raw(&plain, &cypher, &vect);
		fwrite(&cypher, sizeof(spn_Text), 1, fp);
		vect = cypher;
	}
	getchar();
}
