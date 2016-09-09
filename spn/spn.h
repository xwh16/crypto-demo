#pragma once

#define sBits 4
#define sNum 4
#define RoundNum 4

typedef unsigned short spn_Text;
typedef unsigned char mapping;
typedef unsigned int MainKey;
typedef unsigned short RoundKey;
typedef struct {
	MainKey initKey;
	RoundKey roundKey[RoundNum + 1];
}Key;

//Íâ²¿±äÁ¿ÉùÃ÷
extern Key spn_Key;
extern mapping spn_Sub[sBits * sNum], spn_Per[sBits * sNum], 
				spn_rSub[sBits * sNum], spn_rPer[sBits * sNum];


int KeyGen(Key* key);	//ÃÜÔ¿±àÅÅ

int spn_SetKey(MainKey input);

int spn_SetSub(mapping* input);

int spn_SetPer(mapping* input);

spn_Text spn_Encrypt_raw(spn_Text * plain, spn_Text * cypher);

spn_Text spn_Decrypt_raw(spn_Text * plain, spn_Text * cypher);

int mgen();

spn_Text Permutation(spn_Text input, mapping* per);	//ÖÃ»»²Ù×÷

spn_Text Substitution(spn_Text input, mapping* sub);	//SºĞÌæ»»

mapping SBox(mapping input, mapping* sub);

void reverse(mapping* original, mapping* reversed);		//SºĞ/PÖÃ»»ÇóÄæ
