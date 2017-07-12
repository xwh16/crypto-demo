#pragma once

#define sBits 8
#define sNum 8
#define RoundNum 16
#define SBOX_LENGTH 256
#define SPN_KEY_LENGTH sNum * sBits + (RoundNum ) * 4
#include "..\gmp.h" 

typedef unsigned long long spn_Text;	//SPN数据单位

typedef mpz_t MainKey;	//主密钥
typedef spn_Text RoundKey;	//轮密钥
typedef struct {
	MainKey initKey;
	RoundKey roundKey[RoundNum + 1];
}Key;	//SPN密钥

Key spn_Key;
unsigned char spn_Sub[SBOX_LENGTH], spn_rSub[SBOX_LENGTH];
unsigned char spn_Per[sBits * sNum], spn_rPer[sBits * sNum];

int spn_Init();	//Initialize spn with default S/P Boxes

int spn_SetKey(MainKey input);	//Set the main key for spn

int KeyGen(Key* key);	//Generate round key for spn encryption

int spn_SetSub(unsigned char* input);	//Set S-Box

int spn_SetPer(unsigned char* input);	//Set P-Box

spn_Text spn_Encrypt_raw(spn_Text * plain, spn_Text * cypher);

spn_Text spn_Decrypt_raw(spn_Text * plain, spn_Text * cypher);

spn_Text Permutation(spn_Text input, unsigned char* per);	

spn_Text Substitution(spn_Text input, unsigned char* sub);	

char SBox(unsigned char input, unsigned char* sub);

void reverse(unsigned char* original, unsigned char* reversed, int length);		//Reverse LUT

int mgen();	//Generate cypher data for testing

void spn_Encrypt_cbc_raw(spn_Text * plain, spn_Text * cypher, spn_Text * vect);

void spn_Decrypt_cbc_raw(spn_Text * plain, spn_Text * cypher, spn_Text * vect);

int spn_Encrypt_cbc(FILE *fp, FILE *efp, MainKey sessionKey, spn_Text *initVect);

int spn_Decrypt_cbc(FILE *fp, FILE *dfp, MainKey sessionKey, spn_Text *initVect);

void LoadLUT(FILE *fp, char *buffer, int length);

void PrintLUT(char *buffer, int length);

int spn_test();
