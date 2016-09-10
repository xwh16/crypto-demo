#pragma once

#define sBits 8
#define sNum 8
#define RoundNum 16
#define SBOX_LENGTH 256
#define SPN_KEY_LENGTH sNum * sBits + (RoundNum ) * 4
#include "..\gmp.h" 

typedef unsigned long long spn_Text;	//SPN ˝æ›µ•Œª
typedef unsigned char mapping;	//S/P∫–”≥…‰

typedef mpz_t MainKey;	//÷˜√‹‘ø
typedef spn_Text RoundKey;	//¬÷√‹‘ø
typedef struct {
	MainKey initKey;
	RoundKey roundKey[RoundNum + 1];
}Key;	//SPN√‹‘ø

Key spn_Key;
mapping spn_Sub[SBOX_LENGTH], spn_rSub[SBOX_LENGTH];
mapping spn_Per[sBits * sNum], spn_rPer[sBits * sNum];

int spn_Init();	//Initialize spn with default S/P Boxes

int spn_SetKey(MainKey input);	//Set the main key for spn

int KeyGen(Key* key);	//Generate round key for spn encryption

int spn_SetSub(mapping* input);	//Set S-Box

int spn_SetPer(mapping* input);	//Set P-Box

spn_Text spn_Encrypt_raw(spn_Text * plain, spn_Text * cypher);

spn_Text spn_Decrypt_raw(spn_Text * plain, spn_Text * cypher);

spn_Text Permutation(spn_Text input, mapping* per);	

spn_Text Substitution(spn_Text input, mapping* sub);	

char SBox(unsigned char input, mapping* sub);

void reverse(mapping* original, mapping* reversed, int length);		//Reverse LUT

int mgen();	//Generate cypher data for testing

void spn_Encrypt_cbc_raw(spn_Text * plain, spn_Text * cypher, spn_Text * vect);

void spn_Decrypt_cbc_raw(spn_Text * plain, spn_Text * cypher, spn_Text * vect);

int spn_Encrypt_cbc(FILE *fp, FILE *efp, MainKey sessionKey, spn_Text *initVect);

int spn_Decrypt_cbc(FILE *fp, FILE *dfp, MainKey sessionKey, spn_Text *initVect);

int spn_test();
