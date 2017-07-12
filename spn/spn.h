#pragma once

#define sBits 4
#define sNum 4
#define RoundNum 4

typedef unsigned short spn_Text;
typedef unsigned int MainKey;
typedef unsigned short RoundKey;
typedef struct {
	MainKey initKey;
	RoundKey roundKey[RoundNum + 1];
}Key;

//外部变量声明
extern Key *spn_Key;
extern unsigned char *spn_Sub, *spn_Per, *spn_rSub, *spn_rPer;

int spn_Init();

int spn_Destroy();

int spn_SetKey(MainKey input);

static int KeyGen(Key* key);	//密钥编排

int spn_SetSub(unsigned char* input);

int spn_SetPer(unsigned char* input);

spn_Text spn_Encrypt_raw(spn_Text * plain, spn_Text * cypher);

spn_Text spn_Decrypt_raw(spn_Text * plain, spn_Text * cypher);

spn_Text spn_Encrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect);

spn_Text spn_Decrypt_cbc_raw(spn_Text *plain, spn_Text *cypher, spn_Text *vect);

int mgen();

spn_Text Permutation(spn_Text input, unsigned char* per);	//置换操作

spn_Text Substitution(spn_Text input, unsigned char* sub);	//S盒替换

unsigned char SBox(unsigned char input, unsigned char* sub);

void reverse(unsigned char* original, unsigned char* reversed);		//S盒/P置换求逆
