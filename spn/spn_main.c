
#define _CRT_SECURE_NO_WARNINGS
#include<stdio.h>
#include<Windows.h>
#include"spn.h"


int main()
{
	int i;
	unsigned int inputKey;
	//spn_Text plain, cypher;

	spn_Init();

	printf("Initialize SPN Key (32bit, hex input): ");
	scanf("%x", &inputKey);
	getchar();
	spn_SetKey(inputKey);
	for (i = 0; i <= RoundNum; i++)
		printf("> roundKey[%d] = %#x\n", i + 1, spn_Key.roundKey[i]);
	mgen();

	//printf("Plain Text (16bit): ");
	//scanf("%hx", &plain);
	//getchar();
	//printf("Cyher Text (16bit): %#x \n", spn_Encrypt_raw(&plain, &cypher));
	//printf("Decrypted Cypher Text (16bit): %#x ", spn_Decrypt_raw(&plain, &cypher));
	getchar();
}