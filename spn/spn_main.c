
#define _CRT_SECURE_NO_WARNINGS
#include<time.h>
#include<stdio.h>
#include<Windows.h>
#include"spn.h"

int main()
{
	int i, op = 1;
	MainKey inputKey;
	spn_Text plain, cypher;
	spn_Init();
	while (op) {
		printf("原始SPN测试程序\n");
		printf("-------------------\n");
		printf("1.随机生成SPN主密钥 %d bit\n", 32);
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
			srand(time(NULL));
			inputKey = rand()<<16 | rand();
			spn_SetKey(inputKey);
			printf("Main Key : %x\n", inputKey);
			for (i = 0; i <= RoundNum; i++)
				printf("> roundKey[%d] = %#hx\n", i + 1, spn_Key.roundKey[i]);
			break;
		case 2:
			printf("明文输入 (16 bit): ");
			scanf("%hx", &plain);
			getchar();
			printf("加密后密文 (16 bit): %#hx \n", spn_Encrypt_raw(&plain, &cypher));
			printf("解密后明文 (16 bit): %#hx ", spn_Decrypt_raw(&plain, &cypher));
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