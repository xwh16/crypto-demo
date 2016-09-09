
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <time.h>
#include <Windows.h>
#include "..\gmp.h"
#include "..\spn+\spn+.h"
#include "..\rsa\rsa.h"
#include "..\rsa\powm.h"
#include "file_system.h"

#define FILE_OPEN_ERROR 1

void spn_init_session(MainKey sessionKey, spn_Text *initVect)
{
	/******************************************
	descripiton:随机生成SPN-CBC模式参数
	outputParam:
				sessionKey	SPN网络主密钥
				initVect	CBC模式初始向量
	******************************************/
	gmp_randstate_t state;
	mpz_inits(sessionKey, initVect, NULL);
	srand((unsigned int)time(NULL));
	gmp_randinit_lc_2exp_size(state, 128);
	gmp_randseed_ui(state, (unsigned long)time(NULL));
	mpz_urandomb(sessionKey, state, SPN_KEY_LENGTH);	//生成主密钥sessionKey
	*initVect = rand() * rand() * rand() % 0xffffffffffffffff;	//生成初始向量initVect
}

int file_encrypt(RSAPublicKey* RSApubKey)
{
	/*
	descripiton:使用CBC工作模式的SPN+网络加密文件
				文件头写入RSA公钥加密后的SPN密钥和初始向量IV
	inputParam :
				RSApubKey	RSA公钥结构指针
	errorCode  :
				0			ALIZZWELL
				1			文件打开错误
	*/
	clock_t t1, t2;
	mpz_t plain, cypher, temp;
	char buffer[20];
	FILE *fp1, *fp2;
	spn_Text initVect;
	MainKey sessionKey;
	mpz_t sessionInfo, RSAcypher;
	mpz_inits(plain, cypher, temp, sessionKey, RSAcypher, sessionInfo, NULL);
	//打开文件
	{
		printf("输入使用SPN+加密的文件名:");
		scanf("%s", buffer);
		getchar();
		if ((fp1 = fopen(buffer, "rb")) == NULL) {
			printf("文件 %s 打开失败.\n", buffer);
			return FILE_OPEN_ERROR;
		}
		printf("输入加密后文件名:");
		scanf("%s", buffer);
		getchar();
		if ((fp2 = fopen(buffer, "wb")) == NULL) {
			printf("加密文件创建失败.\n");
			return FILE_OPEN_ERROR;
		}
	}
	//生成主密钥和初始向量IV
	{
		spn_init_session(sessionKey, &initVect);	//生成会话参数
		gmp_printf("本次文件加密密钥 %d bit : %Zx\n", sNum * sBits + (RoundNum - 1) * 4, sessionKey);
		printf("CBC模式初始向量:%llx", initVect);
		getchar();
	}
	//使用RSA算法加密本次会话的主密钥和初始向量IV
	//并写入fp2文件头部
	{
		mpz_import(sessionInfo, 1, -1, sizeof(spn_Text), 0, 0, &initVect);	//将initVect导入sessionInfo
		mpz_mul_2exp(sessionInfo, sessionInfo, sNum * sBits + (RoundNum - 1) * 4);	//左移sessionInfo为sessionKey腾出空间
		mpz_xor(sessionInfo, sessionInfo, sessionKey);	//sessionInfo | sessionKey
		rsa_pkcs1_encode(sessionInfo, 2);	//对sessionInfo以pkcs#1 v1.5标准编码
		rsa_encrypt(RSApubKey, sessionInfo, RSAcypher, mpz_powm);
		mpz_out_raw(fp2, RSAcypher);	//加密后的sessionInfo写入文件
	}
	//CBC模式加密fp1文件并写入fp2
	spn_Encrypt_cbc(fp1, fp2, sessionKey, &initVect);
	//释放文件指针
	fclose(fp2);
	fclose(fp1);
	mpz_clears(plain, cypher, temp, sessionKey, sessionInfo, RSAcypher, NULL);
}

int file_decrypt(RSAPrvateKey* RSAprvKey)
{
	/*
	descripiton:使用CBC工作模式的SPN+网络解密文件
				从文件头读入RSA公钥加密后的SPN密钥和初始向量IV
	inputParam :
				RSAprvKey	RSA私钥结构指针
	errorCode  :
				0			ALIZZWELL
				1			文件打开错误
	*/
	clock_t t1, t2;
	mpz_t plain, cypher, temp;
	char buffer[20];
	FILE *fp1, *fp2;
	spn_Text initVect;
	MainKey sessionKey;
	mpz_t sessionInfo, RSAcypher;
	mpz_inits(plain, cypher, temp, sessionKey, RSAcypher, sessionInfo, NULL);
	//打开文件
	{
		printf("输入使用SPN+解密的文件名:");
		scanf("%s", buffer);
		getchar();
		if ((fp1 = fopen(buffer, "rb")) == NULL) {
			printf("文件 %s 打开失败.\n", buffer);
			return FILE_OPEN_ERROR;
		}
		printf("输入解密后文件名:");
		scanf("%s", buffer);
		getchar();
		if ((fp2 = fopen(buffer, "wb")) == NULL) {
			printf("解密文件创建失败.\n");
			return FILE_OPEN_ERROR;
		}
	}
	//从fp1文件头读入sessionInfo
	//并配置好sessionKey与initVect
	{
		mpz_inp_raw(RSAcypher, fp1);
		rsa_decrypt(RSAprvKey, sessionInfo, RSAcypher, 1, mpz_powm);
		rsa_pkcs1_decode(sessionInfo);
		mpz_set_ui(temp, 0x1);
		mpz_mul_2exp(temp, temp, SPN_KEY_LENGTH);
		mpz_sub_ui(temp, temp, 1);	//形成低位的逻辑尺
		mpz_and(sessionKey, sessionInfo, temp);	//使用逻辑尺取出低位的sessionKey
		mpz_tdiv_q_2exp(sessionInfo, sessionInfo, SPN_KEY_LENGTH);
		mpz_export(&initVect, NULL, -1, sizeof(spn_Text), 0, 0, sessionInfo);
		gmp_printf("本次文件加密密钥 %d bit : %Zx\n", SPN_KEY_LENGTH, sessionKey);
		printf("CBC模式初始向量:%llx", initVect);
		getchar();
	}
	//CBC模式解密文件fp1写入fp2
	spn_Decrypt_cbc(fp1, fp2, sessionKey, &initVect);
	//释放文件指针
	fclose(fp2);
	fclose(fp1);
	mpz_clears(plain, cypher, temp, sessionKey, sessionInfo, RSAcypher, NULL);
}

int file_system()
{
	unsigned int op = 1, mark = 0, flag = 0, prvf = 0, pubf = 0;
	char buffer[20];
	clock_t t1, t2;
	mpz_t plain, cypher, temp;
	RSAPublicKey RSApubKey;
	RSAPrvateKey RSAprvKey;
	FILE *fp1, *fp2;
	spn_Text initVect;
	MainKey sessionKey;
	mpz_t sessionInfo, RSAcypher;
	mpz_inits(plain, cypher, temp, NULL);
	mpz_inits(sessionKey, sessionInfo, RSAcypher, NULL);
	rsa_init();
	spn_Init();
	rsa_init_key(&RSApubKey, &RSAprvKey);
	while (op) {
		//system("cls");
		printf("RSA & SPN+ 文件加密程序\n");
		printf("-------------------\n");
		printf("1.导入RSA公钥加密证书\n");
		printf("2.导入RSA私钥解密证书\n");
		printf("3.使用RSA加密数据\n");
		printf("4.使用公钥加密文件\n");
		printf("5.使用私钥解密文件\n");
		printf("0.返回上级菜单:\n");
		scanf("%d", &op);
		getchar();
		if (op > 5) {
			printf("错误操作项.\n");
			getchar();
			continue;
		}
		else if (op == 0) {
			mpz_clears(plain, cypher, temp, NULL);
			mpz_clears(sessionKey, sessionInfo, RSAcypher, NULL);
			rsa_destroy_key(&RSApubKey, &RSAprvKey);
			rsa_quit();
			return 0;
		}
		//system("cls");
		switch (op) {
		case 1: {
			printf("输入公钥证书名:");
			scanf("%s", buffer);
			if ((fp1 = fopen(buffer, "rb")) == NULL)
				break;
			if ((flag = rsa_imp_puk(fp1, &RSApubKey)) == 3) {
				printf("读取RSA算法参数错误.\n");
				printf("检查大数格式与gmp函数库.\n");
				break;
			}
			else if (flag == 2) {
				printf("证书格式错误.\n");
				break;
			}
			else if (flag) {
				printf("打开证书错误.\n");
				break;
			}
			else {
				printf("----------------------------------------------------\n");
				gmp_printf("公共加密指数:%Zx\n", RSApubKey.publicExponent);
				printf("----------------------------------------------------\n");
				gmp_printf("模数:%Zx\n", RSApubKey.modulus);
				printf("----------------------------------------------------\n");
			}
			pubf = 1;
			fclose(fp1);
			break;
		}
		case 2: {
			printf("输入私钥证书名:");
			scanf("%s", buffer);
			if ((fp1 = fopen(buffer, "rb")) == NULL)
				break;
			if ((flag = rsa_imp_prk(fp1, &RSAprvKey)) == 3) {
				printf("读取RSA算法参数错误.\n");
				printf("检查大数格式与gmp函数库.\n");
				break;
			}
			else if (flag == 2) {
				printf("证书格式错误.\n");
				break;
			}
			else if (flag) {
				printf("打开证书错误.\n");
				break;
			}
			else {
				printf("----------------------------------------------------\n");
				gmp_printf("私钥:\n私有指数 : %Zx\n", RSAprvKey.privateExponet);
				printf("----------------------------------------------------\n");
			}
			prvf = 1;
			fclose(fp1);
			break;
		}
		case 3: {
			if (prvf && pubf) {
				printf("输入使用RSA加密的明文:\n");
				gmp_scanf("%Zx", plain);
				getchar();
				printf("----------------------------------------------------\n");
				t1 = clock();
				rsa_encrypt(&RSApubKey, plain, cypher, mpz_powm);
				t2 = clock();
				printf("RSA加密用时:%ld ms\n", t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("密文:\n%Zx\n", cypher);
				printf("----------------------------------------------------\n");
				t1 = clock();
				rsa_decrypt(&RSAprvKey, temp, cypher, 1, mpz_powm);
				t2 = clock();
				printf("RSA解密用时:%ld ms\n", t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("解密后消息:\n%Zx\n", temp);
				printf("----------------------------------------------------\n");
				if (mpz_cmp(temp, plain) != 0)
					printf("解密消息错误.\n");
			}
			else
				printf("RSA算法参数缺失.\n");
			break;
		}
		case 4: {
			file_encrypt(&RSApubKey);
			break;
		}
		case 5: {
			file_decrypt(&RSAprvKey);
			break;
		}
		}
		getchar();
	}
	return 0;
}