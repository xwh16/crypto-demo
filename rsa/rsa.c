
#define _CRT_SECURE_NO_WARNINGS
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include "..\gmp.h"
#include "rsa.h"
#include "powm.h"
#include "ntheorem.h"

gmp_randstate_t state;
char str1[30] = { "-----BEGIN CERTIFICATE-----" };
char str2[30] = { "-----END CERTIFICATE-----" };


void rsa_init_key(RSAPublicKey* puk, RSAPrivateKey* prk)
{
	mpz_inits(puk->modulus, puk->publicExponent, NULL);
	mpz_inits(prk->coefficient, prk->exponet1, prk->exponet2,
		prk->modulus, prk->prime1, prk->prime2, prk->privateExponet,
		prk->publicExponet, NULL);
}

void rsa_destroy_key(RSAPublicKey* puk, RSAPrivateKey* prk)
{
	mpz_clears(puk->modulus, puk->publicExponent, NULL);
	mpz_clears(prk->coefficient, prk->exponet1, prk->exponet2,
		prk->modulus, prk->prime1, prk->prime2, prk->privateExponet,
		prk->publicExponet, NULL);
}

void rsa_generate_key(RSAPublicKey* puk, RSAPrivateKey* prk, int key_length, int round)
{
	int plength, qlength;
	mpz_t totient, buf1, buf2, g;
	mpz_inits(totient, buf1, buf2, g, NULL);
	plength = (key_length + 1) / 2;
	qlength = key_length - plength;
	do {
		randomPrime(prk->prime1, plength, round, state);
		randomPrime(prk->prime2, qlength, round, state);
		mpz_mul(prk->modulus, prk->prime1, prk->prime2);	//n=p*q
	} while (mpz_sizeinbase(prk->modulus, 2) != RSA_KEY_LENGTH);
	mpz_sub_ui(buf1, prk->prime1, 1);	//p-1
	mpz_sub_ui(buf2, prk->prime2, 1);	//q-1
	mpz_mul(totient, buf1, buf2);		//totient(n)=(p-1)*(q-1)
	do {
		mpz_urandomm(prk->publicExponet, state, totient);
		gcd(g, prk->publicExponet, totient);
	} while (mpz_cmp_ui(g, 1));	//test if e and totient(n) are coprime

	//使用2^16+1作为公钥
	/*
	mpz_init(prk->publicExponet);
	mpz_setbit(prk->publicExponet, 16);
	mpz_setbit(prk->publicExponet, 0);
	*/

	mpz_mod(prk->publicExponet, prk->publicExponet, totient);
	Mul_Invert(prk->privateExponet, prk->publicExponet, totient);
	Mul_Invert(prk->coefficient, prk->prime2, prk->prime1);
	mpz_mod(prk->exponet1, prk->privateExponet, buf1);
	mpz_mod(prk->exponet2, prk->privateExponet, buf2);
	mpz_set(puk->modulus, prk->modulus);
	mpz_set(puk->publicExponent, prk->publicExponet);
	mpz_clears(totient, buf1, buf2, g, NULL);
}

void rsa_init()
{
	gmp_randinit_lc_2exp_size(state, 128);	//设置随机数状态state
	gmp_randseed_ui(state, (unsigned long)time(NULL));
}

void rsa_quit()
{
	gmp_randclear(state);
}

void rsa_encrypt(RSAPublicKey* puk, mpz_t x, mpz_t y, void (*fp) (mpz_t, const mpz_t, const mpz_t, const mpz_t))
{
	fp(y, x, puk->publicExponent, puk->modulus);
}

void rsa_decrypt(RSAPrivateKey* prk, mpz_t x, mpz_t y, int chm_flag, void(*fp) (mpz_t, const mpz_t, const mpz_t, const mpz_t))
{
	if (chm_flag) {
		mpz_t m1, m2, h;
		mpz_inits(m1, m2, h, NULL);
		fp(m1, y, prk->exponet1, prk->prime1);
		fp(m2, y, prk->exponet2, prk->prime2);
		mpz_sub(m1, m1, m2);
		mpz_mul(h, prk->coefficient, m1);
		mpz_mul(h, h, prk->prime2);
		mpz_add(m2, m2, h);
		mpz_mod(x, m2, prk->modulus);
		mpz_clears(m1, m2, h, NULL);
	}
	else {
		fp(x, y, prk->privateExponet, prk->modulus);
	}
}

int rsa_cer_gen(FILE* pubs, FILE* prvs, RSAPublicKey* puk, RSAPrivateKey* prk)
{
	//写入公钥数据
	fprintf(pubs, str1);
	if (mpz_out_raw(pubs, puk->publicExponent) == 0) {
		return 2;
	}
	if (mpz_out_raw(pubs, puk->modulus) == 0) {
		return 2;
	}
	fprintf(pubs, str2);
	//写入公钥数据

	//写入私钥数据
	fprintf(prvs, str1);
	if (mpz_out_raw(prvs, prk->privateExponet) == 0) 
		return 3;
	if (mpz_out_raw(prvs, prk->modulus) == 0) 
		return 3;
	if (mpz_out_raw(prvs, prk->publicExponet) == 0) 
		return 3;
	if (mpz_out_raw(prvs, prk->prime1) == 0) 
		return 3;
	if (mpz_out_raw(prvs, prk->prime2) == 0) 
		return 3;
	if (mpz_out_raw(prvs, prk->exponet1) == 0) 
		return 3;
	if (mpz_out_raw(prvs, prk->exponet2) == 0) 
		return 3;
	if (mpz_out_raw(prvs, prk->coefficient) == 0) 
		return 3;
	fprintf(prvs, str2);
	//写入私钥数据

	return 0;
}

int rsa_imp_puk(FILE *fp, RSAPublicKey* puk)
{
	char buffer[30];
	fread(buffer, sizeof(char), 27, fp);
	buffer[27] = 0;
	if (strcmp(buffer, str1))
		return 2;
	if (mpz_inp_raw(puk->publicExponent, fp) == 0)
		return 3;
	if (mpz_inp_raw(puk->modulus, fp) == 0)
		return 3;
	fread(buffer, sizeof(char), 25, fp);
	buffer[25] = 0;
	if (strcmp(buffer, str2))
		return 2;
	return 0;
}

int rsa_imp_prk(FILE *fp, RSAPrivateKey* prk)
{
	char buffer[30];
	fread(buffer, sizeof(char), 27, fp);
	buffer[27] = 0;
	if (strcmp(buffer, str1))
		return 2;
	if (mpz_inp_raw(prk->privateExponet, fp) == 0)
		return 3;
	if (mpz_inp_raw(prk->modulus, fp) == 0)
		return 3;
	if (mpz_inp_raw(prk->publicExponet, fp) == 0)
		return 3;
	if (mpz_inp_raw(prk->prime1, fp) == 0)
		return 3;
	if (mpz_inp_raw(prk->prime2, fp) == 0)
		return 3;
	if (mpz_inp_raw(prk->exponet1, fp) == 0)
		return 3;
	if (mpz_inp_raw(prk->exponet2, fp) == 0)
		return 3;
	if (mpz_inp_raw(prk->coefficient, fp) == 0)
		return 3;
	fread(buffer, sizeof(char), 25, fp);
	buffer[25] = 0;
	if (strcmp(buffer, str2))
		return 2;
	return 0;
}

int rsa_pkcs1_encode(mpz_t message, int bt) {
	int size;
	mpz_t Pstring;
	mpz_init(Pstring);
	size = mpz_sizeinbase(message, 2);
	switch (bt) {
	case 2: {
		mpz_clrbit(message, RSA_KEY_LENGTH - 1);
		mpz_setbit(message, RSA_KEY_LENGTH - 31);
		do {
			mpz_urandomb(Pstring, state, RSA_KEY_LENGTH - 3 * 16 - size - (8 - size % 8));	//生成填充串Pstring																					//8-size%8使得Pstring位数为8的倍数
		} while(mpz_sizeinbase(Pstring, 2) != RSA_KEY_LENGTH - 3 * 16 - size - (8 - size % 8));
		rsa_pad_check(Pstring, 1);	//使用非0字节替换Pstring中的0字节
		mpz_mul_2exp(Pstring, Pstring, size + (8 - size % 8) + 2 * 8);	//左移Pstring空出2个0字节
		mpz_xor(message, message, Pstring);
		break;
	}
	case 1: {
		mpz_clrbit(message, RSA_KEY_LENGTH - 1);
		mpz_setbit(message, RSA_KEY_LENGTH - 32);
		break;
	}
	case 0: {
		mpz_clrbit(message, RSA_KEY_LENGTH - 1);
		break;
	}
	}
	mpz_clear(Pstring);
	return 0;
}

int rsa_pkcs1_decode(mpz_t message) 
{
	int pos;
	mpz_t Pstring;
	mpz_inits(Pstring, NULL);
	//BT = 2
	if (mpz_tstbit(message, RSA_KEY_LENGTH - 31)) {
		mpz_clrbit(message, RSA_KEY_LENGTH - 31);
		pos = rsa_pad_seek(message);
		mpz_tdiv_q_2exp(Pstring, message, RSA_KEY_LENGTH - 8 * (3 + pos));
		if (rsa_pad_check(Pstring, 0))
			return 1;
		else {
			mpz_mul_2exp(Pstring, Pstring, RSA_KEY_LENGTH - 8 * (3 + pos));
			mpz_xor(message, message, Pstring);
		}
	}
	mpz_clears(Pstring, NULL);
	return 0;
}

int rsa_pad_check(mpz_t Pstring, int mode)
{
	int i, size;
	unsigned char *p = (unsigned char*)(Pstring->_mp_d);
	size = mpz_sizeinbase(Pstring, 2);
	srand((unsigned int)time(NULL));
	for (i = 0; i < size / 8; i++, p++) {
		if (*p)
			continue;
		else {
			if (mode) {
				do {
					*p = (unsigned char)rand();	//随机生成非0字节替换Pstring中的0字节
				} while (*p == 0);
			}
			else
				return 1;
		}	
	}
	return 0;
}

int rsa_pad_seek(mpz_t message)
{
	int size, i;
	unsigned char *p;
	size = mpz_sizeinbase(message, 2);
	p = (unsigned char*)(message->_mp_d) + size / 8;	//p指向message的高位
	i = 0;
	do {
		i++;
		p--;
		if (*p == 0)
			break;
	} while (1);
	return i;
}

int rsa_test()
{
	int i;
	FILE *fp1, *fp2;
	unsigned int op = 1;
	char buf1[20], buf2[20];
	clock_t t1, t2;
	mpz_t plain, cypher, temp;
	RSAPublicKey RSApubKey;
	RSAPrivateKey RSAprvKey;
	rsa_init();
	mpz_inits(plain, cypher, temp, NULL);
	rsa_init_key(&RSApubKey, &RSAprvKey);
	while (op) {
		printf("1024位RSA验证测试程序\n");
		printf("-------------------\n");
		printf("1.生成RSA算法参数:\n");
		printf("2.导出证书文件:\n");
		printf("3.使用RSA加密:\n");
		printf("0.返回上级菜单:\n");
		scanf("%d", &op);
		getchar();
		if (op > 3) {
			printf("错误操作项.\n");
			getchar();
			continue;
		}
		else if (op == 0) {
			mpz_clears(plain, cypher, temp, NULL);
			rsa_destroy_key(&RSApubKey, &RSAprvKey);
			rsa_quit();
			return 0;
		}
		switch (op) {
		case 1: {
			t1 = clock();
			rsa_generate_key(&RSApubKey, &RSAprvKey, RSA_KEY_LENGTH, RSA_DEFAULT_ROUND);
			t2 = clock();
			printf("生成RSA算法参数用时:\t%ld ms\n\n", t2 - t1);
			printf("----------------------------------------------------\n");
			gmp_printf("公钥:\n公共指数 : %Zx\n模数 : %Zx\n", RSApubKey.publicExponent, RSApubKey.modulus);
			printf("----------------------------------------------------\n");
			gmp_printf("私钥:\n私有指数 : %Zx\n", RSAprvKey.privateExponet);
			printf("----------------------------------------------------\n");
			break;
		}
		case 2: {
			//rsa_check_key();
			printf("输入RSA公/私钥证书文件名:\n");
			gets(buf1);
			gets(buf2);
			if ((fp1 = fopen(buf1, "wb")) == NULL) {
				printf("Error creating %s", buf1);
				getchar();
				break;
			}
			if ((fp2 = fopen(buf2, "wb")) == NULL) {
				printf("Error creating %s", buf2);
				fclose(fp1);
				getchar();
				break;
			}
			if (rsa_cer_gen(fp1, fp2, &RSApubKey, &RSAprvKey))
				printf("证书写入错误.\n");
			else
				printf("证书写入成功.\n");
			getchar();
			fclose(fp1);
			fclose(fp2);
			break;
		}
		case 3: {
#define COUNT 100
			//rsa_check_key();
			printf("输入使用RSA加密的明文:\n");
			gmp_scanf("%Zx", plain);
			getchar();
			//Binary Exponentiation
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_encrypt(&RSApubKey, plain, cypher, Bin_Exp);
				}
				t2 = clock();
				printf("1.%d次 RSA加密 模重复平方:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("密文:\n%Zx\n", cypher);
			}	
			//Montgomery Exponentiation
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_encrypt(&RSApubKey, plain, cypher, Mont_Exp);
				}
				t2 = clock();
				printf("2.%d次 RSA加密 蒙哥马利法:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("密文:\n%Zx\n", cypher);
			}
			//GMP mpz_powm
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_encrypt(&RSApubKey, plain, cypher, mpz_powm);
				}
				t2 = clock();
				printf("3.%d次 RSA加密 GMP函数:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("密文:\n%Zx\n", cypher);
			}	//
			getchar();

			//Binary Exponentiation
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_decrypt(&RSAprvKey, temp, cypher, 0, Bin_Exp);
				}
				t2 = clock();
				printf("a.%d次 RSA解密 模重复平方:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("解密后消息:\n%Zx\n", temp);
				if (mpz_cmp(temp, plain) != 0)
					printf("解密消息错误.\n");
			}
			//Montgomery Exponentiation
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_decrypt(&RSAprvKey, temp, cypher, 0, Mont_Exp);
				}
				t2 = clock();
				printf("b.%d次 RSA解密 蒙哥马利法:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("解密后消息:\n%Zx\n", temp);
				if (mpz_cmp(temp, plain) != 0)
					printf("解密消息错误.\n");
			}
			//GMP mpz_powm
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_decrypt(&RSAprvKey, temp, cypher, 0, mpz_powm);
				}
				t2 = clock();
				printf("c.%d次 RSA解密 GMP函数:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("解密后消息:\n%Zx\n", temp);
				if (mpz_cmp(temp, plain) != 0)
					printf("解密消息错误.\n");
			}
			getchar();

			//Binary Exponentiation + Chm
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_decrypt(&RSAprvKey, temp, cypher, 1, Bin_Exp);
				}
				t2 = clock();
				printf("A.%d次 RSA解密 模重复平方 + 中国剩余定理:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("解密后消息:\n%Zx\n", temp);
				if (mpz_cmp(temp, plain) != 0)
					printf("解密消息错误.\n");
			}
			//Montgomery Exponentiation + Chm
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_decrypt(&RSAprvKey, temp, cypher, 1, Mont_Exp);
				}
				t2 = clock();
				printf("B.%d次 RSA解密 蒙哥马利法 + 中国剩余定理:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("解密后消息:\n%Zx\n", temp);
				if (mpz_cmp(temp, plain) != 0)
					printf("解密消息错误.\n");
			}
			//GMP mpz_powm + Chm
			{
				printf("----------------------------------------------------\n");
				t1 = clock();
				for (i = 0; i < COUNT; i++) {
					rsa_decrypt(&RSAprvKey, temp, cypher, 1, mpz_powm);
				}
				t2 = clock();
				printf("C.%d次 RSA解密 GMP函数 + 中国剩余定理:%ld ms\n", COUNT, t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("解密后消息:\n%Zx\n", temp);
				if (mpz_cmp(temp, plain) != 0)
					printf("解密消息错误.\n");
			}
			getchar();
			break;
		}
		}
		getchar();
	}
	return 0;
}
