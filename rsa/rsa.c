
#define _CRT_SECURE_NO_WARNINGS
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <Windows.h>
#include "..\gmp.h"
#include "rsa.h"
#include "powm.h"

gmp_randstate_t state;
char str1[30] = { "-----BEGIN CERTIFICATE-----" };
char str2[30] = { "-----END CERTIFICATE-----" };

void gcd(mpz_t rop, mpz_t num1, mpz_t num2)
{
	mpz_t r0, r1, q, temp;
	mpz_inits(r0, r1, q, temp, NULL);
	mpz_set(r0, num1);
	mpz_set(r1, num2);
	while (mpz_cmp_ui(r1, 0) != 0) {
		mpz_tdiv_q(q, r0, r1);	//q<m> = [r<m-1> / r<m>]
		mpz_mul(q, q, r1);
		mpz_set(temp, r1);
		mpz_sub(r1, r0, q);	//r<m+1> = r<m-1> - q<m> * r<m>
		mpz_set(r0, temp);
	}
	mpz_set(rop, r0);
	mpz_clears(r0, r1, q, temp, NULL);
}

bool Mul_Invert(mpz_t rop, mpz_t num, mpz_t mod)
{
	mpz_t a, b, t0, t1, q, r, temp;
	mpz_inits(a, b, t0, t1, q, r, temp, NULL);
	mpz_set(a, mod);
	mpz_set(b, num);
	mpz_set_ui(t0, 0);
	mpz_set_ui(t1, 1);
	mpz_tdiv_q(q, a, b);
	mpz_mul(temp, q, b);
	mpz_sub(r, a, temp);
	while (mpz_cmp_ui(r, 0) > 0) {
		mpz_mul(temp, q, t1);
		mpz_sub(temp, t0, temp);
		mpz_set(t0, t1);
		mpz_set(t1, temp);
		mpz_set(a, b);
		mpz_set(b, r);
		mpz_tdiv_q(q, a, b);
		mpz_mul(temp, q, b);
		mpz_sub(r, a, temp);
	}
	if (mpz_cmp_ui(b, 1) == 0) {
		mpz_mod(t1, t1, mod);
		mpz_set(rop, t1);
		mpz_clears(a, b, t0, t1, q, r, temp, NULL);
		return true;
	}
	else {
		mpz_clears(a, b, t0, t1, q, r, temp, NULL);
		return false;
	}
}

bool modEqual(mpz_t num, int target, mpz_t modulus)
{
	mpz_t residue, temp;
	mpz_inits(residue, temp, NULL);
	mpz_set_si(temp, target);
	mpz_mod(residue, num, modulus);
	mpz_mod(temp, temp, modulus);
	if (mpz_cmp(residue, temp) == 0) {
		mpz_clears(residue, temp, NULL);
		return true;
	}
	else {
		mpz_clears(residue, temp, NULL);
		return false;
	}
}

bool oddTest(mpz_t num)
{
	if (mpz_tstbit(num, 0) == 1)
		return true;
	else
		return false;
}

bool primeTest(mpz_t num, int round)
{
	while (round-- > 0) {
		if (Miller_Rabin(num) == false) 
			return false;
	}
	return true;
}

bool Miller_Rabin(mpz_t n)	
{
	int k = 0, i;
	mpz_t m, a, b;
	mpz_inits(m, a, b, NULL);
	mpz_sub_ui(m, n, 1);	//m = n- 1
	mpz_urandomm(a, state, m);	//generate random number a
	mpz_add_ui(a, a, 1);
	do {
		mpz_tdiv_q_2exp(m, m, 1);
		k++;
	} while (oddTest(m) == false);	//m = (n - 1) / 2^k
	modPow(b, a, m, n);	//b = a ^ m mod n
	if (modEqual(b, 1, n)) {
		return true;	//b == 1 mod n
	}
	for (i = 0; i < k; i++) {
		if (modEqual(b, -1, n)) {
			mpz_clears(a, b, m, NULL);
			return true;	//b == -1 mod n
		}
		else {
			mpz_mul(b, b, b);
			mpz_mod(b, b, n);
		}	//b = b ^ 2 mod n
	}
	mpz_clears(a, b, m, NULL, NULL);
	return false;
}

void modPow(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod)
{
	//Bin_Exp(rop, base, exp, mod);
	//Mont_Exp_v2(rop, base, exp, mod);
	mpz_powm(rop, base, exp, mod);
}

void randomPrime(mpz_t num, int key_length, int round)
{
	int i = 1;
	do {
		mpz_urandomb(num, state, key_length);	//生成随机数num
		mpz_setbit(num, 0);	//设置num为奇数
	} while (primeTest(num, round) == false);
}

void rsa_init_key(RSAPublicKey* puk, RSAPrvateKey* prk)
{
	mpz_inits(puk->modulus, puk->publicExponent, NULL);
	mpz_inits(prk->coefficient, prk->exponet1, prk->exponet2,
		prk->modulus, prk->prime1, prk->prime2, prk->privateExponet,
		prk->publicExponet, NULL);
}

void rsa_destroy_key(RSAPublicKey* puk, RSAPrvateKey* prk)
{
	mpz_clears(puk->modulus, puk->publicExponent, NULL);
	mpz_clears(prk->coefficient, prk->exponet1, prk->exponet2,
		prk->modulus, prk->prime1, prk->prime2, prk->privateExponet,
		prk->publicExponet, NULL);
}

void rsa_generate_key(RSAPublicKey* puk, RSAPrvateKey* prk, int key_length, int round)
{
	int plength, qlength;
	mpz_t totient, buf1, buf2, g;
	mpz_inits(totient, buf1, buf2, g, NULL);
	plength = (key_length + 1) / 2;
	qlength = key_length - plength;
	do {
		randomPrime(prk->prime1, plength, round);
		randomPrime(prk->prime2, qlength, round);
		mpz_mul(prk->modulus, prk->prime1, prk->prime2);	//n=p*q
	} while (mpz_sizeinbase(prk->modulus, 2) != RSA_KEY_LENGTH);
	mpz_sub_ui(buf1, prk->prime1, 1);	//p-1
	mpz_sub_ui(buf2, prk->prime2, 1);	//q-1
	mpz_mul(totient, buf1, buf2);		//totient(n)=(p-1)*(q-1)
	//do {
	//	mpz_urandomm(prk->publicExponet, state, totient);
	//	gcd(g, prk->publicExponet, totient);
	//} while (mpz_cmp_ui(g, 1));	//test if e and totient(n) are coprime

	//使用2^16+1作为公钥
	mpz_init(prk->publicExponet);
	mpz_setbit(prk->publicExponet, 16);
	mpz_setbit(prk->publicExponet, 0);

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

void rsa_decrypt(RSAPrvateKey* prk, mpz_t x, mpz_t y, int chm_flag, void(*fp) (mpz_t, const mpz_t, const mpz_t, const mpz_t))
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

int rsa_cer_gen(char* pubs, char* prvs, RSAPublicKey* puk, RSAPrvateKey* prk)
{
	FILE *fp;
	if ((fp = fopen(pubs, "wb")) == NULL)
		return 1;
	fprintf(fp, str1);
	if (mpz_out_raw(fp, puk->publicExponent) == 0) {
		fclose(fp);
		return 2;
	}
	if (mpz_out_raw(fp, puk->modulus) == 0) {
		fclose(fp);
		return 2;
	}
	fprintf(fp, str2);
	fclose(fp);
	if ((fp = fopen(prvs, "wb")) == NULL) {
		printf("Error creating %s", prvs);
		getchar();
		return 1;
	}
	fprintf(fp, str1);
	if (mpz_out_raw(fp, prk->privateExponet) == 0) {
		fclose(fp);
		return 3;
	}
	if (mpz_out_raw(fp, prk->modulus) == 0) {
		fclose(fp);
		return 3;
	}
	if (mpz_out_raw(fp, prk->publicExponet) == 0) {
		fclose(fp);
		return 3;
	}
	if (mpz_out_raw(fp, prk->prime1) == 0) {
		fclose(fp);
		return 3;
	}
	if (mpz_out_raw(fp, prk->prime2) == 0) {
		fclose(fp);
		return 3;
	}
	if (mpz_out_raw(fp, prk->exponet1) == 0) {
		fclose(fp);
		return 3;
	}
	if (mpz_out_raw(fp, prk->exponet2) == 0) {
		fclose(fp);
		return 3;
	}
	if (mpz_out_raw(fp, prk->coefficient) == 0) {
		fclose(fp);
		return 3;
	}
	fprintf(fp, str2);
	fclose(fp);
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

int rsa_imp_prk(FILE *fp, RSAPrvateKey* prk)
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
		mpz_urandomb(Pstring, state, RSA_KEY_LENGTH - 3 * 16 - size - (8 - size % 8));	//生成填充串Pstring
																						//8-size%8使得Pstring位数为8的倍数
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
		mpz_tdiv_q_2exp(Pstring, message, RSA_KEY_LENGTH - 8 * (4 + pos));
		if (rsa_pad_check(Pstring, 0))
			return 1;
		else {
			mpz_mul_2exp(Pstring, Pstring, RSA_KEY_LENGTH - 8 * (4 + pos));
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
	unsigned int op = 1;
	char buf1[20], buf2[20];
	clock_t t1, t2;
	mpz_t plain, cypher, temp;
	RSAPublicKey RSApubKey;
	RSAPrvateKey RSAprvKey;
	rsa_init();
	mpz_inits(plain, cypher, temp, NULL);
	rsa_init_key(&RSApubKey, &RSAprvKey);
	while (op) {
		system("cls");
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
		system("cls");
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
			if (rsa_cer_gen(buf1, buf2, &RSApubKey, &RSAprvKey))
				printf("证书写入错误.\n");
			else
				printf("证书写入成功.\n");
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
					rsa_encrypt(&RSApubKey, plain, cypher, Mont_Exp_32);
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
					rsa_decrypt(&RSAprvKey, temp, cypher, 0, Mont_Exp_32);
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
					rsa_decrypt(&RSAprvKey, temp, cypher, 1, Mont_Exp_32);
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
