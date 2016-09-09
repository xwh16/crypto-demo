#pragma once

#include<stdbool.h>
#include"..\gmp.h"
#define RSA_KEY_LENGTH 1024
#define RSA_DEFAULT_ROUND 20

typedef struct {
	mpz_t modulus;
	mpz_t publicExponent;
} RSAPublicKey;

typedef struct {
	mpz_t modulus;
	mpz_t publicExponet;
	mpz_t privateExponet;
	mpz_t prime1;
	mpz_t prime2;
	mpz_t exponet1;
	mpz_t exponet2;
	mpz_t coefficient;
} RSAPrvateKey;

void gcd(mpz_t rop, mpz_t num1, mpz_t num2);

bool Mul_Invert(mpz_t rop, mpz_t num, mpz_t mod);

bool modEqual(mpz_t num, int target, mpz_t modulus);

bool oddTest(mpz_t num);

bool primeTest(mpz_t num, int round);

bool Miller_Rabin(mpz_t n);

void modPow(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod);

void randomPrime(mpz_t num, int key_length, int round);

void rsa_generate_key(RSAPublicKey * puk, RSAPrvateKey * prk, int key_length, int round);

void rsa_init_key(RSAPublicKey * puk, RSAPrvateKey * prk);

void rsa_destroy_key(RSAPublicKey * puk, RSAPrvateKey * prk);

void rsa_init();

void rsa_quit();

void rsa_encrypt(RSAPublicKey* puk, mpz_t x, mpz_t y, void(*fp) (mpz_t, const mpz_t, const mpz_t, const mpz_t));

void rsa_decrypt(RSAPrvateKey* prk, mpz_t x, mpz_t y, int chm_flag, void(*fp) (mpz_t, const mpz_t, const mpz_t, const mpz_t));

int rsa_cer_gen(char * pubs, char * prvs, RSAPublicKey * puk, RSAPrvateKey * prk);

int rsa_imp_puk(FILE *fp, RSAPublicKey * puk);

int rsa_imp_prk(FILE *fp, RSAPrvateKey * prk);

int rsa_pkcs1_encode(mpz_t message, int bt);

int rsa_pkcs1_decode(mpz_t message);

int rsa_pad_check(mpz_t Pstring, int mode);

int rsa_pad_seek(mpz_t message);

int rsa_test();
