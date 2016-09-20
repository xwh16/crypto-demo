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
} RSAPrivateKey;

void rsa_generate_key(RSAPublicKey * puk, RSAPrivateKey * prk, int key_length, int round);

void rsa_init_key(RSAPublicKey * puk, RSAPrivateKey * prk);

void rsa_destroy_key(RSAPublicKey * puk, RSAPrivateKey * prk);

void rsa_init();

void rsa_quit();

void rsa_encrypt(RSAPublicKey* puk, mpz_t x, mpz_t y, void(*fp) (mpz_t, const mpz_t, const mpz_t, const mpz_t));

void rsa_decrypt(RSAPrivateKey* prk, mpz_t x, mpz_t y, int chm_flag, void(*fp) (mpz_t, const mpz_t, const mpz_t, const mpz_t));

int rsa_cer_gen(FILE* pubs, FILE* prvs, RSAPublicKey* puk, RSAPrivateKey* prk);

int rsa_imp_puk(FILE *fp, RSAPublicKey * puk);

int rsa_imp_prk(FILE *fp, RSAPrivateKey * prk);

int rsa_pkcs1_encode(mpz_t message, int bt);

int rsa_pkcs1_decode(mpz_t message);

int rsa_pad_check(mpz_t Pstring, int mode);

int rsa_pad_seek(mpz_t message);

int rsa_test();
