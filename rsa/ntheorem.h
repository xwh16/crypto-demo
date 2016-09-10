#pragma once

void gcd(mpz_t rop, mpz_t num1, mpz_t num2);

bool Mul_Invert(mpz_t rop, mpz_t num, mpz_t mod);

void modPow(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod);

bool modEqual(mpz_t num, int target, mpz_t modulus);

bool oddTest(mpz_t num);

bool primeTest(mpz_t num, int round);

bool Miller_Rabin(mpz_t n);
