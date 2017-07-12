#pragma once

void Mont_Test();

void Mont_Exp(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod);
void Bin_Exp(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t N);

void MontPro(mpz_t T, const mpz_t x, const mpz_t y, const  mpz_t N, const mp_limb_t N_1);
void MontPro1(mpz_t t, const mpz_t x, const mpz_t y, const mpz_t N, const mp_limb_t N_1);
void MontPro2(mpz_t T, const mpz_t x, const mpz_t y, const  mpz_t N, const mp_limb_t N_1);