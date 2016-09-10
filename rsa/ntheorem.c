
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include "..\gmp.h"
#include "ntheorem.h"

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

void modPow(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod)
{
	//Bin_Exp(rop, base, exp, mod);
	//Mont_Exp(rop, base, exp, mod);
	mpz_powm(rop, base, exp, mod);
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
	gmp_randstate_t state;
	int k = 0, i;
	mpz_t m, a, b;
	gmp_randinit_lc_2exp_size(state, 128);	//ÉèÖÃËæ»úÊý×´Ì¬state
	gmp_randseed_ui(state, (unsigned long)time(NULL));
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