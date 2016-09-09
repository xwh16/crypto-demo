
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include "..\gmp.h"
#include "powm.h"

//�����ɸ�������ȷ�Բ���
#define MONT_CHECK

//Mont_Test�Ĳ��Դ���
#define TESTCOUNT 100
//Mont_Test��ģ�����λ��
#define TESTBITS 1024
//��mp_limb_tΪ�ɸ�����������λ��
#define MONTBITS (8*sizeof(mp_limb_t))
//�����ɸ������е�T=XY�����λ��������MONT_MAX��mp_limb_t
#define MONT_MAX 64
//�����״̬
gmp_randstate_t state; 


void Mont_Exp_32(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t N)
{
	/*************************************************
		description:ʹ�� �ɸ������㷨 ���� rop = base^exp mod N
		inputParam :
					base	����
					exp		ָ��
					N		ģ��, �ٶ�Ϊ����
		outputParam:
					rop		������
	*************************************************/
	assert(mpz_odd_p(N) == true);	//N����Ϊ����

	mp_limb_t N_1;	
	mp_bitcnt_t ebit;
	mp_bitcnt_t rbit;
	mp_bitcnt_t index;	//ѭ��������

	mpz_t K;	
	mpz_t P, R;
	mpz_t temp, N_inv, b;
	mpz_inits(K, P, R, temp, N_inv, b, NULL);	//��ʼ��mpz��������

	rbit = N->_mp_size*MONTBITS;	//ģ��Nλ��
	ebit = mpz_sizeinbase(exp, 2);	//ָ��expλ��

	mpz_setbit(b, MONTBITS);	//b = 2^32
	mpz_invert(N_inv, N, b);	
	mpz_sub(N_inv, b, N_inv);	
	N_1 = *(N_inv->_mp_d);	//N_1*N = -1 mod R

	mpz_set_ui(temp, 1);	//temp = 1
	mpz_setbit(K, 2 * rbit);	
	mpz_mod(K, K, N);	//K = 2^(2*rbit) mod N

	Mont_Pro_32(P, K, base, N, N_1);	//��baseת��Ϊ�ɸ������� P
	Mont_Pro_32(R, K, temp, N, N_1);	//��  1 ת��Ϊ�ɸ������� R
	for (index = 0; index < ebit; index++) {
		if (mpz_tstbit(exp, index) == 1)
			Mont_Pro_32(R, R, P, N, N_1);	//R = R*P mod N
		Mont_Pro_32(P, P, P, N, N_1);	//P = P*P mod N
	}
	Mont_Pro_32(rop, temp, R, N, N_1);	//��Rת����ʵ����

#ifdef MONT_CHECK
	/*
		���Դ���
		ʹ��gmp:mpz_powm()����ģ����������ȷ��
	*/
	mpz_powm(temp, base, exp, N);
	if (mpz_cmp(temp, rop) != 0) {
		gmp_printf("r1 = %Zx\n", rop);
		gmp_printf("r2 = %Zx\n", temp);
		gmp_printf("mod = %Zx\n", N);
		gmp_printf("base = %Zx\n", base);
		gmp_printf("exp = %Zx\n", exp);
		getchar();
	}
#endif

	mpz_clears(K, P, R, temp, N_inv, b, NULL);	//����mpz��������
}

void Mont_Pro_32(mpz_t T, const mpz_t x, const mpz_t y, const mpz_t N, const mp_limb_t N_1)
{
	/*************************************************
	description:ʹ�� REDC ���� x*y*r^(-1) mod N
	inputParam :
				x, y	������1, 2, �ٶ�Ϊ�ɸ�������
				N		ģ��
				N_1		Ԥ����� -N^(-1) mod b
	outputParam:
				rop		������
	*************************************************/
	int i;
	mpz_t t;
	mp_limb_t num;
	mpz_init(t);
	mpz_mul(t, x, y);		//T = xy
	for (i = 0; i < N->_mp_size; i++) {
		num = (*(t->_mp_d) * N_1);	//num = Ti * N_1 mod b
									//ģ2^32ͨ��num�����ʵ��
		mpz_addmul_ui(t, N, num);	//t = t + N*Num
		mpz_tdiv_q_2exp(t, t, MONTBITS);	//��t����MONTBITSλ
	}
	//ѭ������ʱ t Ӧ�� N ������ͬλ��
	//���� t < 2N
	if (mpz_cmp(t, N) >= 0) {
		mpz_mod(t, t, N);
	}

	//�����ʱ��t >= N
	//�Ǿ�������!
	assert(mpz_cmp(t, N) <= 0);

	mpz_set(T, t);
	mpz_clear(t);
}

void Bin_Exp(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t N)
{
	/*************************************************
		description:ʹ�� ģ�ظ�ƽ���� ���� base^exp mod N
		inputParam :
					base	����
					exp		ָ��
					N		ģ��
		outputParam:
					rop		������
	*************************************************/
	int i;
	mpz_set_ui(rop, 1);	//rop = 1
	for (i = mpz_sizeinbase(exp, 2) - 1; i >= 0; i--) {
		mpz_mul(rop, rop, rop);	//z  =z^2 
		if (mpz_tstbit(exp, i) == 1) {	//exp[i] == 1	
			mpz_mul(rop, rop, base);	//rop = rop*base
		}
		mpz_mod(rop, rop, N);	//rop = rop mod N
	}
}

void Mont_Exp(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t mod)
{
	mpz_t K, P, R, temp;
	mp_bitcnt_t index;
	unsigned int k = mpz_sizeinbase(mod, 2);
	mpz_inits(K, P, R, temp, NULL);
	mpz_set_ui(temp, 1);
	mpz_setbit(K, 2 * k);
	mpz_mod(K, K, mod);
	Mont_Pro(P, K, base, mod);
	Mont_Pro(R, K, temp, mod);
	for (index = 0; index < k; index++) {
		if (mpz_tstbit(exp, index) == 1)
			Mont_Pro(R, R, P, mod);
		Mont_Pro(P, P, P, mod);
	}
	Mont_Pro(rop, temp, R, mod);
	////test code
	//mpz_powm(temp, base, exp, mod);
	//if (mpz_cmp(temp, rop) != 0) {
	//	gmp_printf("r1 = %Zx\n", rop);
	//	gmp_printf("r2 = %Zx", temp);
	//	getchar();
	//}
	////test code
	mpz_clears(K, P, R, temp, NULL);
}

void Mont_Pro(mpz_t t, const mpz_t x, const mpz_t y, const mpz_t mod)	//Montgomery Product t = MontMul(x, y, mod)
{
	/*************************************************
		description:ʹ�� ģ�ظ�ƽ���� ���� base^exp mod N
		inputParam :
					base	����
					exp		ָ��
					N		ģ��
		outputParam:
					rop		������
	*************************************************/
	mpz_t z;
	mp_bitcnt_t index;
	mpz_init(z);
	unsigned int n = mpz_sizeinbase(mod, 2);
	mpz_set_ui(z, 0);
	for (index = 0; index < n; index++) {
		if (mpz_tstbit(x, index) == 1)	//Z = Z + Xi*Y
			mpz_add(z, z, y);
		if (mpz_odd_p(z) == true)	//if Z is odd
			mpz_add(z, z, mod);		//then Z = Z + M
		mpz_tdiv_q_2exp(z, z, 1);	//Z = Z / 2 (rshift 1 bit)
	}
	if (mpz_cmp(z, mod) > 0)
		mpz_sub(z, z, mod);
	mpz_set(t, z);
	mpz_clear(z);
}

void MontMulti(mpz_t T, const mpz_t x, const mpz_t y, const  mpz_t N, const mp_limb_t N_1)
{
	/*
	���ܣ�����x��y���ɸ������˻������������T�У����� 0<=x��y<N
	N��ģ
	N_1:����N*N_1=-1(mod 2^32)������
	*/

	int i;
	mp_limb_t num, carry, res[MONT_MAX] = { 0 };
	mp_limb_t *temp,t[MONT_MAX] = { 0 };

	//����x��y�ĳ˻���������t�У��������x��y��Ϊ�ɸ�������
	//mpn_mul����Ҫ��s1n > s2n
	if (x->_mp_size > y->_mp_size)
	   mpn_mul(t, x->_mp_d, x->_mp_size,y->_mp_d,y->_mp_size);
	else
	   mpn_mul(t, y->_mp_d, y->_mp_size, x->_mp_d, x->_mp_size);

	temp = t;
	for (i = 0; i < N->_mp_size; i++){
 		num = temp[0]*N_1;//num=t[0]*N_1
		res[i] = mpn_addmul_1(temp, N->_mp_d,N->_mp_size,num);//t=t+N*num,���Ǽӷ�ֻ����N->_mp_size�Σ�����N->_mp_size���ȵı�����res[i]��
		temp++;//�൱������2^32
	}
	
	carry = mpn_add_n(temp, temp, res, N->_mp_size);//�����沽��������û�д���Ľ�λres[i]һ���Եؼӵ�t��
	if (carry != 0 || mpn_cmp(temp, N->_mp_d, N->_mp_size) >= 0)//�ж��Ƿ���Ҫ-N
		mpn_sub_n(temp, temp, N->_mp_d, N->_mp_size);

	mpz_import(T, N->_mp_size, -1, sizeof(mp_limb_t), 0, 0,temp);//���õ��Ľ��������T��
}

void Mont_Exp_o(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t N)
{
	/*
	���ܣ������ɸ�����ģ�ˣ�����base^exp(mod N)�����������rop��
	*/
	mp_limb_t N_1;
	mpz_t K, P, R, temp, N_inv, b;
	mp_bitcnt_t index;
	unsigned int bitnum = mpz_sizeinbase(exp, 2);
	unsigned int rbit = N->_mp_size*MONTBITS;//�ɸ�������r��ѡ���Ǻ�ģ��λ����صģ�r=2^rbit���˴�����Ҫ��Nһ����1024���أ�1023��1022�ȣ��õ���rbitֵ����һ����
	mpz_inits(K, P, R, temp, N_inv, R, NULL);

	mpz_setbit(b, MONTBITS);	//b = 2^32
	mpz_invert(N_inv, N, b);//
	mpz_sub(N_inv, b, N_inv);
	N_1 = *(N_inv->_mp_d);	//N*N_1 =-1 (mod 2^32)

	mpz_set_ui(temp, 1);
	mpz_setbit(K, 2 * rbit);//K=r^2
	mpz_mod(K, K, N);//��֤0<=K<N

	MontMulti(P, K, base, N, N_1);//��base����ɸ���������P=K*base*r^-1=r^2*base*r^-1=base*r(mod N)�����Դ��ֱ�Ӽ���base<<rbit(modN)�����һ��
	MontMulti(R, K, temp, N, N_1);//��1����ɸ���������R==r^2*1*r^-1=r(mod N),���Դ��ֱ�Ӽ���1<<rbit(modN)�����һ��
	for (index = 0; index < bitnum; index++) {
		if (mpz_tstbit(exp, index) == 1)
			MontMulti(R, R, P, N, N_1);
		MontMulti(P, P, P, N, N_1);
	}
	MontMulti(rop, temp, R, N, N_1);//��R��ԭ����ͨ������rop=1*R*r^-1=base^exp(mod N)
	
	//test code,������Ϳ⺯�����жԱ�
	/*mpz_powm(temp, base, exp, N);
	if (mpz_cmp(temp, rop) != 0) {
		gmp_printf("r1 = %Zx\n", rop);
		gmp_printf("r2 = %Zx\n", temp);
		gmp_printf("mod = %Zx\n", N);
		gmp_printf("base = %Zx\n", base);
		gmp_printf("exp = %Zx\n", exp);
		getchar();
	}
	*/
	
	//test code
	mpz_clears(K, P, R, temp, N_inv, b, NULL);
}

void Mont_Test()
{
	gmp_randinit_lc_2exp_size(state, 128);	//���������״̬state
	gmp_randseed_ui(state, (unsigned long)time(NULL));
	int i;
	time_t t1, t2;
	mpz_t base, exp, mod, r1, r2;
	mpz_inits(base, exp, mod, r1, r2, NULL);

	mpz_rrandomb(exp, state, TESTBITS);
	mpz_rrandomb(mod, state, TESTBITS);
	mpz_rrandomb(base, state, TESTBITS);
	mpz_setbit(mod, 0);	//����modΪ����

	t1 = clock();
	for (i = 0; i < TESTCOUNT; i++) {
		mpz_powm(r1, base, exp, mod);
	}
	t2 = clock();
	printf("GMP mpz_powm ������ʱ: \t%lf\n", (double)(t2 - t1) / TESTCOUNT);

	t1 = clock();
	for (i = 0; i < TESTCOUNT; i++) {
		Mont_Exp_32(r1, base, exp, mod);
	}
	t2 = clock();
	printf("32λ�ɸ������㷨��ʱ : \t%lf\n", (double)(t2 - t1) / TESTCOUNT);

	t1 = clock();
	for (i = 0; i < TESTCOUNT; i++) {
		Bin_Exp(r1, base, exp, mod);
	}
	t2 = clock();
	printf("ģ�ظ�ƽ����ʱ : \t%lf\n", (double)(t2 - t1) / TESTCOUNT);

	getchar();
	getchar();
	mpz_clears(base, exp, mod, r1, r2, NULL);
}