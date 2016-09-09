
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <assert.h>
#include "..\gmp.h"
#include "powm.h"

//启用蒙哥马利正确性测试
#define MONT_CHECK

//Mont_Test的测试次数
#define TESTCOUNT 100
//Mont_Test的模数最大位数
#define TESTBITS 1024
//以mp_limb_t为蒙哥马利乘运算位数
#define MONTBITS (8*sizeof(mp_limb_t))
//假设蒙哥马利中的T=XY的最大位数不超过MONT_MAX个mp_limb_t
#define MONT_MAX 64
//随机数状态
gmp_randstate_t state; 


void Mont_Exp_32(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t N)
{
	/*************************************************
		description:使用 蒙哥马利算法 计算 rop = base^exp mod N
		inputParam :
					base	底数
					exp		指数
					N		模数, 假定为奇数
		outputParam:
					rop		运算结果
	*************************************************/
	assert(mpz_odd_p(N) == true);	//N必须为奇数

	mp_limb_t N_1;	
	mp_bitcnt_t ebit;
	mp_bitcnt_t rbit;
	mp_bitcnt_t index;	//循环计数器

	mpz_t K;	
	mpz_t P, R;
	mpz_t temp, N_inv, b;
	mpz_inits(K, P, R, temp, N_inv, b, NULL);	//初始化mpz大数变量

	rbit = N->_mp_size*MONTBITS;	//模数N位数
	ebit = mpz_sizeinbase(exp, 2);	//指数exp位数

	mpz_setbit(b, MONTBITS);	//b = 2^32
	mpz_invert(N_inv, N, b);	
	mpz_sub(N_inv, b, N_inv);	
	N_1 = *(N_inv->_mp_d);	//N_1*N = -1 mod R

	mpz_set_ui(temp, 1);	//temp = 1
	mpz_setbit(K, 2 * rbit);	
	mpz_mod(K, K, N);	//K = 2^(2*rbit) mod N

	Mont_Pro_32(P, K, base, N, N_1);	//将base转化为蒙哥马利数 P
	Mont_Pro_32(R, K, temp, N, N_1);	//将  1 转化为蒙哥马利数 R
	for (index = 0; index < ebit; index++) {
		if (mpz_tstbit(exp, index) == 1)
			Mont_Pro_32(R, R, P, N, N_1);	//R = R*P mod N
		Mont_Pro_32(P, P, P, N, N_1);	//P = P*P mod N
	}
	Mont_Pro_32(rop, temp, R, N, N_1);	//将R转化回实数域

#ifdef MONT_CHECK
	/*
		测试代码
		使用gmp:mpz_powm()测试模幂运算结果正确性
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

	mpz_clears(K, P, R, temp, N_inv, b, NULL);	//销毁mpz大数变量
}

void Mont_Pro_32(mpz_t T, const mpz_t x, const mpz_t y, const mpz_t N, const mp_limb_t N_1)
{
	/*************************************************
	description:使用 REDC 计算 x*y*r^(-1) mod N
	inputParam :
				x, y	操作数1, 2, 假定为蒙哥马利数
				N		模数
				N_1		预计算的 -N^(-1) mod b
	outputParam:
				rop		运算结果
	*************************************************/
	int i;
	mpz_t t;
	mp_limb_t num;
	mpz_init(t);
	mpz_mul(t, x, y);		//T = xy
	for (i = 0; i < N->_mp_size; i++) {
		num = (*(t->_mp_d) * N_1);	//num = Ti * N_1 mod b
									//模2^32通过num的溢出实现
		mpz_addmul_ui(t, N, num);	//t = t + N*Num
		mpz_tdiv_q_2exp(t, t, MONTBITS);	//将t右移MONTBITS位
	}
	//循环结束时 t 应与 N 具有相同位数
	//并且 t < 2N
	if (mpz_cmp(t, N) >= 0) {
		mpz_mod(t, t, N);
	}

	//如果这时候t >= N
	//那就碰鬼了!
	assert(mpz_cmp(t, N) <= 0);

	mpz_set(T, t);
	mpz_clear(t);
}

void Bin_Exp(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t N)
{
	/*************************************************
		description:使用 模重复平方法 计算 base^exp mod N
		inputParam :
					base	底数
					exp		指数
					N		模数
		outputParam:
					rop		运算结果
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
		description:使用 模重复平方法 计算 base^exp mod N
		inputParam :
					base	底数
					exp		指数
					N		模数
		outputParam:
					rop		运算结果
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
	功能：计算x和y的蒙哥马利乘积，结果保存在T中，其中 0<=x，y<N
	N：模
	N_1:满足N*N_1=-1(mod 2^32)的整数
	*/

	int i;
	mp_limb_t num, carry, res[MONT_MAX] = { 0 };
	mp_limb_t *temp,t[MONT_MAX] = { 0 };

	//计算x和y的乘积，保存在t中，这里假设x和y均为蒙哥马利数
	//mpn_mul函数要求s1n > s2n
	if (x->_mp_size > y->_mp_size)
	   mpn_mul(t, x->_mp_d, x->_mp_size,y->_mp_d,y->_mp_size);
	else
	   mpn_mul(t, y->_mp_d, y->_mp_size, x->_mp_d, x->_mp_size);

	temp = t;
	for (i = 0; i < N->_mp_size; i++){
 		num = temp[0]*N_1;//num=t[0]*N_1
		res[i] = mpn_addmul_1(temp, N->_mp_d,N->_mp_size,num);//t=t+N*num,但是加法只做了N->_mp_size次，超出N->_mp_size长度的保存在res[i]中
		temp++;//相当于整除2^32
	}
	
	carry = mpn_add_n(temp, temp, res, N->_mp_size);//将上面步骤中所有没有处理的进位res[i]一次性地加到t上
	if (carry != 0 || mpn_cmp(temp, N->_mp_d, N->_mp_size) >= 0)//判断是否需要-N
		mpn_sub_n(temp, temp, N->_mp_d, N->_mp_size);

	mpz_import(T, N->_mp_size, -1, sizeof(mp_limb_t), 0, 0,temp);//将得到的结果保存在T中
}

void Mont_Exp_o(mpz_t rop, const mpz_t base, const mpz_t exp, const mpz_t N)
{
	/*
	功能：利用蒙哥马利模乘，计算base^exp(mod N)，结果保存在rop中
	*/
	mp_limb_t N_1;
	mpz_t K, P, R, temp, N_inv, b;
	mp_bitcnt_t index;
	unsigned int bitnum = mpz_sizeinbase(exp, 2);
	unsigned int rbit = N->_mp_size*MONTBITS;//蒙哥马利中r的选择是和模的位数相关的，r=2^rbit。此处并不要求N一定是1024比特，1023，1022等，得到的rbit值都是一样的
	mpz_inits(K, P, R, temp, N_inv, R, NULL);

	mpz_setbit(b, MONTBITS);	//b = 2^32
	mpz_invert(N_inv, N, b);//
	mpz_sub(N_inv, b, N_inv);
	N_1 = *(N_inv->_mp_d);	//N*N_1 =-1 (mod 2^32)

	mpz_set_ui(temp, 1);
	mpz_setbit(K, 2 * rbit);//K=r^2
	mpz_mod(K, K, N);//保证0<=K<N

	MontMulti(P, K, base, N, N_1);//将base变成蒙哥马利数，P=K*base*r^-1=r^2*base*r^-1=base*r(mod N)，所以大家直接计算base<<rbit(modN)会更快一点
	MontMulti(R, K, temp, N, N_1);//将1变成蒙哥马利数，R==r^2*1*r^-1=r(mod N),所以大家直接计算1<<rbit(modN)会更快一点
	for (index = 0; index < bitnum; index++) {
		if (mpz_tstbit(exp, index) == 1)
			MontMulti(R, R, P, N, N_1);
		MontMulti(P, P, P, N, N_1);
	}
	MontMulti(rop, temp, R, N, N_1);//将R还原成普通整数，rop=1*R*r^-1=base^exp(mod N)
	
	//test code,将结果和库函数进行对比
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
	gmp_randinit_lc_2exp_size(state, 128);	//设置随机数状态state
	gmp_randseed_ui(state, (unsigned long)time(NULL));
	int i;
	time_t t1, t2;
	mpz_t base, exp, mod, r1, r2;
	mpz_inits(base, exp, mod, r1, r2, NULL);

	mpz_rrandomb(exp, state, TESTBITS);
	mpz_rrandomb(mod, state, TESTBITS);
	mpz_rrandomb(base, state, TESTBITS);
	mpz_setbit(mod, 0);	//设置mod为奇数

	t1 = clock();
	for (i = 0; i < TESTCOUNT; i++) {
		mpz_powm(r1, base, exp, mod);
	}
	t2 = clock();
	printf("GMP mpz_powm 函数用时: \t%lf\n", (double)(t2 - t1) / TESTCOUNT);

	t1 = clock();
	for (i = 0; i < TESTCOUNT; i++) {
		Mont_Exp_32(r1, base, exp, mod);
	}
	t2 = clock();
	printf("32位蒙哥马利算法用时 : \t%lf\n", (double)(t2 - t1) / TESTCOUNT);

	t1 = clock();
	for (i = 0; i < TESTCOUNT; i++) {
		Bin_Exp(r1, base, exp, mod);
	}
	t2 = clock();
	printf("模重复平方用时 : \t%lf\n", (double)(t2 - t1) / TESTCOUNT);

	getchar();
	getchar();
	mpz_clears(base, exp, mod, r1, r2, NULL);
}