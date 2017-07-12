
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "spn.h"

const unsigned int crackKey = 0x3a94d63f;

typedef struct {
	char x[sNum], y[sNum];
	int keyNum;
	int pairNum;
	double bias;
	spn_Text in;
}chain;

char approxTable[16][16];

char bitXor(char num);
int printb(int value, int quadbit);
void calcApprox();
void printApprox();
chain findChain_linear();
void findKey_linear(chain linear_chain);

int keyCracker(spn_Text *p1, spn_Text *p2, int n);

int main()
{
	int i;
	char op;
	chain linear_chain;
	spn_Text *pp, *cp;
	spn_Text plain, cypher;
	spn_Init();
	spn_SetKey(crackKey);
	calcApprox();
	while (1) {
		system("cls");
		printApprox();
		linear_chain = findChain_linear();
		printf("Run linear analysis. (y/n) :");
		scanf("%c", &op);
		getchar();
		switch (op) {
		case 'y': case 'Y':
			findKey_linear(linear_chain);
			pp = (spn_Text*)malloc(sizeof(spn_Text) * 5);
			cp = (spn_Text*)malloc(sizeof(spn_Text) * 5);
			for (i = 0; i < 5; i++) {
				plain = rand();
				cypher = spn_Encrypt_raw(&plain, &cypher);
				pp[i] = plain;
				cp[i] = cypher;
			}
			printf("Brute force crack >>>\n");
			keyCracker(pp, cp, 5);
			break;
		case 'n': case 'N':
			break;
		}
		getchar();
	}
}

int keyCracker(spn_Text *p1, spn_Text *p2, int num)
{
	clock_t t1, t2;
	int i, j, mark;
	MainKey key;
	spn_Text temp;
	t1 = clock();
	for (i = (int)pow(2, 24); i >= 0; i--) {
		key = ((i & 0xf) << 4) ^ ((i >> 4) << 12) ^ 0x60f;
		spn_SetKey(key);
		for (j = 0; j < num; j++) {
			spn_Encrypt_raw(p1 + j, &temp);
			if (temp == *(p2 + j)) {
				mark = 1;
				continue;
			}
			else {
				mark = 0;
				break;
			}
		}
		if (mark)
			break;
	}
	t2 = clock();
	printf("Key : %x\n", key);
	printf("time consumed : %ld ms", t2 - t1);
	getchar();
}

void calcApprox()
{
	char a, b;
	char x, y;
	for (a = 0; a < pow(2, sBits); a++)
		for (b = 0; b < pow(2, sBits); b++)
			approxTable[a][b] = 0;
	for (a = 0; a < pow(2, sBits); a++)
		for (b = 0; b < pow(2, sBits); b++)
			for (x = 0; x < pow(2, sBits); x++)
			{
				y = SBox(x, spn_Sub);
				if (bitXor(a & x) == bitXor(b & y))
					approxTable[a][b]++;
			}
}

void printApprox()
{
	char a, b;
	printf("Linear Approximation Table:\n");
	printf("\na\\b|");
	for (b = 0; b < pow(2, sBits); b++)
		printf("%3X", b);
	printf("\n");
	for (b = 0; b < 3 * pow(2, sBits) + 4; b++)
	{
		if (b == 3)
		{
			printf("|");
			continue;
		}
		printf("-");
	}
	printf("\n");
	for (a = 0; a < pow(2, sBits); a++)
	{
		printf("%3X|", a);
		for (b = 0; b < pow(2, sBits); b++)
		{
			printf("%3d", approxTable[a][b]);
		}
		printf("\n");
	}
}

char bitXor(char num)
{
	return (num & 0x1) ^ ((num & 0x2) >> 1) ^ ((num & 0x4) >> 2) ^ ((num & 0x8) >> 3) ^
		(num & 0x10) ^ ((num & 0x20) >> 4) ^ ((num & 0x40) >> 5) ^ ((num & 0x80) >> 6);
}

int printb(int value, int quadbit)
{
	int i;
	for (i = 0; i < 4 * quadbit; i++) {
		if ((i % 4 == 0) && (i != 0))
			printf(" | ");
		printf("%d", (value >> (4 * quadbit - i - 1)) & 0x1);
	}
	printf("\n");
	return 0;
}

chain findChain_linear()
{
	int sId;	//1234
	int r;
	int c;
	double bias;
	char smark[sNum];
	spn_Text u, v, x, y;
	spn_Text sIn[RoundNum - 1][sNum], sOut[RoundNum - 1][sNum];
	chain linear_chain;
	printf("Select an Initial Input : ");
	scanf("%hx", &x);
	getchar();
	u = x;
	bias = 1;
	//逐轮搜索找到最大spn逼近
	for (r = 0; r < RoundNum - 1; r++) {
		printf("\nRound %d\n", r + 1);
		printf("Probability bias now is : %lf\n", bias / 2);
		printf("--------------------------------\n");
		printf("...In  Vectors  : ");
		printb(u, 4);
		//标记活动的s盒
		printf("...Active S-Box : ");
		for (sId = sNum - 1; sId >= 0; sId--) {
			sIn[r][sId] = (u >> sId * 4) & 0xf;	//对u进行拆分 3210
			if ((u & (0xf << (sId * 4))) != 0) {
				smark[sId] = 1;
				printf("|  S%d  |", 4 - sId);	//转换为大端显示
			}
			else
				smark[sId] = 0;
		}
		printf("\n");
		//对活动的s盒寻找最大线性逼近
		v = 0;
		for (sId = sNum - 1; sId >= 0; sId--) {
			if (smark[sId] == 0) {
				sOut[r][sId] = 0;	//3210
				continue;
			}
			else {
				printf("......Select Out Vector for S%d: ", 4 - sId);
				scanf("%hx", &sOut[r][sId]);
				getchar();
				v = v ^ (sOut[r][sId] << sId * 4);
				bias = 2 * bias * (approxTable[sIn[r][sId]][sOut[r][sId]] - 8) / 16;	//线性链的概率偏差
			}
		}
		//根据选择的s盒输出P置换得到下一轮的随机变量输入
		u = Permutation(v, spn_Per);
		printf("...Out Vectors  : ");
		printb(v, 4);
		printf("...Next Round In: ");
		printb(u, 4);
		printf("--------------------------------\n");
	}
	y = u;
	c = 0;
	for (sId = 0; sId < sNum; sId++) {
		linear_chain.x[sId] = sIn[0][sId];
		linear_chain.y[sId] = (y >> sId * 4) & 0xf;
		if (u & (0xf << 4 * sId))
			c++;	//统计影响的密钥比特
	}
	linear_chain.bias = bias / 2;
	linear_chain.keyNum = c;
	linear_chain.pairNum = 1000 + (double)linear_chain.keyNum * 4 * pow(linear_chain.bias, -2);
	printf("Linear Approximation Chain : \n");
	printf("--------------------------------\n");
	printf("In  : ");
	printb(x, 4);
	printf("Out : ");
	printb(y, 4);
	printf("Probability Bias : %lf\n", linear_chain.bias);
	printf("Affected Key Bits : %d bit\n", linear_chain.keyNum * 4);
	printf("Known Plain/Cypher sample required : %d pairs", linear_chain.pairNum);
	getchar();
	return linear_chain;
}

void findKey_linear(chain linear_chain)
{
	int i, j;
	int *counter;	//候选密钥计数器指针
	int key, maxcount, maxkey;
	char *u, *v;
	char *mark;
	char z;
	clock_t t1, t2;
	spn_Text plain, cypher;
	u = (char*)malloc(sizeof(char) * linear_chain.keyNum);
	v = (char*)malloc(sizeof(char) * linear_chain.keyNum);
	mark = (char*)malloc(sizeof(char) * linear_chain.keyNum);
	counter = (int*)malloc(sizeof(int) * pow(2, 4 * linear_chain.keyNum));
	//分配并初始化密钥计数器
	for (i = 0; i < pow(2, 4 * linear_chain.keyNum); i++)
		counter[i] = 0;
	//v/u下标与实际位置的关系
	for (i = 0, j = 0; i < sNum; i++)
		if (linear_chain.y[i] != 0)
			mark[j++] = i;	//3210
	srand(time(0));
	//测试pairNum个明密文对
	t1 = clock();
	for (i = 0; i < linear_chain.pairNum; i++) {
		plain = rand() % 0xffff;	//生成16bit的随机明文
		spn_Encrypt_raw(&plain, &cypher);
		//测试候选密钥
		for (key = 0; key < pow(2, 4 * linear_chain.keyNum); key++) {
			z = 0;
			for (j = 0; j < linear_chain.keyNum; j++) {
				v[j] = ((cypher >> 4 * mark[j]) ^ (key >> 4 * j)) & 0xf;
				u[j] = SBox(v[j], spn_rSub);
				z = z ^ bitXor(u[j] & linear_chain.y[mark[j]]);
			}
			for (j = 0; j < sNum; j++)
				z = z ^ bitXor(linear_chain.x[j] & (plain >> (4 * j)));
			if (z == 0)
				counter[key]++;
		}
	}
	//遍历计数器寻找T/2最大偏移量
	maxcount = 0;
	for (key = 0; key < pow(2, 4 * linear_chain.keyNum); key++) {
		counter[key] = abs(counter[key] - linear_chain.pairNum / 2);
		if (counter[key] > maxcount)
		{
			maxcount = counter[key];
			maxkey = key;
		}
	}
	t2 = clock();
	for (i = 0; i <= RoundNum; i++)
		printf("...roundKey[%d] = %#x\n", i + 1, spn_Key->roundKey[i]);
	for (i = linear_chain.keyNum - 1; i >= 0; i--) {
		printf("k%d = %x\t", 4 - mark[i], (maxkey >> i * 4) & 0xf);
	}
	printf("\ntime consumed : %ld ms", t2 -t1);
	getchar();
}