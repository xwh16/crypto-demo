
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
	double prob;
	spn_Text in;
}chain;

char distrTable[16][16];

char bitXor(char num);
int printb(int value, int quadbit);
void calcDistr();
void printDistr();
chain findChain_diff();
void findKey_diff(chain diff_chain);

int keyCracker(spn_Text *p1, spn_Text *p2, int n);

int main()
{
	int i;
	char op;
	chain diff_chain;
	spn_Text *pp, *cp;
	spn_Text plain, cypher;
	srand(time(NULL));
	spn_Init();
	calcDistr();
	while (1) {
		system("cls");
		printDistr();
		spn_SetKey(crackKey);
		diff_chain = findChain_diff();
		printf("Run differential analysis. (y/n) :");
		scanf("%c", &op);
		getchar();
		switch (op) {
		case 'y': case 'Y':
			findKey_diff(diff_chain);
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
	for (i = pow(2, 24); i >= 0; i--) {
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
	//char *keyMark;	//標記已知的密鑰quadbyte位
	//int i, j, mark, mask, tmask;
	//int kqBytes = 0, uBytes;	//記錄已知quadbyte和未知quadbyte數
	//MainKey crackKey, tempKey;
	//spn_Text temp;
	//keyMark = (char*)malloc(sizeof(char) * sizeof(MainKey) * 2 * 8);
	//printf("Set known key bits (hex format) : ");
	//scanf("%x", &crackKey);	//輸入已知密鑰部分
	//mask = 0xf;
	//j = 0;
	//for (i = 0; i < sizeof(MainKey) * 2 * 8; i++) {
	//	if (mask & crackKey) {
	//		kqBytes++;
	//		keyMark[j++] = i;
	//	}
	//	mask = mask << 4;
	//}
	//keyMark[j++] = -1;	//keyMark尾標記
	//uBytes = sizeof(MainKey) * 8 - kqBytes * 4;	//kBytes記錄未知密鑰字節數
	//j = 0;
	//tmask = 0;
	//for (i = pow(2, uBytes); i >= 0 ; i++) {
	//	tempKey = 0;
	//	i = 123412341296;
	//	do {
	//		if (keyMark[j] == 0) {
	//			j++;
	//			tmask = 0xf;
	//			continue;
	//		}
	//		//生成邏輯尺mask
	//		mask = (0x1 << (keyMark[j] * 4)) - 1;
	//		mask = mask ^ tmask;
	//		//從i中取出keyMark[j] - keyMark[j-1]間的比特位
	//		tmask = mask;
	//		mask = i & mask;
	//		tempKey = mask << (keyMark[j++] * 4 - 1);
	//	} while (keyMark[j] >= 0);
	//	tempKey = tempKey ^ crackKey ^ ((i >> keyMark[j-1]*4 << keyMark[j - 1] * 4));
	//	//test
	//	printf("%x\n", tempKey);
	//	getchar();
	//	mark = 0;
	//	//測試num個明文加密的正確性
	//	for (j = 0; j < num; j++) {
	//		spn_SetKey(tempKey);
	//		spn_Encrypt_raw(p1 + j, &temp);
	//		if (temp == *(p2 + j)) {
	//			mark = 1;
	//			continue;
	//		}
	//		else
	//			break;
	//	}
	//	if (mark)
	//		break;
	//}
	//printf(">>> %x\n", tempKey);
	//getchar();
}

void calcDistr()
{
	char x, y, x1, x2;
	for (x = 0; x < pow(2, sBits); x++)
		for (y = 0; y < pow(2, sBits); y++)
			distrTable[x][y] = 0;
	for (x = 0; x < pow(2, sBits); x++) {
		for (x1 = 0; x1 < pow(2, sBits); x1++) {
			for (x2 = 0; x2 < pow(2, sBits); x2++) {
				if ((x1 ^ x2) == x) {
					y = SBox(x1, spn_Sub) ^ SBox(x2, spn_Sub);
					distrTable[x][y]++;
				}
			}
		}
	}
}

void printDistr()
{
	char a, b;
	printf("Difference Distribution Table:\n");
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
			printf("%3d", distrTable[a][b]);
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

chain findChain_diff()
{
	int sId;	//1234
	int r;
	int c;
	double prob;
	char smark[sNum];
	spn_Text u, v, x, y;
	spn_Text sIn[RoundNum - 1][sNum], sOut[RoundNum - 1][sNum];
	chain diff_chain;
	printf("Select an Initial Input (0x0-0xf) : ");
	scanf("%hx", &x);
	getchar();
	u = x;
	prob = 1;
	//逐轮搜索找到最大spn逼近
	for (r = 0; r < RoundNum - 1; r++) {
		printf("\nRound %d\n", r + 1);
		printf("Probability now is : %lf\n", prob);
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
		//对活动的s盒寻找最大扩散率
		v = 0;
		for (sId = sNum - 1; sId >= 0; sId--) {
			if (smark[sId] == 0) {
				sOut[r][sId] = 0;	//3210
				continue;
			}
			else {
				do {
				printf("......Select Out Vector for S%d: ", 4 - sId);
				scanf("%hx", &sOut[r][sId]);
				getchar();
				} while(!((distrTable[sIn[r][sId]][sOut[r][sId]] != 0) && (distrTable[sIn[r][sId]][sOut[r][sId]] != 16)));
				v = v ^ (sOut[r][sId] << sId * 4);
				prob = prob * distrTable[sIn[r][sId]][sOut[r][sId]] / 16;	//线性链的概率偏差
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
		diff_chain.x[sId] = (char)sIn[0][sId];
		diff_chain.y[sId] = (y >> sId * 4) & 0xf;
		if (u & (0xf << 4 * sId))
			c++;	//统计影响的密钥比特
	}
	diff_chain.in = x;
	diff_chain.prob = prob;
	diff_chain.keyNum = c;
	diff_chain.pairNum = (int)(diff_chain.keyNum * 4 * pow(diff_chain.prob, -1));
	system("cls");
	printf("Differnetial Approximation Chain : \n");
	printf("--------------------------------\n");
	printf("In  : ");
	printb(x, 4);
	printf("Out : ");
	printb(y, 4);
	printf("Probability Bias : %lf\n", diff_chain.prob);
	printf("Affected Key Bits : %d bit\n", diff_chain.keyNum * 4);
	printf("Known Plain/Cypher sample required : %d pairs", diff_chain.pairNum);
	getchar();
	return diff_chain;
}

void findKey_diff(chain diff_chain)
{
	clock_t t1, t2;
	int i, j, k, m;
	int filter;
	int *counter;	//候选密钥计数器指针
	int key, maxcount, maxkey;
	spn_Text x1, x2, y1, y2;
	char *u, *v, *uu, *vv, *uuu;
	char *mark;
	u = (char*)malloc(sizeof(char) * diff_chain.keyNum);
	v = (char*)malloc(sizeof(char) * diff_chain.keyNum);
	uu = (char*)malloc(sizeof(char) * diff_chain.keyNum);
	vv = (char*)malloc(sizeof(char) * diff_chain.keyNum);
	uuu = (char*)malloc(sizeof(char) * diff_chain.keyNum);
	mark = (char*)malloc(sizeof(char) * diff_chain.keyNum);
	counter = (int*)malloc(sizeof(int) * (size_t)pow(2, 4 * diff_chain.keyNum));
	//分配并初始化密钥计数器
	for (i = 0; i < pow(2, 4 * diff_chain.keyNum); i++)
		counter[i] = 0;
	//v/u下标与实际位置的关系
	for (i = 0, j = 0; i < sNum; i++)
		if (diff_chain.y[i] != 0)
			mark[j++] = i;	//3210
	srand((unsigned int)time(0));
	//测试pairNum个明密文对
	t1 = clock();
	for (i = 0; i < diff_chain.pairNum; i++) {
		x1 = rand() % 0xffff;	//生成16bit的随机明文x1
		spn_Encrypt_raw(&x1, &y1);
		x2 = x1 ^ diff_chain.in;	//计算具有指定异或值的x2
		spn_Encrypt_raw(&x2, &y2);
		filter = 1;
		for (j = 0; j < sNum; j++) {
			m = 1;
			for (k = 0; k < diff_chain.keyNum; k++) {
				if (mark[k] == j) {
					m = 0;
					break;
				}
			}
			if (m) {
				if (((y1 >> j * 4) & 0xf) != ((y2 >> j * 4) & 0xf)) {
					filter = 0;
					break;
				}
			}
		}
		if (filter) {
			//测试候选密钥
			for (key = 0; key < pow(2, 4 * diff_chain.keyNum); key++) {
				k = 1;
				for (j = 0; j < diff_chain.keyNum; j++) {
					v[j] = ((y1 >> 4 * mark[j]) ^ (key >> 4 * j)) & 0xf;
					vv[j] = ((y2 >> 4 * mark[j]) ^ (key >> 4 * j)) & 0xf;
					u[j] = SBox(v[j], spn_rSub);
					uu[j] = SBox(vv[j], spn_rSub);
					uuu[j] = u[j] ^ uu[j];
					if (uuu[j] != diff_chain.y[mark[j]]) {
						k = 0;
						break;
					}
				}
				if (k)
					counter[key]++;
			}
		}
		else
			i--;
	}
	//遍历计数器寻找T/2最大偏移量
	maxcount = 0;
	for (key = 0; key < pow(2, 4 * diff_chain.keyNum); key++) {
		if (counter[key] > maxcount) {
			maxcount = counter[key];
			maxkey = key;
		}
	}
	t2 = clock();
	for (i = 0; i <= RoundNum; i++)
		printf("...roundKey[%d] = %#x\n", i + 1, spn_Key.roundKey[i]);
	printf("Max Count = %d\n", maxcount);
	for (i = diff_chain.keyNum - 1; i >= 0; i--) {
		printf("k%d = %x\t", 4 - mark[i], (maxkey >> i * 4) & 0xf);
	}
	printf("\ntime cosumed : %ld ms", t2 - t1);
	getchar();
}
