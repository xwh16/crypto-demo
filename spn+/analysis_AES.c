
#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <time.h>
#include "spn+.h"

typedef struct {
	char x[sNum], y[sNum];
	int keyNum;
	int pairNum;
	double bias;
	spn_Text in;
}chain;

unsigned char approxTable[256][256];

unsigned char bitXor(unsigned char num);
void calcApprox();
void printApprox();

int main()
{
	spn_Init();
	calcApprox();
	printApprox();
    //getchar();
}

void calcApprox()
{
	unsigned int a, b;
	unsigned int x, y;
	for (a = 0; a < 256; a++)
		for (b = 0; b < 256; b++)
			approxTable[a][b] = 0;
	for (a = 0; a < 256; a++)
		for (b = 0; b < 256; b++)
			for (x = 0; x < 256; x++)
			{
				y = SBox(x, spn_Sub);
				if (bitXor(a & x) == bitXor(b & y))
					approxTable[a][b]++;
			}
}

void printApprox()
{
	unsigned int a, b;
	/*printf("Linear Approximation Table:\n");
	printf("\n a\\b|");
	for (b = 0; b < 256; b++)
		printf("%3X", b);
	printf("\n");
	for (b = 0; b < 3 * 256 + 4; b++)
	{
		if (b == 3)
		{
			printf("|");
			continue;
		}
		printf("-");
	}
	printf("\n");*/
	for (a = 0; a < 256; a++)
	{
		//printf("%3X|", a);
		for (b = 0; b < 256; b++)
		{
			printf("%3d", approxTable[a][b]);
		}
		printf("\n");
	}
}

unsigned char bitXor(unsigned char num)
{
	return (num & 0x1) ^ ((num & 0x2) >> 1) ^ ((num & 0x4) >> 2) ^ ((num & 0x8) >> 3) ^
		(num & 0x10) ^ ((num & 0x20) >> 4) ^ ((num & 0x40) >> 5) ^ ((num & 0x80) >> 6);
}