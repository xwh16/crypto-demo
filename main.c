
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <time.h>
#include <Windows.h>
#include "gmp.h"
#include "spn+\spn+.h"
#include "rsa\rsa.h"
#include "rsa\powm.h"
#include "file_system\file_system.h"

RSAPublicKey RSApubKey;
RSAPrivateKey RSAprvKey;

int main()
{
	int op = 1;
	while (op) {
		system("cls");
		printf("选择测试类型:\n");
		printf("1.Mont_Test\n");
		printf("2.RSA_Test\n");
		printf("3.SPN_Test\n");
		printf("4.File_Encrypt\n");
		printf("0.Exit\n");
		scanf("%d", &op);
		system("cls");
		switch (op) {
		case 1:
			Mont_Test();
			break;
		case 2:
			rsa_test();
			break;
		case 3:
			spn_test();
			break;
		case 4:
			file_system();
			break;
		case 0:
			return 0;
		}
	}
}
