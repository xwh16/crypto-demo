
#define _CRT_SECURE_NO_WARNINGS
#include <stdlib.h>
#include <stdio.h>
#include <time.h> 
#include "..\gmp.h"
#include "..\spn+\spn+.h"
#include "..\rsa\rsa.h"
#include "..\rsa\powm.h"
#include "file_system.h"

void file_init_session(MainKey sessionKey, spn_Text *initVect)
{
    /******************************************
	descripiton:�������SPN-CBCģʽ����
	outputParam:
				sessionKey	SPN��������Կ
				initVect	CBCģʽ��ʼ����
	******************************************/
    gmp_randstate_t state;
    mpz_inits(sessionKey, initVect, NULL);
    srand((unsigned int)time(NULL));
    gmp_randinit_lc_2exp_size(state, 128);
    gmp_randseed_ui(state, (unsigned long)time(NULL));
    mpz_urandomb(sessionKey, state, SPN_KEY_LENGTH);	   //��������ԿsessionKey
    *initVect = rand() * rand() * rand() % 0xffffffffffffffff; //���ɳ�ʼ����initVect
}

int file_encrypt(RSAPublicKey *RSApubKey)
{
    /******************************************
	descripiton:ʹ��CBC����ģʽ��SPN+��������ļ�
				�ļ�ͷд��RSA��Կ���ܺ��SPN��Կ�ͳ�ʼ����IV
	inputParam :
				RSApubKey	RSA��Կ�ṹָ��
	errorCode  :
				0			ALIZZWELL
				1			�ļ��򿪴���
	******************************************/
    clock_t t1, t2;
    mpz_t plain, cypher, temp;
    char buffer[20];
    FILE *fp1, *fp2;
    spn_Text initVect;
    MainKey sessionKey;
    mpz_t sessionInfo, RSAcypher;
    mpz_inits(plain, cypher, temp, sessionKey, RSAcypher, sessionInfo, NULL);
    //���ļ�
    {
	printf("����ʹ��SPN+���ܵ��ļ���:");
	scanf("%s", buffer);
	getchar();
	if ((fp1 = fopen(buffer, "rb")) == NULL)
	{
	    printf("�ļ� %s ��ʧ��.\n", buffer);
	    return FILE_OPEN_ERROR;
	}
	printf("������ܺ��ļ���:");
	scanf("%s", buffer);
	getchar();
	if ((fp2 = fopen(buffer, "wb")) == NULL)
	{
	    printf("�����ļ�����ʧ��.\n");
	    return FILE_OPEN_ERROR;
	}
    }
    //��������Կ�ͳ�ʼ����IV
    {
		file_init_session(sessionKey, &initVect); //���ɻỰ����
		gmp_printf("�����ļ�������Կ %d bit : %Zx\n", SPN_KEY_LENGTH, sessionKey);
		printf("CBCģʽ��ʼ����:%llx", initVect);
		getchar();
    }
    //ʹ��RSA�㷨���ܱ��λỰ������Կ�ͳ�ʼ����IV
    //��д��fp2�ļ�ͷ��
    {
		mpz_import(sessionInfo, 1, -1, sizeof(spn_Text), 0, 0, &initVect);	 //��initVect����sessionInfo
		mpz_mul_2exp(sessionInfo, sessionInfo, SPN_KEY_LENGTH); //����sessionInfoΪsessionKey�ڳ��ռ�
		mpz_xor(sessionInfo, sessionInfo, sessionKey);				   //sessionInfo | sessionKey
		rsa_pkcs1_encode(sessionInfo, 2);					   //��sessionInfo��pkcs#1 v1.5��׼����
		rsa_encrypt(RSApubKey, sessionInfo, RSAcypher, mpz_powm);
		mpz_out_raw(fp2, RSAcypher); //���ܺ��sessionInfoд���ļ�
    }
    //CBCģʽ����fp1�ļ���д��fp2
    spn_Encrypt_cbc(fp1, fp2, sessionKey, &initVect);
    //�ͷ��ļ�ָ��
    fclose(fp2);
    fclose(fp1);
    mpz_clears(plain, cypher, temp, sessionKey, sessionInfo, RSAcypher, NULL);
}

int file_decrypt(RSAPrvateKey *RSAprvKey)
{
    /******************************************
	descripiton:ʹ��CBC����ģʽ��SPN+��������ļ�
				���ļ�ͷ����RSA��Կ���ܺ��SPN��Կ�ͳ�ʼ����IV
	inputParam :
				RSAprvKey	RSA˽Կ�ṹָ��
	errorCode  :
				0			ALIZZWELL
				1			�ļ��򿪴���
	******************************************/
    clock_t t1, t2;
    mpz_t plain, cypher, temp;
    char buffer[20];
    FILE *fp1, *fp2;
    spn_Text initVect;
    MainKey sessionKey;
    mpz_t sessionInfo, RSAcypher;
    mpz_inits(plain, cypher, temp, sessionKey, RSAcypher, sessionInfo, NULL);
    //���ļ�
    {
	printf("����ʹ��SPN+���ܵ��ļ���:");
	scanf("%s", buffer);
	getchar();
	if ((fp1 = fopen(buffer, "rb")) == NULL)
	{
	    printf("�ļ� %s ��ʧ��.\n", buffer);
	    return FILE_OPEN_ERROR;
	}
	printf("������ܺ��ļ���:");
	scanf("%s", buffer);
	getchar();
	if ((fp2 = fopen(buffer, "wb")) == NULL)
	{
	    printf("�����ļ�����ʧ��.\n");
	    return FILE_OPEN_ERROR;
	}
    }
    //��fp1�ļ�ͷ����sessionInfo
    //�����ú�sessionKey��initVect
    {
		mpz_inp_raw(RSAcypher, fp1);
		rsa_decrypt(RSAprvKey, sessionInfo, RSAcypher, 1, mpz_powm);
		if (rsa_pkcs1_decode(sessionInfo)){
			printf("RSA pkcs#1 �������.\n");
			getchar();
			return 2;
		}
		mpz_set_ui(temp, 0x1);
		mpz_mul_2exp(temp, temp, SPN_KEY_LENGTH);
		mpz_sub_ui(temp, temp, 1);		//�γɵ�λ���߼���
		mpz_and(sessionKey, sessionInfo, temp); //ʹ���߼���ȡ����λ��sessionKey
		mpz_tdiv_q_2exp(sessionInfo, sessionInfo, SPN_KEY_LENGTH);
		mpz_export(&initVect, NULL, -1, sizeof(spn_Text), 0, 0, sessionInfo);
		gmp_printf("�����ļ�������Կ %d bit : %Zx\n", SPN_KEY_LENGTH, sessionKey);
		printf("CBCģʽ��ʼ����:%llx", initVect);
		getchar();
    }
    //CBCģʽ�����ļ�fp1д��fp2
    spn_Decrypt_cbc(fp1, fp2, sessionKey, &initVect);
    //�ͷ��ļ�ָ��
    fclose(fp2);
    fclose(fp1);
    mpz_clears(plain, cypher, temp, sessionKey, sessionInfo, RSAcypher, NULL);
	return 0;
}

int file_system()
{
    char op = 1;
    char mark = 0, flag = 0;
    char prvf = 0, pubf = 0;
    char buffer[20];
    clock_t t1, t2;
    mpz_t plain, cypher, temp;
    RSAPublicKey RSApubKey;
    RSAPrvateKey RSAprvKey;
    FILE *fp1;
    spn_Text initVect;
    mpz_inits(plain, cypher, temp, NULL);
    rsa_init();
    spn_Init();
    rsa_init_key(&RSApubKey, &RSAprvKey);
    while (op)
    {
		printf("RSA & SPN+ �ļ����ܳ���\n");
		printf("-------------------\n");
		printf("1.����RSA��Կ����֤��\n");
		printf("2.����RSA˽Կ����֤��\n");
		printf("3.ʹ��RSA�������� (pkcs#1 padding)\n");
		printf("4.ʹ�ù�Կ�����ļ�\n");
		printf("5.ʹ��˽Կ�����ļ�\n");
		printf("0.�����ϼ��˵�:\n");
		scanf("%d", &op);
		getchar();
		if (op > 5)
		{
			printf("���������.\n");
			getchar();
			continue;
		}
		else if (op == 0)
		{
			mpz_clears(plain, cypher, temp, NULL);
			rsa_destroy_key(&RSApubKey, &RSAprvKey);
			rsa_quit();
			return 0;
		}
		switch (op)
		{
		case 1:
		{
			printf("���빫Կ֤����:");
			scanf("%s", buffer);
			getchar();
			if ((fp1 = fopen(buffer, "rb")) == NULL)
				break;
			if ((flag = rsa_imp_puk(fp1, &RSApubKey)) == 3)
			{
				printf("��ȡRSA�㷨��������.\n");
				printf("��������ʽ��gmp������.\n");
				break;
			}
			else if (flag == 2)
			{
				printf("֤���ʽ����.\n");
				break;
			}
			else if (flag)
			{
				printf("��֤�����.\n");
				break;
			}
			else
			{
				printf("----------------------------------------------------\n");
				gmp_printf("��������ָ��:%Zx\n", RSApubKey.publicExponent);
				printf("----------------------------------------------------\n");
				gmp_printf("ģ��:%Zx\n", RSApubKey.modulus);
				printf("----------------------------------------------------\n");
			}
			pubf = 1;
			fclose(fp1);
			break;
		}
		case 2:
		{
			printf("����˽Կ֤����:");
			scanf("%s", buffer);
			getchar();
			if ((fp1 = fopen(buffer, "rb")) == NULL)
				break;
			if ((flag = rsa_imp_prk(fp1, &RSAprvKey)) == 3)
			{
				printf("��ȡRSA�㷨��������.\n");
				printf("��������ʽ��gmp������.\n");
				break;
			}
			else if (flag == 2)
			{
				printf("֤���ʽ����.\n");
				break;
			}
			else if (flag)
			{
				printf("��֤�����.\n");
				break;
			}
			else
			{
				printf("----------------------------------------------------\n");
				gmp_printf("˽Կ:\n˽��ָ�� : %Zx\n", RSAprvKey.privateExponet);
				printf("----------------------------------------------------\n");
			}
			prvf = 1;
			fclose(fp1);
			break;
		}
		case 3:
		{
			if (prvf && pubf)
			{
				printf("����ʹ��RSA���ܵ�����:\n");
				gmp_scanf("%Zx", plain);
				mpz_set(temp, plain);
				getchar();
				printf("----------------------------------------------------\n");
				t1 = clock();
				rsa_pkcs1_encode(temp, 2);
				rsa_encrypt(&RSApubKey, temp, cypher, mpz_powm);
				t2 = clock();
				printf("RSA������ʱ:%ld ms\n", t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("����:\n%Zx\n", cypher);
				printf("----------------------------------------------------\n");
				t1 = clock();
				rsa_decrypt(&RSAprvKey, temp, cypher, 1, mpz_powm);
				rsa_pkcs1_decode(temp);
				t2 = clock();
				printf("RSA������ʱ:%ld ms\n", t2 - t1);
				printf("----------------------------------------------------\n");
				gmp_printf("���ܺ���Ϣ:\n%Zx\n", temp);
				printf("----------------------------------------------------\n");
				if (mpz_cmp(temp, plain) != 0)
					printf("������Ϣ����.\n");
			}
			else
			printf("RSA�㷨����ȱʧ.\n");
			break;
		}
		case 4:
		{
			file_encrypt(&RSApubKey);
			break;
		}
		case 5:
		{
			file_decrypt(&RSAprvKey);
			break;
		}
		}
		getchar();
    }
    return 0;
}