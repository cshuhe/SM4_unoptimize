#include "SM4.h"
#include<iostream>
#include <windows.h>
#include <cstdlib> 
using namespace std;
class TimeCounter {
public:
	TimeCounter(void) {
		QueryPerformanceFrequency(&CPUClock);
	}
	double timeInterval;
private:
	LARGE_INTEGER startTime, endTime, CPUClock;

public:
	void start() {
		QueryPerformanceCounter(&startTime);
	}
	void end() {
		QueryPerformanceCounter(&endTime);
		timeInterval = 1e3 * ((double)endTime.QuadPart - (double)startTime.QuadPart) / (double)CPUClock.QuadPart;
		//ms
	}
};
void random_char_generator(unsigned char str[16]) {
	unsigned char r = 0, l = 255;
	srand(time(0));
	for (int i = 0; i < 16; i++) {
		str[i] = (rand() % (r - l + 1) + l);
	}
}
void SM4_KeySchedule(unsigned char MK[], unsigned int rk[]) {
	unsigned int tmp, buf, K[36]{};
	int i;
	for (i = 0; i < 4; i++) {
		K[i] = SM4_FK[i] ^ ((MK[4 * i] << 24) | (MK[4 * i + 1] << 16)
			| (MK[4 * i + 2] << 8) | (MK[4 * i + 3]));
	}
	for (i = 0; i < 32; i++) {
		tmp = K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ SM4_CK[i];
		//nonlinear operation
		buf = (SM4_Sbox[(tmp >> 24) & 0xFF]) << 24
			| (SM4_Sbox[(tmp >> 16) & 0xFF]) << 16
			| (SM4_Sbox[(tmp >> 8) & 0xFF]) << 8
			| (SM4_Sbox[tmp & 0xFF]);
		//linear operation
		K[i + 4] = K[i] ^ ((buf) ^ (SM4_Rotl32((buf), 13)) ^ (SM4_Rotl32((buf), 23)));
		rk[i] = K[i + 4];
	}
}
void SM4_Encrypt(unsigned char MK[], unsigned char PlainText[], unsigned char CipherText[]) {
	unsigned int rk[32], X[36], tmp, buf;
	int i, j;
	SM4_KeySchedule(MK, rk);
	for (j = 0; j < 4; j++) {
		int j_4 = j * 4;
		X[j] = (PlainText[j_4] << 24) | (PlainText[j_4 + 1] << 16)
			| (PlainText[j_4 + 2] << 8) | (PlainText[j_4 + 3]);
	}
	for (i = 0; i < 32; i++) {
		tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[i];
		//nonlinear operation
		buf = (SM4_Sbox[(tmp >> 24) & 0xFF]) << 24
			| (SM4_Sbox[(tmp >> 16) & 0xFF]) << 16
			| (SM4_Sbox[(tmp >> 8) & 0xFF]) << 8
			| (SM4_Sbox[tmp & 0xFF]);
		//linear operation
		X[i + 4] = X[i] ^ (buf ^ SM4_Rotl32((buf), 2) ^ SM4_Rotl32((buf), 10)
			^ SM4_Rotl32((buf), 18) ^ SM4_Rotl32((buf), 24));
	}
	for (j = 0; j < 4; j++) {
		int j_4 = j * 4, j_35 = 35 - j;
		CipherText[j_4] = (X[j_35] >> 24) & 0xFF;
		CipherText[j_4 + 1] = (X[j_35] >> 16) & 0xFF;
		CipherText[j_4 + 2] = (X[j_35] >> 8) & 0xFF;
		CipherText[j_4 + 3] = (X[j_35]) & 0xFF;
	}
}
void SM4_Decrypt(unsigned char MK[], unsigned char CipherText[], unsigned char PlainText[])
{
	unsigned int rk[32], X[36], tmp, buf;
	int i, j;
	SM4_KeySchedule(MK, rk);
	for (j = 0; j < 4; j++) {
		int j_4 = j * 4;
		X[j] = (CipherText[j_4] << 24) | (CipherText[j_4 + 1] << 16) |
			(CipherText[j_4 + 2] << 8) | (CipherText[j_4 + 3]);
	}
	for (i = 0; i < 32; i++) {
		tmp = X[i + 1] ^ X[i + 2] ^ X[i + 3] ^ rk[31 - i];
		//nonlinear operation
		buf = (SM4_Sbox[(tmp >> 24) & 0xFF]) << 24
			| (SM4_Sbox[(tmp >> 16) & 0xFF]) << 16
			| (SM4_Sbox[(tmp >> 8) & 0xFF]) << 8
			| (SM4_Sbox[tmp & 0xFF]);
		//linear operation
		X[i + 4] = X[i] ^ (buf ^ SM4_Rotl32((buf), 2) ^ SM4_Rotl32((buf), 10)
			^ SM4_Rotl32((buf), 18) ^ SM4_Rotl32((buf), 24));
	}
	for (j = 0; j < 4; j++) {
		int j_4 = j * 4, j_35 = 35 - j;
		PlainText[j_4] = (X[j_35] >> 24) & 0xFF;
		PlainText[j_4 + 1] = (X[j_35] >> 16) & 0xFF;
		PlainText[j_4 + 2] = (X[j_35] >> 8) & 0xFF;
		PlainText[j_4 + 3] = (X[j_35]) & 0xFF;
	}
}
int SM4_SelfCheck() {
	int i;
	//Standard data
	unsigned char key[16] =
	{ 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
	unsigned char plain[16] =
	{ 0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10 };
	unsigned char
		cipher[16] = { 0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46 }
	;
	unsigned char En_output[16];
	unsigned char De_output[16];
	TimeCounter Timer1, Timer2;

	Timer1.start();
	SM4_Encrypt(key, plain, En_output);
	Timer1.end();

	cout << "Enc spends " << Timer1.timeInterval << "ms" << endl;

	Timer2.start();
	SM4_Decrypt(key, cipher, De_output);
	Timer2.end();
	cout << "Dec spends " << Timer2.timeInterval << "ms" << endl;

	for (i = 0; i < 16; i++)
	{
		if ((En_output[i] != cipher[i]) | (De_output[i] != plain[i]))
		{
			printf("Self-check error");
			return 1;
		}
	}
	printf("Self-check success");
	return 0;
}

int SM4_Test() {
	int i;
	unsigned char key[16], plain[16], cipher[16], De_output[16];
	random_char_generator(key); random_char_generator(plain);
	TimeCounter Timer1, Timer2;

	Timer1.start();
	SM4_Encrypt(key, plain, cipher);
	Timer1.end();

	cout << "Enc spends " << Timer1.timeInterval << "ms" << endl;

	Timer2.start();
	SM4_Decrypt(key, cipher, De_output);
	Timer2.end();
	cout << "Dec spends " << Timer2.timeInterval << "ms" << endl;

	for (i = 0; i < 16; i++) {
		if ((De_output[i] != plain[i])) {
			printf("Self-check error\n");
			return 1;
		}
	}
	printf("Self-check success\n");
	return 0;
}

int main() {
	SM4_Test();
}
