#include "aes.h"

//학번_이름
char SUBMISSION_INFO[256] = "2021350027_강재현";

//관련 데이터 타입 정의 내역
typedef uint8_t AES_STATE_t[16];
typedef uint8_t AES128_KEY_t[16];
typedef uint8_t AES192_KEY_t[24];
typedef uint8_t AES256_KEY_t[32];

//MixColumns에서 이용할 함수 Mul
uint8_t Mul(uint8_t a, uint8_t b)
{
	uint8_t temp;
	if (a == 1)
		return b;

	else if (a == 2)
	{
		if (b * 2 >= 0x100)
		{
			b = b * 2 - 0x100;
			b = b ^ 0x1B;
		}
		else
		{
			b = b * 2;
		}
	}
	else if (a == 3)
	{
		b = b ^ Mul(2, b);
	}
	else if (a == 9)
	{
		temp = Mul(2, b);
		temp = Mul(2, temp);
		temp = Mul(2, temp);
		b = b ^ temp;
	}
	else if (a == 11)
	{
		temp = Mul(2, b);
		temp = Mul(2, temp);
		temp = b ^ temp;
		temp = Mul(2, temp);
		b = b ^ temp;
	}
	else if (a == 13)
	{
		temp = Mul(2, b);
		temp = b ^ temp;
		temp = Mul(2, temp);
		temp = Mul(2, temp);
		b = b ^ temp;
	}
	else if (a == 14)
	{
		temp = Mul(2, b);
		temp = b ^ temp;
		temp = Mul(2, temp);
		temp = b ^ temp;
		b = Mul(2, temp);
	}
	return b;
}

//MixColumn에서 이용할 Mix 배열과 inverse
AES_STATE_t Mix = {
	0x02, 0x03, 0x01, 0x01,
	0x01, 0x02, 0x03, 0x01,
	0x01, 0x01, 0x02, 0x03,
	0x03, 0x01, 0x01, 0x02 };
AES_STATE_t Inv_Mix = {
	0x0E, 0x0B, 0x0D, 0x09,
	0x09, 0x0E, 0x0B, 0x0D,
	0x0D, 0x09, 0x0E, 0x0B,
	0x0B, 0x0D, 0x09, 0x0E};

//S Box
uint8_t SBox[256] = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
//S Box의 inverse 구하기
uint8_t Inv_SBox[256] = { 0x00, };
void Make_Inv_SBox()
{
	for (int i = 0; i < 256; i++)
		Inv_SBox[SBox[i]] = i;
}

//연산에 필요한 Temp 변수들
AES_STATE_t Temp;

//라운드 키 생성 과정 필요한 변수들과 함수들
uint8_t Keytemp[32];
uint8_t RC_128[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
uint8_t RC_192[8] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
uint8_t RC_256[7] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40 };
uint8_t word[240];
uint8_t wtemp[4];
uint8_t Round[240];
void RotWord(int r)
{
	wtemp[0] = word[4 * r + 1];
	wtemp[1] = word[4 * r + 2];
	wtemp[2] = word[4 * r + 3];
	wtemp[3] = word[4 * r + 0];
}
void SubWord()
{
	for (int i = 0; i < 4; i++)
		wtemp[i] = SBox[wtemp[i]];
}
void RCons(int i, uint8_t c)
{
	wtemp[0] = c ^ wtemp[0];
}

//키 확장 후 라운드키 생성
void RoundKey(int R)
{
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		Round[16 * R + i] = word[16 * R + 4 * b + a];
	}
}
void KeyExpansion_128()
{
	//RoundKey0 (word0~word3)
	for (int i = 0; i < 16; i++)
	{
		word[i] = Keytemp[i];
	}
	for (int R = 1; R <= 10; R++)
	{
		RotWord(4 * R - 1);//word 4R-1에서 함수를 시작한다. 처음에 R이 1이면 인자로 3을 준다.
		SubWord();
		RCons(4 * R - 1, RC_128[R - 1]);
		for (int r = 0; r < 4; r++)
		{
			word[16 * R + r] = wtemp[r] ^ word[16 * (R - 1) + r];
			word[16 * R + 4 + r] = word[16 * R + r] ^ word[16 * (R - 1) + 4 + r];
			word[16 * R + 8 + r] = word[16 * R + 4 + r] ^ word[16 * (R - 1) + 8 + r];
			word[16 * R + 12 + r] = word[16 * R + 8 + r] ^ word[16 * (R - 1) + 12 + r];
		}
	}
	for (int r = 0; r <= 10; r++)
	{
		RoundKey(r);
	}
}
void KeyExpansion_192()
{
	//word 0~5
	for (int i = 0; i < 24; i++)
		word[i] = Keytemp[i];
	//word 6개씩 7번 반복 6~47
	for (int R = 1; R < 8; R++)
	{
		RotWord(6 * R - 1);
		SubWord();
		RCons(6 * R - 1, RC_192[R - 1]);
		for (int i = 0; i < 4; i++)
		{
			word[24 * R + i] = wtemp[i] ^ word[24 * (R - 1) + i];
			word[24 * R + 4 + i] = word[24 * R + i] ^ word[24 * (R - 1) + 4 + i];
			word[24 * R + 8 + i] = word[24 * R + 4 + i] ^ word[24 * (R - 1) + 8 + i];
			word[24 * R + 12 + i] = word[24 * R + 8 + i] ^ word[24 * (R - 1) + 12 + i];
			word[24 * R + 16 + i] = word[24 * R + 12 + i] ^ word[24 * (R - 1) + 16 + i];
			word[24 * R + 20 + i] = word[24 * R + 16 + i] ^ word[24 * (R - 1) + 20 + i];
		}
	}
	//word 마지막 4개. 48~51
	RotWord(47);
	SubWord();
	RCons(47, RC_192[7]);
	for (int i = 0; i < 4; i++)
	{
		word[48 * 4 + i] = wtemp[i] ^ word[42 * 4 + i];
		word[49 * 4 + i] = word[48 * 4 + i] ^ word[43 * 4 + i];
		word[50 * 4 + i] = word[49 * 4 + i] ^ word[44 * 4 + i];
		word[51 * 4 + i] = word[50 * 4 + i] ^ word[45 * 4 + i];
	}
	for (int r = 0; r <= 12; r++)
	{
		RoundKey(r);
	}
}
void KeyExpansion_256()
{
	//word 0~7
	for (int i = 0; i < 32; i++)
		word[i] = Keytemp[i];

	//word 8개씩 6번 word8~55
	for (int R = 1; R < 7; R++)
	{
		RotWord(8 * R - 1);
		SubWord();
		RCons(8 * R - 1, RC_256[R - 1]);
		for (int i = 0; i < 4; i++)
		{
			word[32 * R + i] = word[32 * (R - 1) + i] ^ wtemp[i];
			word[32 * R + 4 + i] = word[32 * (R - 1) + 4 + i] ^ word[32 * R + i];
			word[32 * R + 8 + i] = word[32 * (R - 1) + 8 + i] ^ word[32 * R + 4 + i];
			word[32 * R + 12 + i] = word[32 * (R - 1) + 12 + i] ^ word[32 * R + 8 + i];
		}
		for (int i = 0; i < 4; i++)
			wtemp[i] = word[32 * R + 12 + i];
		SubWord();
		for (int i = 0; i < 4; i++)
		{
			word[32 * R + 16 + i] = word[32 * (R - 1) + 16 + i] ^ wtemp[i];
			word[32 * R + 20 + i] = word[32 * (R - 1) + 20 + i] ^ word[32 * R + 16 + i];
			word[32 * R + 24 + i] = word[32 * (R - 1) + 24 + i] ^ word[32 * R + 20 + i];
			word[32 * R + 28 + i] = word[32 * (R - 1) + 28 + i] ^ word[32 * R + 24 + i];
		}
	}

	//word 56~59
	RotWord(55);
	SubWord();
	RCons(55, RC_256[6]);
	for (int i = 0; i < 4; i++)
	{
		word[56 * 4 + i] = wtemp[i] ^ word[48 * 4 + i];
		word[57 * 4 + i] = word[56 * 4 + i] ^ word[49 * 4 + i];
		word[58 * 4 + i] = word[57 * 4 + i] ^ word[50 * 4 + i];
		word[59 * 4 + i] = word[58 * 4 + i] ^ word[51 * 4 + i];
	}

	for (int r = 0; r <= 14; r++)
	{
		RoundKey(r);
	}
}

//라운드 돌면서 실행할 과정 함수
void SubBytes() //상태 A를 S-Box에 따라 치환을 한다.
{
	for (int s = 0; s < 16; s++)
	{
		uint8_t temp = Temp[s];
		Temp[s] = SBox[temp];
	}
}
void ShiftRows()
{
	uint8_t temp;
	//1행 Shift 없음
	//2행 Shift_L1
	temp = Temp[4];
	Temp[4] = Temp[5];
	Temp[5] = Temp[6];
	Temp[6] = Temp[7];
	Temp[7] = temp;
	//3행 Shift_L2
	temp = Temp[8];
	Temp[8] = Temp[10];
	Temp[10] = temp;
	temp = Temp[9];
	Temp[9] = Temp[11];
	Temp[11] = temp;
	//4행 Shift_L3
	temp = Temp[15];
	Temp[15] = Temp[14];
	Temp[14] = Temp[13];
	Temp[13] = Temp[12];
	Temp[12] = temp;
}
void MixColumns()
{
	AES_STATE_t A = { 0x00, };
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		for (int j = 0; j < 4; j++)
			A[i] = A[i] ^ Mul(Mix[4 * a + j], Temp[4 * j + b]);
	}
	//Temp<=A
	for (int i = 0; i < 16; i++)
	{
		Temp[i] = A[i];
	}
}
void AddRoundKey(int round)
{
	for (int i = 0; i < 16; i++)
	{
		Temp[i] = Temp[i] ^ Round[16 * round + i];
	}
}

//라운드 역으로 실행할 과정 함수
void Inv_ShiftRows()
{
	uint8_t temp;
	//1행 Shift 없음
	//2행 Shift_R1
	temp = Temp[7];
	Temp[7] = Temp[6];
	Temp[6] = Temp[5];
	Temp[5] = Temp[4];
	Temp[4] = temp;
	//3행 Shift_R2
	temp = Temp[8];
	Temp[8] = Temp[10];
	Temp[10] = temp;
	temp = Temp[9];
	Temp[9] = Temp[11];
	Temp[11] = temp;
	//4행 Shift_R3
	temp = Temp[12];
	Temp[12] = Temp[13];
	Temp[13] = Temp[14];
	Temp[14] = Temp[15];
	Temp[15] = temp;
}
void Inv_MixColumns()
{
	AES_STATE_t A = { 0x00, };
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		for (int j = 0; j < 4; j++)
			A[i] = A[i] ^ Mul(Inv_Mix[4 * a + j], Temp[4 * j + b]);
	}
	//Temp<=A
	for (int i = 0; i < 16; i++)
	{
		Temp[i] = A[i];
	}
}
void Inv_SubBytes()
{
	for (int s = 0; s < 16; s++)
	{
		uint8_t temp = Temp[s];
		Temp[s] = Inv_SBox[temp];
	}
}


void AES128_enc(AES_STATE_t C, AES_STATE_t P, AES128_KEY_t K128)
{
	//Temp에 P 대입, Keytemp에 K128 대입
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		Temp[4 * b + a] = P[i];
		Keytemp[i] = K128[i];
	}
	//라운드키 생성
	KeyExpansion_128();

	//Round 0
	AddRoundKey(0);
	//Round 1~9
	for (int round = 1; round < 10; round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}
	//Round 10
	SubBytes();
	ShiftRows();
	AddRoundKey(10);
	//C에 Temp 대입
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		C[4 * b + a] = Temp[i];
	}
}


void AES128_dec(AES_STATE_t P, AES_STATE_t C, AES128_KEY_t K128)
{
	//Temp에 C 대입, Keytemp에 K128 대입
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		Temp[4 * b + a] = C[i];
		Keytemp[i] = K128[i];
	}
	//S Box 역 만들고, 라운드키 생성
	Make_Inv_SBox();
	KeyExpansion_128();

	//Round 10
	AddRoundKey(10);
	//Round 9~1
	for (int round = 9; round > 0; round--)
	{
		Inv_ShiftRows();
		Inv_SubBytes();
		AddRoundKey(round);
		Inv_MixColumns();
	}
	//Round 0
	Inv_ShiftRows();
	Inv_SubBytes();
	AddRoundKey(0);

	//Temp를 P에 옮겨담는다.
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		P[4 * b + a] = Temp[i];
	}
}


void AES192_enc(AES_STATE_t C, AES_STATE_t P, AES192_KEY_t K192)
{
	//Temp에 P 담고, Keytemp에 K192 담기
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		Temp[4 * b + a] = P[i];
	}
	for (int i = 0; i < 24; i++)
		Keytemp[i] = K192[i];
	//라운드키 생성
	KeyExpansion_192();

	//Round 0
	AddRoundKey(0);
	//Round 1~11
	for (int round = 1; round < 12; round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}
	//Round 12
	SubBytes();
	ShiftRows();
	AddRoundKey(12);
	//Temp를 C에 저장
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		C[4 * b + a] = Temp[i];
	}
}


void AES192_dec(AES_STATE_t P, AES_STATE_t C, AES192_KEY_t K192)
{
	//Temp에 C 담고, Keytemp에 K192 담기
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		Temp[4 * b + a] = C[i];
	}
	for (int i = 0; i < 24; i++)
		Keytemp[i] = K192[i];
	//라운드키 생성, S Box 역 만들기
	Make_Inv_SBox();
	KeyExpansion_192();

	//Round 12
	AddRoundKey(12);
	//Round 11~1
	for (int round = 11; round > 0; round--)
	{
		Inv_ShiftRows();
		Inv_SubBytes();
		AddRoundKey(round);
		Inv_MixColumns();
	}
	//Round 0
	Inv_ShiftRows();
	Inv_SubBytes();
	AddRoundKey(0);

	//Temp를 P에 옮겨담는다.
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		P[4 * b + a] = Temp[i];
	}
}


void AES256_enc(AES_STATE_t C, AES_STATE_t P, AES256_KEY_t K256)
{
	//Temp에 P 담고, Keytemp에 K256 담기
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		Temp[4 * b + a] = P[i];
	}
	for (int i = 0; i < 32; i++)
		Keytemp[i] = K256[i];
	//라운드키 생성
	KeyExpansion_256();

	//Round 0
	AddRoundKey(0);
	//Round 1~13
	for (int round = 1; round < 14; round++)
	{
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(round);
	}
	//Round 14
	SubBytes();
	ShiftRows();
	AddRoundKey(14);
	//Temp를 C에 저장
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		C[4 * b + a] = Temp[i];
	}
}


void AES256_dec(AES_STATE_t P, AES_STATE_t C, AES256_KEY_t K256)
{
	//Temp에 C 담고, Keytemp에 K256 담기
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		Temp[4 * b + a] = C[i];
	}
	for (int i = 0; i < 24; i++)
		Keytemp[i] = K256[i];
	//라운드키 생성, S Box 역 만들기
	Make_Inv_SBox();
	KeyExpansion_256();

	//Round 14
	AddRoundKey(14);
	//Round 13~1
	for (int round = 13; round > 0; round--)
	{
		Inv_ShiftRows();
		Inv_SubBytes();
		AddRoundKey(round);
		Inv_MixColumns();
	}
	//Round 0
	Inv_ShiftRows();
	Inv_SubBytes();
	AddRoundKey(0);

	//Temp를 P에 옮겨담는다.
	for (int i = 0; i < 16; i++)
	{
		int a = i / 4; int b = i % 4;
		P[4 * b + a] = Temp[i];
	}
}
