
#include "DES.h"

void DES::ByteToWord(Byte* in, u32* left, u32* right)
{
	*left = 0;
	*right = 0;
	for (int i = 0; i < 4; ++i)
	{
		*left = (*left << 8) | in[i];
		*right = (*right << 8) | in[i + 4];
	}
}

void DES::WordToByte(u32 l, u32 r, Byte* out)
{
	u32 mask = 0xFF'00'00'00;
	for (int i = 0; i < 8; ++i)
	{
		if (i < 4)
			out[i] = (l & (mask >> i * 8)) >> (24 - (i * 8));
		else
			out[i] = (r & (mask >> (i - 4) * 8)) >> (56 - (i * 8));
	}
}

void DES::Encrypt(Byte* plainText, Byte* result, Byte* key)
{
	Byte data[BLOCK_SIZE] = { 0, }; // 64bit
	Byte roundKey[DES_ROUND][6] = { 0, };
	u32 left = 0, right = 0;

	KeyExpansion(key, roundKey);

	InitPermutation(plainText, data); // 초기 치환
	ByteToWord(data, &left, &right); // 8바이트를 2개의 4바이트로 나눔

	for (int i = 0; i < DES_ROUND; ++i)
	{
		Byte exRight[6]{ 0, };
		Expand(right, exRight);
		for (int j = 0; j < 6; ++j)
			exRight[j] ^= roundKey[i][j];
		left ^= Permutation(SBox(exRight));

		if (i != DES_ROUND - 1)
		{
			left ^= right;
			right ^= left;
			left ^= right;
		}
	}
	WordToByte(left, right, data); // 2개의 4바이트를 하나로 합침
	FinalPermutation(data, result); // 최종 치환
}

void DES::Decrypt(Byte* cypherText, Byte* result, Byte* key)
{
	Byte data[BLOCK_SIZE] = { 0, }; // 64bit
	Byte roundKey[DES_ROUND][6] = { 0, };
	u32 left = 0, right = 0;

	KeyExpansion(key, roundKey);

	InitPermutation(cypherText, data); // 초기 치환
	ByteToWord(data, &left, &right); // 8바이트를 2개의 4바이트로 나눔

	for (int i = 0; i < DES_ROUND; ++i)
	{
		Byte exRight[6]{ 0, };
		Expand(right, exRight);
		for (int j = 0; j < 6; ++j)
			exRight[j] ^= roundKey[DES_ROUND - i - 1][j];
		left ^= Permutation(SBox(exRight));

		if (i != DES_ROUND - 1)
		{
			left ^= right;
			right ^= left;
			left ^= right;
		}
	}
	WordToByte(left, right, data); // 2개의 4바이트를 하나로 합침
	FinalPermutation(data, result); // 최종 치환
}

void DES::InitPermutation(Byte* in, Byte* out)
{
	// in 64bit = in[8] = out[8]
	Byte mask = 0b1000'0000; // 0x80

	for (int i = 0; i < 64; ++i)
	{
		int index = (ip[i] - 1) / 8; // 해당 테이블 값에 해당하는 in의 인덱스 번호
		int bit = (ip[i] - 1) % 8; // 해당 테이블 값에 해당하는 in의 비트 순서
		if (in[index] & (mask >> bit)) // in의 해당 인덱스의 비트가 1이라면
			out[i / 8] |= mask >> (i % 8); // out의 i % 8번째 비트에 1을 기록한다.
	}
}

void DES::FinalPermutation(Byte* in, Byte* out)
{
	Byte mask = 0b1000'0000;

	for (int i = 0; i < 64; ++i)
	{
		int index = (ipInv[i] - 1) / 8;
		int bit = (ipInv[i] - 1) % 8;
		if (in[index] & (mask >> bit))
			out[i / 8] |= mask >> (i % 8);
	}
}

void DES::Expand(u32 right, Byte* out)
{
	u32 mask = 0x80'00'00'00; // 제일 왼쪽 비트가 1인 32비트 마스크
	for (int i = 0; i < 48; ++i)
	{
		if (right & (mask >> (expansion[i] - 1)))
			out[i / 8] |= (Byte)(0x80 >> (i % 8));
	}
}

auto DES::Permutation(u32 in) -> u32
{
	u32 mask = 0x80'00'00'00; // 제일 왼쪽 비트가 1인 32비트 마스크
	u32 out = 0;
	for (int i = 0; i < 32; ++i)
	{
		if (in & (mask >> (permutation[i] - 1)))
			out |= mask >> i;
	}
	return out;
}

auto DES::SBox(Byte* in) -> u32
{
	// in 6byte out 4byte
	u32 mask = 0b1000'0000;
	u32 temp = 0;
	u32 result = 0;
	u32 shift = 28;
	for (int i = 0; i < 48; ++i)
	{
		if (in[i / 8] & (Byte)(mask >> (i % 8))) 
			temp |= 0b10'0000 >> (i % 6); // temp에 6비트씩 나눈다.

		if ((i + 1) % 6 == 0)
		{
			int row = ((temp & 0b100000) >> 4) + (temp & 0b000001);
			int col = (temp & 0b011110) >> 1;
			int byte = sbox[i / 6][col * 16 + row]; // 6비트를 4비트로 축소
			result += byte << shift; // 4비트씩 8부분
			shift -= 4;
			temp = 0;
		}
	}
	return result;
}

void DES::KeyExpansion(Byte* key, Byte expKey[16][6])
{
	Byte key56[7]{ 0, };
	PC1(key, key56);

	u32 lkey = 0, rkey = 0;
	MakeBit28(&lkey, &rkey, key56);

	for (int i = 0; i < DES_ROUND; ++i)
	{
		lkey = CirShift(lkey, i);
		rkey = CirShift(rkey, i);

		PC2(lkey, rkey, expKey[i]);
	}
}

void DES::PC1(Byte* in, Byte* out)
{
	Byte mask = 0x80;
	for (int i = 0; i < 56; ++i)
	{
		int index = (pc1[i] - 1) / 8;
		int bit = (pc1[i] - 1) % 8;

		if (in[index] & (Byte)(mask >> bit))
			out[i / 8] |= (Byte)(mask >> (i % 8));
	}
}

void DES::PC2(u32 lkey, u32 rkey, Byte* out)
{
	u32 mask = 0x08'00'00'00;

	for (int i = 0; i < 48; ++i)
	{
		if (pc2[i] - 1 < 28)
		{
			if (lkey & (mask >> (pc2[i] - 1)))
				out[i / 8] |= 0x80 >> (i % 8);
		}
		else
		{
			if (rkey & (mask >> (pc2[i] - 1 - 28)))
				out[i / 8] |= 0x80 >> (i % 8);
		}
	}
}

void DES::MakeBit28(u32* lkey, u32* rkey, Byte* data)
{
	Byte mask = 0x80;
	for (int i = 0; i < 56; ++i)
	{
		if (i < 28)
		{
			if (data[i / 8] & (mask >> (i % 8)))
				*lkey |= 0x08'00'00'00 >> i; // 28bit
		}
		else
		{
			if (data[i / 8] & (mask >> (i % 8)))
				*rkey |= 0x08'00'00'00 >> (i - 28); // 28bit
		}
	}
}

auto DES::CirShift(u32 key, int r) -> u32
{
	u32 result = 0;
	u32 mask = 0x0F'FF'FF'FF; // 28bit
	const int shift[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };
	if (shift[r] == 1) // 한 번 회전
	{
		result = ((key << 1) + (key >> 27)) & mask;
	}
	else // 두 번 회전
	{
		result = ((key << 2) + (key >> 26)) & mask;
	}
	return result;
}
