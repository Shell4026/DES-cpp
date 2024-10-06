
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

	InitPermutation(plainText, data); // �ʱ� ġȯ
	ByteToWord(data, &left, &right); // 8����Ʈ�� 2���� 4����Ʈ�� ����

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
	WordToByte(left, right, data); // 2���� 4����Ʈ�� �ϳ��� ��ħ
	FinalPermutation(data, result); // ���� ġȯ
}

void DES::Decrypt(Byte* cypherText, Byte* result, Byte* key)
{
	Byte data[BLOCK_SIZE] = { 0, }; // 64bit
	Byte roundKey[DES_ROUND][6] = { 0, };
	u32 left = 0, right = 0;

	KeyExpansion(key, roundKey);

	InitPermutation(cypherText, data); // �ʱ� ġȯ
	ByteToWord(data, &left, &right); // 8����Ʈ�� 2���� 4����Ʈ�� ����

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
	WordToByte(left, right, data); // 2���� 4����Ʈ�� �ϳ��� ��ħ
	FinalPermutation(data, result); // ���� ġȯ
}

void DES::InitPermutation(Byte* in, Byte* out)
{
	// in 64bit = in[8] = out[8]
	Byte mask = 0b1000'0000; // 0x80

	for (int i = 0; i < 64; ++i)
	{
		int index = (ip[i] - 1) / 8; // �ش� ���̺� ���� �ش��ϴ� in�� �ε��� ��ȣ
		int bit = (ip[i] - 1) % 8; // �ش� ���̺� ���� �ش��ϴ� in�� ��Ʈ ����
		if (in[index] & (mask >> bit)) // in�� �ش� �ε����� ��Ʈ�� 1�̶��
			out[i / 8] |= mask >> (i % 8); // out�� i % 8��° ��Ʈ�� 1�� ����Ѵ�.
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
	u32 mask = 0x80'00'00'00; // ���� ���� ��Ʈ�� 1�� 32��Ʈ ����ũ
	for (int i = 0; i < 48; ++i)
	{
		if (right & (mask >> (expansion[i] - 1)))
			out[i / 8] |= (Byte)(0x80 >> (i % 8));
	}
}

auto DES::Permutation(u32 in) -> u32
{
	u32 mask = 0x80'00'00'00; // ���� ���� ��Ʈ�� 1�� 32��Ʈ ����ũ
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
			temp |= 0b10'0000 >> (i % 6); // temp�� 6��Ʈ�� ������.

		if ((i + 1) % 6 == 0)
		{
			int row = ((temp & 0b100000) >> 4) + (temp & 0b000001);
			int col = (temp & 0b011110) >> 1;
			int byte = sbox[i / 6][col * 16 + row]; // 6��Ʈ�� 4��Ʈ�� ���
			result += byte << shift; // 4��Ʈ�� 8�κ�
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
	if (shift[r] == 1) // �� �� ȸ��
	{
		result = ((key << 1) + (key >> 27)) & mask;
	}
	else // �� �� ȸ��
	{
		result = ((key << 2) + (key >> 26)) & mask;
	}
	return result;
}
