#include "DES.h"

#include <iostream>
#include <string>

int main()
{
	DES des{};

	Byte plainText[128]{ 0, };
	Byte cypherText[128]{ 0, };
	Byte decryptionTest[128]{ 0, };
	Byte key[8] = { 0, };
	
	std::cout << "�� �Է�: ";
	std::cin.getline((char*)plainText, 128);
	std::cout << "���Ű �Է�: ";
	std::cin.getline((char*)key, 8);

	int msgLen = strlen((const char*)plainText);
	// ��Ͽ� ��� ���� �޽����� �ִ� ��� ����� �ϳ� �� �߰��Ѵ�.
	int blockCnt = (msgLen % DES::BLOCK_SIZE) ? (msgLen / DES::BLOCK_SIZE + 1) : (msgLen / DES::BLOCK_SIZE);

	// ��ȣȭ
	for (int i = 0; i < blockCnt; ++i)
		des.Encrypt(&plainText[i * DES::BLOCK_SIZE], &cypherText[i * DES::BLOCK_SIZE], key);
	std::cout << "��ȣ��: ";
	for (int i = 0; i < blockCnt * DES::BLOCK_SIZE; ++i)
		std::cout << std::hex << (unsigned int)cypherText[i];
	std::cout << '\n';

	// ��ȣȭ
	for (int i = 0; i < blockCnt; ++i)
		des.Decrypt(&cypherText[i * DES::BLOCK_SIZE], &decryptionTest[i * DES::BLOCK_SIZE], key);
	std::cout << "��ȣ��: ";
	for (int i = 0; i < blockCnt * DES::BLOCK_SIZE; ++i)
		std::cout << decryptionTest[i];
	std::cout << '\n';
	return 0;
}