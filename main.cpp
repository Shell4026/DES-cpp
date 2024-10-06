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
	
	std::cout << "평문 입력: ";
	std::cin.getline((char*)plainText, 128);
	std::cout << "비밀키 입력: ";
	std::cin.getline((char*)key, 8);

	int msgLen = strlen((const char*)plainText);
	// 블록에 담고 남는 메시지가 있는 경우 블록을 하나 더 추가한다.
	int blockCnt = (msgLen % DES::BLOCK_SIZE) ? (msgLen / DES::BLOCK_SIZE + 1) : (msgLen / DES::BLOCK_SIZE);

	// 암호화
	for (int i = 0; i < blockCnt; ++i)
		des.Encrypt(&plainText[i * DES::BLOCK_SIZE], &cypherText[i * DES::BLOCK_SIZE], key);
	std::cout << "암호문: ";
	for (int i = 0; i < blockCnt * DES::BLOCK_SIZE; ++i)
		std::cout << std::hex << (unsigned int)cypherText[i];
	std::cout << '\n';

	// 복호화
	for (int i = 0; i < blockCnt; ++i)
		des.Decrypt(&cypherText[i * DES::BLOCK_SIZE], &decryptionTest[i * DES::BLOCK_SIZE], key);
	std::cout << "복호문: ";
	for (int i = 0; i < blockCnt * DES::BLOCK_SIZE; ++i)
		std::cout << decryptionTest[i];
	std::cout << '\n';
	return 0;
}