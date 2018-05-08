#include "../Crypto.h"
#include <fstream>
#include <vector>
#include <string.h>
#include <iostream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>

using namespace std;
using namespace CryptoPP;

int main () {
    // ifstream testFile("test.dat", ios::binary);
    // vector<char> buffer ((istreambuf_iterator<char>(testFile)), (istreambuf_iterator<char>()));
    const byte input[1024] = "1234";
    byte *output = new byte[1024];
    byte key[ AES::DEFAULT_KEYLENGTH ];
    memset( key, 0x00, AES::DEFAULT_KEYLENGTH );
    Crypto::AESEncrypt(input, 6, key, AES::DEFAULT_KEYLENGTH, output);

    byte *recover = new byte[1024];
    Crypto::AESDecrypt(output, 5, key, AES::DEFAULT_KEYLENGTH, recover);
    std::cout << (char *)(recover) << std::endl;
    return 0;
}
