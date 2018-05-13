#include <fstream>
#include <vector>
#include <string.h>
#include <iostream>
#include <cassert>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <cstdio>

#include "../Util.h"
#include "../Crypto.h"

using namespace std;
using namespace CryptoPP;


std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}

int main () {
    Crypto::Crypto crypto;
    crypto.generateKeys();

    const byte *input = (byte *)"fuck123123123123123123123 u";

    std::cout << "  -- Test for basic symmetric encryption/decryption --" << std::endl;

    int len = strlen((char *)input);
    // std::cout << len << std::endl;
    byte *output = new byte[len + 1 + 16];
    crypto.encrypt(input, len, output);
    byte *recovered = new byte[len + 1 + 16];
    memset(recovered, 0, len + 1);
    crypto.decrypt(output, len, recovered);

    // std::cout << (char *)recovered << std::endl;
    assert (strcmp((char *)input, (char *)recovered) == 0);                     // Testcase for symmetric encryption
    std::cout << "  -- Test passed! --" << std::endl << std::endl;

    std::cout << "  -- Test for hashsum --" << std::endl;

    std::string hexHash = crypto.hashsum(input, len);
    Util::writeBinary("input.bin", input, len);

// std::cout << exec ("sha256sum -b input.bin | awk '{print $1;}' | head -n1") << std::endl;
    assert (hexHash == exec ("sha256sum -b input.bin | head -n1 | awk '{printf $1;}'"));    // Testcase for hash
    std::cout << "  -- Test passed! --" << std::endl << std::endl;

    std::cout << "  -- Test for digital signature --" << std::endl;

    byte *signature = new byte [384];
    int sigLen = crypto.sign(input, len, signature);
    // signature[0] ^= 0x10;
    assert (crypto.verify(input, len, signature, sigLen));
    std::cout << "  -- Test passed! --" << std::endl << std::endl;

    std::cout << "  -- Test for .keys files --" << std::endl;

    // crypto.displayKeys();
    crypto.saveKeys(".keys");
cout << "save ok" << endl;
    crypto.loadKeys(".keys");
    return 0;
    // crypto.displayKeys();

    memset(recovered, 0, len + 1);
    crypto.decrypt(output, len, recovered);

    // std::cout << (char *) recovered << std::endl;
    assert (strcmp((char *)input, (char *)recovered) == 0);                     // Testcase for symmetric encryption
    std::cout << "  -- Test passed! --" << std::endl << std::endl;

    std::cout << "  -- Test for .keys files --" << std::endl;
    crypto.saveSec("tmp.sec", input, len);
    memset (recovered, 0x00, len + 1);
    // std::cerr << len << std::endl;
    assert (crypto.loadSec("tmp.sec", recovered, len));
    // std::cerr << "123123" << std::endl;
    /* for (int i = 0; i < len; ++ i)
        std::cout << (char)(recovered[i]);*/
    // std::cerr << (char *) recovered << std::endl;
    assert (strcmp ((char *) input, (char *)recovered) == 0);
    std::cout << "  -- Test passed! --" << std::endl << std::endl;

    // delete [] input;
    delete [] output;
    delete [] recovered;
    delete [] signature;

    return 0;
}
