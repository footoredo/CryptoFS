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

    int len = strlen((char *)input);
    byte *output = new byte[len + 1 + 16];
    crypto.encrypt(input, len, output);
    byte *recovered = new byte[len + 1 + 16];
    memset(recovered, 0, len + 1);
    crypto.decrypt(output, len, recovered);

    // std::cout << (char *)recovered << std::endl;
    assert (strcmp((char *)input, (char *)recovered) == 0);                     // Testcase for symmetric encryption

    std::string hexHash = crypto.hashsum(input, len);
    Util::writeBinary("input.bin", input, len);

// std::cout << exec ("sha256sum -b input.bin | awk '{print $1;}' | head -n1") << std::endl;
    assert (hexHash == exec ("sha256sum -b input.bin | head -n1 | awk '{printf $1;}'"));    // Testcase for hash

    byte *signature = new byte [384];
    int sigLen = crypto.sign(input, len, signature);
    // signature[0] ^= 0x10;
    assert (crypto.verify(input, len, signature, sigLen));
    delete [] signature;

    // crypto.displayKeys();
    crypto.saveKeys(".keys");
    crypto.loadKeys(".keys");
    // crypto.displayKeys();

    memset(recovered, 0, len + 1);
    crypto.decrypt(output, len, recovered);

    // std::cout << (char *) recovered << std::endl;
    assert (strcmp((char *)input, (char *)recovered) == 0);                     // Testcase for symmetric encryption


    return 0;
}
