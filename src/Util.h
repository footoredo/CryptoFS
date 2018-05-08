#ifndef CRYPTOFS_UTIL_H
#define CRYPTOFS_UTIL_H

#include <fstream>
#include <cryptopp/cryptlib.h>

namespace Util {
    void readBinary (const char *filename, byte *content, int maxLen) {
        auto file = std::fstream (filename, std::ios::in | std::ios::binary);
        file.read ((char *)content, maxLen);
        file.close ();
    }
    void writeBinary (const byte *content, int len, const char *filename) {
        auto file = std::fstream (filename, std::ios::out | std::ios::binary);
        file.write ((char *)content, len);
        file.close ();
    }
}

#endif
