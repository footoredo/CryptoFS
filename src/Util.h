#ifndef CRYPTOFS_UTIL_H
#define CRYPTOFS_UTIL_H

#include <fstream>
#include <cryptopp/cryptlib.h>
#include <sys/types.h>
#include <sys/stat.h>

namespace Util {
    size_t readBinary (const char *filename, byte *content, int maxLen) {
        auto file = std::fstream (filename, std::ios::in | std::ios::binary);
        if (file.fail ()) return 0;
        file.read ((char *)content, maxLen);
        size_t length = file.tellg();
        // std::cout << length << std::endl;
        file.close ();
        return length;
    }

    void writeBinary (const char *filename, const byte *content, int len) {
        auto file = std::fstream (filename, std::ios::out | std::ios::binary);
        file.write ((char *)content, len);
        file.close ();
    }

    bool readText (const char *filename, char *content, int maxLen) {
        auto file = std::fstream (filename, std::ios::in);
        if (file.fail ()) return false;
        file.read (content, maxLen);
        file.close ();
        return true;
    }

    void writeText (const char *filename, const char *content, int len) {
        auto file = std::fstream (filename, std::ios::out);
        file.write (content, len);
        file.close ();
    }

    std::string combinePath(std::string path1, std::string path2) {
        if (path1.back() == '/')
            path1.pop_back();
        if (path2.front() == '/') return path1 + path2;
        else return path1 + "/" + path2;
    }

    void mkdir (std::string path) {
        ::mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    }
}

#endif
