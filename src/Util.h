#ifndef CRYPTOFS_UTIL_H
#define CRYPTOFS_UTIL_H

#include <fstream>
#include <cryptopp/cryptlib.h>
#include <sys/types.h>
#include <sys/stat.h>

namespace Util {
    size_t readBinary (const char *filename, byte *content, int maxLen);

    void writeBinary (const char *filename, const byte *content, int len);

    bool readText (const char *filename, char *content, int maxLen);

    void writeText (const char *filename, const char *content, int len);

    std::string combinePath(std::string path1, std::string path2);

    void mkdir (std::string path);
    
    class Exception {
    public:
    	std::string msg;
    	Exception(const std::string &_msg);
    };

    std::string exec(const char* cmd);

}

#endif
