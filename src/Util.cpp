#include <fstream>
#include <cryptopp/cryptlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "Util.h"

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

    Exception::Exception(const std::string &_msg): msg(_msg) {}

    void writeBinary (const char *filename, const byte *content, int len) {
        auto file = std::fstream (filename, std::ios::out | std::ios::binary);
		if(!file.is_open())
			throw Exception(std::string(filename) + " not open");
        file.write ((char *)content, len);
		if(len == 0) 
			throw Exception(std::string(filename) + " output len = 0");
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

}
