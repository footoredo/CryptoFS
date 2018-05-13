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
#include <sys/stat.h>

#include "../Util.h"
#include "../Crypto.h"
#include "../Structure.h"

using namespace std;
using namespace CryptoPP;

Crypto::Crypto c1, c2;
const byte *input = (byte *)"fuck123123123123123123123 u";
int len = 100;

inline void save() {
	c1.generateKeys();
	c1.saveKeys(".keys");
    c1.saveSec("tmp.sec", input, len);
    // std::cerr << len << std::endl;
}

inline void load() {
	c2.loadKeys(".keys");
    byte *recovered = new byte[len + 10];
    memset (recovered, 0x00, len + 1);
    
    assert (c2.loadSec("tmp.sec", recovered, len));
    // std::cerr << "123123" << std::endl;
    /* for (int i = 0; i < len; ++ i)
        std::cout << (char)(recovered[i]);*/
    std::cerr << (char *) recovered << std::endl;	
}



int main () {
cout << "saving..." << endl;
	save();
cout << "save ok\nloading..." << endl;
	load();
cout << "load ok" << endl;
return 0;
	Structure file;
	struct stat t_stat;
	try {
		/*for (int i = 0; i < 3; ++i) {
			string ni = to_string(i % 10);
			file.add_file(ni, "id" + ni, 0, t_stat, "salt" + ni);
//cerr << "father: " << i << endl;
			for (int j = 0; j < 3; ++j) {
				string nj = to_string(j % 10);
//cerr << "son: " << j << endl;
				file.add_file(ni + "/" + nj, "id" + nj, 1, t_stat, "salt" + nj);
//cerr << "son: " << j << " ok" << endl;				
			}
		}*/
		file.add_file("a", "ida", 0, t_stat, "salta");
		//file.print("filetree");
		file.save("structure.sec");
		file.print("origin");
		Structure newf;
		newf.load("structure.sec");
		newf.print("copy");
		//cout << file.add_file("a", "id1", 1, t_stat, "salt1") << endl;
	} catch (Util::Exception &exc) {
		cout << "exception: " << exc.msg << endl;
	}
}
