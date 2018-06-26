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

int main () {
	Structure file;
	struct stat t_stat;
	try {
		for (int i = 0; i < 3; ++i) {
			string ni = to_string(i % 10);
			file.add_file(ni, "id" + ni, 1, "salt" + ni);
			for (int j = 0; j < 3; ++j) {
				string nj = to_string(j % 10);
				file.add_file(ni + "/" + nj, "id" + nj, 0, "salt" + nj);
			}
		}
		file.add_file("a", "ida", 0, "salta");//filename, id, isfile, stat, salt
		cout << file.del_file("0/1") << endl;
		
		Crypto::Crypto c1;
		c1.generateKeys();
		c1.saveKeys(".keys");
		Crypto::Crypto c2;
		c2.loadKeys(".keys");
		file.save("structure.sec", c1);
		file.print("origin");
		
		Structure newf;		
		newf.load("structure.sec", c2);
		newf.print("copy");
		
		system("diff copy origin");
		system("cat origin");
		system("rm origin");
		system("rm copy");
		system("rm -r .keys");
	} catch (Util::Exception &exc) {
		cout << "exception: " << exc.msg << endl;
	}
}
