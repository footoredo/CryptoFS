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

//#include "../Util.h"
#include "../Crypto.h"
#include "../Structure.h"

using namespace std;
using namespace CryptoPP;

Crypto::Crypto c1, c2;
int len = 100;

int main () {
	Structure file;
	Crypto::Crypto crypto;
	crypto.generateKeys();
	try {
		cerr << "\n ------- add file check -------- " << endl;
		for (int i = 0; i < 3; ++i) {
			string ni = to_string(i % 10);
			file.add_file("/" + ni, 0, true, crypto);
			for (int j = 0; j < 3; ++j) {
				string nj = to_string(j % 10);
				file.add_file("/" + ni + "/" + nj, i * 100 + j, false, crypto);
			}
		}
		file.add_file("/satomi", 10000, false, crypto);
		cerr << " ------- add file check finished-------- " << endl;
		
		cerr << "\n ------- del file check -------- " << endl;
		cout << file.del_file("/0/1") << endl;
		cout << file.del_file("/0/123") << endl;
		cerr << " ------- del file check finished -------- " << endl;
		
		cerr << " ------- modify size check -------- " << endl;
		cout << file.modify_size("/gakki", 10007) << endl;
		cout << file.modify_size("/2/2", 23333) << endl;
		file.print("print_tree");
		system("cat print_tree");
		system("rm cat print_tree");
		cerr << " ------- modify size check ok-------- " << endl;
		/*
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
		system("rm -r .keys");*/
	} catch (Util::Exception &exc) {
		cout << "exception: " << exc.msg << endl;
	}
}
