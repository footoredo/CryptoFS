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
	c1.generateKeys();
	system("rm -r .keys");
	system("mkdir .keys");
	try {
		cerr << "\n ------- add file check -------- " << endl;
		for (int i = 0; i < 3; ++i) {
			string ni = to_string(i % 10);
			file.add_file("/f" + ni, 0, true, c1);
			for (int j = 0; j < 3; ++j) {
				string nj = "[" + to_string(j % 10) + "]";
				file.add_file("/f" + ni + "/" + nj, i * 100 + j, false, c1);
			}
		}
		/*file.add_file("/satomi", 10000, false, c1);
		cerr << " ------- add file check finished-------- " << endl;
		
		cerr << "\n ------- del file check -------- " << endl;
		cerr << file.del_file("/0/1") << endl;
		cerr << file.del_file("/0/123") << endl;
		cerr << " ------- del file check finished -------- " << endl;
		
		cerr << " ------- modify size check -------- " << endl;
		cerr << file.modify_size("/gakki", 10007) << endl;
		cerr << file.modify_size("/2/2", 23333) << endl;
		//cerr << file.get_state("/2/2").st_size << endl;
		cerr << " ------- modify size check ok-------- " << endl;
		*/
		cerr << " ------- modify state list check -------- " << endl;
		cerr << "ok = " << file.get_state_list("/f2").first << endl;
		vector<Structure::State> state_list = file.get_state_list("/f2").second;
		for (auto s: state_list) {
			cerr << s.exist << " " << s.isfolder << " " << s.st_size << " " << s.real_name << " " << s.fake_name << " " << s.salt << endl;
		}		
		cerr << " ------- modify state list check finished -------- " << endl;
		
		file.print("print_tree");
		//system("cat print_tree");
		system("rm print_tree");
		
		c1;
		c1.saveKeys(".keys");
		c2;
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
