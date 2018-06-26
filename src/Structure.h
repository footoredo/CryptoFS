//relative path required!!!

#ifndef CRYPTOFS_STRUCTURE_H
#define CRYPTOFS_STRUCTURE_H

#include <string>
#include <map>
#include <fstream>
#include <sys/types.h>  
#include <sys/stat.h>  
#include <unistd.h>
#include <sys/statfs.h>
#include "Crypto.h"

using std::string;
using std::map;
using std::cout;
using std::endl;
using std::cerr;
using std::ofstream;
using std::ifstream;
using std::to_string;
using Crypto::Crypto;

class Structure {
public:
	
	struct State {
		bool exist, isfolder;
		off_t st_size;
		string real_name;
		string salt;
		
		State() {};
		
		State(bool _exist, bool _isfolder, off_t _st_size, string _real_name, string _salt):
			exist(_exist), isfolder(_isfolder), st_size(_st_size), real_name(_real_name), salt(_salt) {};
		
	}

	Structure();

	~Structure();
	
	//absolute path required!: /asdf/da/er...   
	
	void load(string filename, Crypto::Crypto &crypto);
	
	void save(string filename, Crypto::Crypto &crypto);
	
	bool add_file(string path, off_t size, bool isfolder, Crypto::Crypto &crypto);
	
	bool del_file(string path);
	
	bool modify_size(string path, off_t size);
	
	State get_state(string filename);
	
	pair<bool, vector<State> > get_state_list(string path);
	
	void print(string filename);

private:

	struct Node {
		map<string, Node *> children;
		off_t real_size = 0;
		bool isfolder;
		string hashsum;
		string salt;
		string edge;
	};

	Node *root;
	byte *info;
	static const int MAXN = 1000;
	
	inline void normalize_path(string &path);

	void delete_node(Node *u);
	
	void load_node(byte *&info, Node *u); 

	void save_node(string &info, Node *u); 

	bool add_file_with_stat(string path, string hashsum, off_t size, bool isfolder, const string &salt);

	bool dfs_add(Node *u, const string &hash, string &path, off_t size, bool isfolder, const string &salt);
	
	inline bool dfs_del(Node *u, string path);
	
	inline pair<bool, vector<Node *> > dfs_get_list(Node *u, string path);

	inline void dfs_print(ofstream &fout, Node *u, string str_edge, int depth);
};


#endif 
