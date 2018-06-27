#include <string>
#include <map>
#include <fstream>
#include <vector>
#include <sys/types.h>  
#include <sys/stat.h>  
#include <unistd.h>
#include <sys/statfs.h>
#include "Crypto.h"
#include "Structure.h"

using std::string;
using std::pair;
using std::map;
using std::cout;
using std::endl;
using std::cerr;
using std::ofstream;
using std::ifstream;
using std::to_string;
using std::vector;
using Crypto::Crypto;

namespace convert {

	inline bool file_letter(byte a) {
//		return isdigit(a)
//			   || a >= 'a' && a <= 'z'
//			   || a >= 'A' && a <= 'Z'
//			   || a == '-'
//			   || a == '_'
//			   || a == '.';
		return !isspace((int)a) && a != '/' && (int)a != 0;
	}

	inline int get_int(byte *&str) {
		int ret = 0;
		bool sign = true;
		for (; *str != '-' && !isdigit(*str); ++str);
		if (*str == '-') {
			sign = false;
			++str;
		}
		for (; isdigit(*str); ++str) {
			ret = ret * 10 + *str - '0';
		}
		return sign ? ret : -ret;
	}

	inline long long get_long(byte *&str) {
		long long ret = 0;
		bool sign = true;
		for (; *str != '-' && !isdigit(*str); ++str);
		if (*str == '-') {
			sign = false;
			++str;
		}
		for (; isdigit(*str); ++str) {
			ret = ret * 10 + *str - '0';
		}
		return sign ? ret : -ret;
	}

	inline string get_str(byte *&str) {
		for (; !file_letter(*str); ++str);
		string ret = "";
		for (; file_letter(*str); ++str) {
			ret = ret + (char)*str;
		}
		return ret;
	}

	inline bool get_bool(byte *&str) {
		for (; !isdigit(*str); ++str);
		int ret = *str - '0';
		++str;
		return (bool)ret;
	}

}

//name of file cannot contain [/ \]
	
Structure::Structure() {
	root = new Structure::Node();
	root -> hashsum = "root";
	root -> salt = "RootSalt";
	root -> edge = "root";
	root -> real_size = 0;
	root -> isfolder = true;
}

Structure::~Structure() {
	Structure::delete_node(root);
}
	
inline void Structure::normalize_path(string &path) {
	if (path.length() == 0) {
		throw Util::Exception("Empty path!");
	}
	if (path[0] != '/') {
		throw Util::Exception("Not an absolute path");
	}
	for (; path.size() && !convert::file_letter(path.back()); path.pop_back());
	if (path.length() == 0) {
		path = "/";
		return;
	}
	path = path.substr(1);
	if (path.back() != '/') {
		path.append(1, '/');
	}
}

void Structure::delete_node(Node *u) {
	for (auto v: u -> children) {
		Structure::delete_node(v.second);
	}
	delete u;
}
	
void Structure::load_node(byte *&info, Node *u) {
/*std::cerr << "\n now: " << info << std::endl;
if (*info == 0) {
	while (1) {
	
	}
}*/
	u -> real_size = convert::get_long(info);
	u -> isfolder = convert::get_bool(info);
	u -> hashsum = convert::get_str(info);
	u -> salt = convert::get_str(info);
	u -> edge = convert::get_str(info);
	int n_son = convert::get_int(info);
//std::cerr << "read " << u -> real_size << " " << u -> edge << " " << n_son << std::endl;
	string edge;
	for (; n_son; --n_son) {
		Node *v = new Node();
		edge = convert::get_str(info);
		u -> children[edge] = v;
		Structure::load_node(info, v);
	}
}

void Structure::save_node(string &info, Node *u) {
	info = info.append(to_string(u -> real_size) + " ");
	info = info.append(to_string(u -> isfolder) + " ");
	info = info.append(u -> hashsum + " "); 
	info = info.append(u -> salt + " "); 
	info = info.append(u -> edge + " "); 
	//print stat
	info = info.append(to_string(u -> children.size()) + " ");
	info = info.append("\n");
	for (auto v: u -> children) {
		info = info.append(v.first + " ");
		Structure::save_node(info, v.second);
	}
}

bool Structure::add_file_with_stat(string path, string hashsum, 
			off_t size, bool isfolder, const string &salt) {
	return Structure::dfs_add(root, hashsum, path, size, isfolder, salt);
}

bool Structure::dfs_add(Node *u, const string &hash, string &path, 
			off_t size, bool isfolder, const string &salt) {
	int pos = path.find('/');
	string now = path.substr(0, pos);
	path = path.substr(pos + 1);
	if (path.length() == 0) {
		if (u -> children.count(now)) {
			//throw Util::Exception("File or dir already existed: " + now);
			return false;
		}
		Node *v = new Node();
		v -> hashsum = hash;
		v -> isfolder = isfolder;
		v -> real_size = size;
		v -> salt = salt;
		v -> edge = now;
		u -> children[now] = v;
		return true;
	} else {
		map<string, Node *>::iterator it = u -> children.find(now);
		if (it == u -> children.end()) {
			//throw Util::Exception("No such direction: " + now);
			return false;
		} else {
			if (!(it -> second -> isfolder)) {
				//throw Util::Exception(now + " is not a direction");
				return false;
			}
			return Structure::dfs_add(it -> second, hash, path, size, isfolder, salt);
		}
	}
}
	
inline bool Structure::dfs_del(Node *u, string path) {
//std::cerr << "now path: " << path << std::endl;
	int pos = path.find('/');
	string now = path.substr(0, pos);
	path = path.substr(pos + 1);
	map<string, Node *>::iterator it = u -> children.find(now);
	if (path.length() == 0) {
		if (it == u -> children.end()) {
			//throw Util::Exception("target not found");
			return false;
		}
		if (it -> second -> children.size()) {
			//throw Util::Exception("target not empty");
			return false;
		} else {
			u -> children.erase(it);
			//std::cerr << "left size: " << u -> children.size() << std::endl;
			return true;
		}
	} else {
		if (it == u -> children.end()) {
			//throw Util::Exception("dir not found: " + now);
			return false;
		} else {
			return Structure::dfs_del(it -> second, path);
		}
	}
}
	
inline pair<bool, vector<Structure::Node *> > Structure::dfs_get_list(Structure::Node *u, string path) {
//std::cerr << "now dfs path: " << path << std::endl;
	bool flag = path == "/";
	int pos = path.find('/');
	string now = path.substr(0, pos);
	path = path.substr(pos + 1);
	map<string, Structure::Node *>::iterator it = u -> children.find(now);
	if (!flag && (it == u -> children.end() || !(it -> second -> isfolder))) {
		return make_pair(false, vector<Structure::Node *>());
	}
	if (path.length() == 0) {
//std::cerr << "ok" << std::endl;
		u = flag ? root : it -> second;
		vector<Structure::Node *> vec;
		for (auto v: u -> children) {
			vec.push_back(v.second);
		}
//std::cerr << "123" << std::endl;
		return make_pair(true, vec);
	} else {
		return Structure::dfs_get_list(it -> second, path);
	}
}

inline void Structure::dfs_print(ofstream &fout, Structure::Node *u, string str_edge, int depth) {
	string s;
	s.append(depth * 4, ' ');
	fout << s << "{";
	fout << "real_size: " << u -> real_size << ", ";
	fout << "isfolder: " << u -> isfolder << ", ";
	fout << "hashsum: " << u -> hashsum << ", ";
	fout << "salt: " << u -> salt << ", ";
	fout << "edge: " << u -> edge << "}" << std::endl;
	for (auto v: u -> children) {
		Structure::dfs_print(fout, v.second, v.first, depth + 1);
	}
}

void Structure::load(string filename, Crypto::Crypto &crypto) {
	info = new byte[MAXN + 100];
	memset (info, 0x00, MAXN + 10);
	crypto.loadSec(filename, crypto.getStructureSalt(), info, MAXN);
	byte * tmp = info;
	root = new Node();
	load_node(tmp, root);
	delete [] info;
}

void Structure::save(string filename, Crypto::Crypto &crypto) {
	string info;
	save_node(info, root);
	if (info.length() >= MAXN) {
		throw Util::Exception("file system too large!");
	}
	byte *buffer = new byte[MAXN + 10];
	for (int i = 0; i < (int)info.size(); ++i) {
		buffer[i] = info[i];
	}
	buffer[info.size()] = 0;
	string nowsalt = crypto.getStructureSalt();
	crypto.saveSec(filename, nowsalt, buffer, MAXN);
	delete []buffer;
}
bool Structure::add_file(string path, off_t size, bool isfolder, Crypto::Crypto &crypto) {
	Structure::normalize_path(path);
	string nowsalt = crypto.generateSalt();
	string nowhash = crypto.hashsum(path + ":" + nowsalt).substr(0, 11);
	return add_file_with_stat(path, nowhash, size, isfolder, nowsalt);
}

bool Structure::del_file(string path) {
	Structure::normalize_path(path);
	return dfs_del(root, path);
}

Structure::Node *Structure::get_target_node(string &path) {
	Structure::normalize_path(path);
	path.pop_back();
	string filename;
	for (; convert::file_letter(path.back()); path.pop_back()) {
		filename = path.back() + filename;
	}
//std::cerr << "split: [ " << path << ", " << filename << "]" << std::endl;
	pair<bool, vector<Structure::Node *> > ret = dfs_get_list(root, path);
//std::cerr << "size: " << ret.second.size() << std::endl;
	for (int j = 0; j < (int)ret.second.size(); ++j) {
		if (ret.second[j] -> edge == filename) {
			return ret.second[j];
		}
	}
//std::cerr << "----------" << std::endl;
	return nullptr;
}

bool Structure::modify_size(string path, off_t size) {
	Structure::Node *target = Structure::get_target_node(path);
	if (target == nullptr) {
		return false;
	} else {
		target -> real_size = size;
		return true;
	}
}

Structure::State Structure::get_state(string filename) {
	Structure::Node *target = Structure::get_target_node(filename);
	State ret;
	if (target == nullptr) {
		ret.exist = false;
	} else {
		ret = State(true, target -> isfolder, target -> real_size, target -> hashsum, target -> edge, target -> salt);
	}
	return ret;
}

pair<bool, vector<Structure::State> > Structure::get_state_list(string path) {
//std::cerr << "raw = " << path << std::endl;
	Structure::normalize_path(path);
//std::cerr << "normalized = " << path << std::endl;
	pair<bool, vector<Structure::Node *> > node_list = Structure::dfs_get_list(root, path);
	if (node_list.first == false) {
		return make_pair(false, vector<Structure::State>());
	}
	vector<Structure::State> state_list;
	for (auto node: node_list.second) {
		state_list.push_back(State(true, node -> isfolder, node -> real_size, node -> hashsum, node -> edge, node -> salt));
	}
	return make_pair(true, state_list);
}

void Structure::print(string filename) {
	ofstream fout(filename);
	dfs_print(fout, root, "RT", 0);
}
