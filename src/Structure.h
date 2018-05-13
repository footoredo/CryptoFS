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

class Structure {
public:

	struct Node {
		map<string, Node *> children;
		struct stat my_stat;
		bool isfile;
		string id;
		string salt;
	};

	Structure() {
		root = new Node();
		root -> id = "rt";
		root -> salt = "rt";
		root -> isfile = false;
	}

	~Structure() {
		delete_node(root);
	}

	void load(string filename) {
//cerr << "loading..." << endl;
		Crypto::Crypto crypto;
		crypto.loadKeys(".keys");
//cerr << "loading..." << endl;
		info = new byte[MAXN + 100];
		memset (info, 0x00, MAXN + 10);
//cerr << "loading..." << endl;
		crypto.loadSec(filename, info, MAXN);
//cerr << "\nloading: " << info << endl;
		byte * tmp = info;
		root = new Node();
		load_node(tmp, root);
		delete [] info;
	}

	void save(string filename) {
		Crypto::Crypto crypto;
		crypto.generateKeys();
		crypto.saveKeys(".keys");
		string info;
		save_node(info, root);
		if (info.length() >= MAXN) {
			throw Util::Exception("file system too large!");
		}
//cerr << "\nsave: " << info << endl;
		byte *buffer = new byte[MAXN + 10];
		for (int i = 0; i < info.size(); ++i) {
			buffer[i] = info[i];
		}
		buffer[info.size()] = 0;
//cerr << buffer << endl;
		crypto.saveSec(filename, buffer, MAXN);
		delete []buffer;
	}

	bool add_file(string filename, string id, bool isfile,
				  const struct stat &my_stat, const string &salt) { //filename including path
		normalize_path(filename);
		return dfs_add(root, id, filename, isfile, my_stat, salt);
	}
	
	Node get_property(string filename) {
		normalize_path(filename);
		Node *u = dfs_get_property(root, filename);
		Node ret;
		ret.my_stat = u -> my_stat;
		ret.isfile = u -> isfile;
		ret.id = u -> id;
		ret.salt = u -> salt;
		return ret;
	}

	void print(string filename) {
		ofstream fout(filename);
		dfs_print(fout, root, 0);
	}

private:

	Node *root;
	byte *info;
	static const int MAXN = 1000;
	
	inline void normalize_path(string &path) {
		for (; path.size() && !convert::file_letter(path.back()); path.pop_back());
		for (auto u: path) {
			if (!convert::file_letter(u) && u != '/') {
				throw Util::Exception(string("dangerous path containing:") + u);
			}
		}
		if (path == "" || path == "/") {
			throw Util::Exception("Nothing to add");
		}
		if (path.back() != '/') {
			path.append(1, '/');
		}
	}

	void delete_node(Node *u) {
		for (auto v: u -> children) {
			delete_node(v.second);
		}
		delete u;
	}
//int cnt = 0;
	void load_node(byte *&info, Node *u) {
//cerr << info << endl; 
		u -> id = convert::get_str(info);
		u -> isfile = convert::get_bool(info);
		u -> salt = convert::get_str(info);
		int n_son = convert::get_int(info);
//cerr << "node: " << u -> id << " " << u -> isfile << " " << u -> salt << " " << n_son << endl;
//cerr << "left info->" << info << endl;
//if (++cnt == 2) { 
//	return;
//}
		string edge;
		for (; n_son; --n_son) {
			Node *v = new Node();
			edge = convert::get_str(info);
			u -> children[edge] = v;
			load_node(info, v);
		}
	}

	void save_node(string &info, Node *u) {
		//info = info + "__root__" + " ";
		info = info.append(u -> id + " ");
		info = info.append(to_string(u -> isfile) + " ");
		info = info.append(u -> salt + " "); 
//cerr << "id when saving: " << info << endl;	
//cerr << "node: " << info << endl;
		//print stat
		info = info.append(to_string(u -> children.size()) + " ");
		for (auto v: u -> children) {
			info = info.append(v.first + " ");
			save_node(info, v.second);
		}
	}

	bool dfs_add(Node *u, const string &id, string &filename, bool isfile,
				  const struct stat &my_stat, const string &salt) { //filename including path
		int pos = filename.find('/');
//cout << filename;
		string now = filename.substr(0, pos);
		filename = filename.substr(pos + 1);
//cout << " -> " << now << " + " << filename << ";" << endl;
		if (filename.length() == 0) {
			if (u -> children.count(now)) {
				throw Util::Exception("File or dir already existed: " + now);
				return false;
			}
			Node *v = new Node();
			v -> id = id;
			v -> isfile = isfile;
//cout << "add file prop" << isfile << endl;
			v -> my_stat = my_stat;
			v -> salt = salt;
			u -> children[now] = v;
			return true;
		} else {
			map<string, Node *>::iterator it = u -> children.find(now);
			if (it == u -> children.end()) {
				throw Util::Exception("No such direction: " + now);
				return false;
			} else {
//std::cout << u -> isfile << endl;
				if (it -> second -> isfile) {
					throw Util::Exception(now + " is not a dir");
				}
				return dfs_add(it -> second, id, filename, isfile, my_stat, salt);
			}
		}
	}
	
	inline Node *dfs_get_property(Node *u, string filename) {
		int pos = filename.find('/');
		string now = filename.substr(0, pos);
		filename = filename.substr(pos + 1);
		map<string, Node *>::iterator it = u -> children.find(now);
		if (filename.length() == 0) {
			if (it == u -> children.end()) {
				throw Util::Exception("target not found");
			}
			return it -> second;
		} else {
			if (it == u -> children.end()) {
				throw Util::Exception("dir not found: " + now);
			} else {
				return dfs_get_property(it -> second, filename);
			}
		}
	}

	inline void dfs_print(ofstream &fout, Node *u, int depth) {
		string s;
		s.append(depth * 4, ' ');
		fout << s << "{";
		fout << "id: " << u -> id << ", ";
		fout << "salt: " << u -> salt << ", ";
		fout << "isfile: " << u -> isfile << "}" << std::endl;
		for (auto v: u -> children) {
			dfs_print(fout, v.second, depth + 1);
		}
	}

};


#endif 
