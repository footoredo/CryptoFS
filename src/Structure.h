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
		//struct stat my_stat;
		bool isfolder;
		string id;
		string salt;
	};

	Structure() {
		root = new Node();
		root -> id = "root";
		root -> salt = "root";
		root -> isfolder = true;
	}

	~Structure() {
		delete_node(root);
	}
	
	//absolute path required!
	
	void load(string filename);
	
	void save(string filename);
	
	bool add_file(string path, string id, bool isfolder, const string &salt);
	
	bool del_file(string path);
	
	struct stat *get_stat(string filename);
	
	void print(string filename);

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
		u -> isfolder = convert::get_bool(info);
		u -> salt = convert::get_str(info);
		int n_son = convert::get_int(info);
//cerr << "node: " << u -> id << " " << u -> isfolder << " " << u -> salt << " " << n_son << endl;
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
		info = info.append(to_string(u -> isfolder) + " ");
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

	bool add_file_with_stat(string path, string id, bool isfolder,
				  const struct stat &my_stat, const string &salt) { //filename including path
		normalize_path(path);
		return dfs_add(root, id, path, isfolder, my_stat, salt);
	}

	bool dfs_add(Node *u, const string &id, string &path, bool isfolder,
				  const struct stat &my_stat, const string &salt) { //absolute path
		int pos = path.find('/');
//cout << path;
		string now = path.substr(0, pos);
		path = path.substr(pos + 1);
//cout << " -> " << now << " + " << path << ";" << endl;
		if (path.length() == 0) {
			if (u -> children.count(now)) {
				throw Util::Exception("File or dir already existed: " + now);
				return false;
			}
			Node *v = new Node();
			v -> id = id;
			v -> isfolder = isfolder;
//cout << "add file prop" << isfolder << endl;
			//v -> my_stat = my_stat;
			v -> salt = salt;
			u -> children[now] = v;
			return true;
		} else {
			map<string, Node *>::iterator it = u -> children.find(now);
			if (it == u -> children.end()) {
				throw Util::Exception("No such direction: " + now);
				return false;
			} else {
//std::cout << u -> isfolder << endl;
				if (!(it -> second -> isfolder)) {
					throw Util::Exception(now + " is not a dir");
				}
				return dfs_add(it -> second, id, path, isfolder, my_stat, salt);
			}
		}
	}
	
	inline bool dfs_del(Node *u, string path) {
		int pos = path.find('/');
		string now = path.substr(0, pos);
		path = path.substr(pos + 1);
		map<string, Node *>::iterator it = u -> children.find(now);
		if (path.length() == 0) {
			if (it == u -> children.end()) {
				throw Util::Exception("target not found");
			}
			if (it -> second -> children.size()) {
				throw Util::Exception("target not empty");
			} else {
				u -> children.erase(it);
				std::cerr << "left size: " << u -> children.size() << std::endl;
				return 1;
			}
		} else {
			if (it == u -> children.end()) {
				throw Util::Exception("dir not found: " + now);
			} else {
				return dfs_del(it -> second, path);
			}
		}
	}
	
	inline Node *dfs_get_property(Node *u, string path) {
		int pos = path.find('/');
		string now = path.substr(0, pos);
		path = path.substr(pos + 1);
		map<string, Node *>::iterator it = u -> children.find(now);
		if (path.length() == 0) {
			if (it == u -> children.end()) {
				throw Util::Exception("target not found");
			}
			return it -> second;
		} else {
			if (it == u -> children.end()) {
				throw Util::Exception("dir not found: " + now);
			} else {
				return dfs_get_property(it -> second, path);
			}
		}
	}

	inline void dfs_print(ofstream &fout, Node *u, int depth) {
		string s;
		s.append(depth * 4, ' ');
		fout << s << "{";
		fout << "id: " << u -> id << ", ";
		fout << "salt: " << u -> salt << ", ";
		fout << "isfolder: " << u -> isfolder << "}" << std::endl;
		for (auto v: u -> children) {
			dfs_print(fout, v.second, depth + 1);
		}
	}

};


void Structure::load(string filename) {
//cerr << "loading..." << endl;
	Crypto::Crypto crypto;
	crypto.loadKeys(".keys");
//cerr << "loading..." << endl;
	info = new byte[MAXN + 100];
	memset (info, 0x00, MAXN + 10);
//cerr << "loading..." << endl;
	crypto.loadSec(filename, "", info, MAXN);
//cerr << "\nloading: " << info << endl;
	byte * tmp = info;
	root = new Node();
	load_node(tmp, root);
	delete [] info;
}

void Structure::save(string filename) {
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
	for (int i = 0; i < (int)info.size(); ++i) {
		buffer[i] = info[i];
	}
	buffer[info.size()] = 0;
//cerr << buffer << endl;
	crypto.saveSec(filename, "", buffer, MAXN);
	delete []buffer;
}

bool Structure::add_file(string path, string id, bool isfolder, const string &salt) {
	struct stat tmp;
	return add_file_with_stat(path, id, isfolder, tmp, salt);
}

bool Structure::del_file(string path) {
	normalize_path(path);
	return dfs_del(root, path);
}
//??? to fix???
struct stat *Structure::get_stat(string filename) {
	normalize_path(filename);
	Node *u = dfs_get_property(root, filename);
	//Node ret;
	//ret.my_stat = u -> my_stat;
	//ret.isfolder = u -> isfolder;
	//ret.id = u -> id;
	//ret.salt = u -> salt;
	struct stat *ret;
	lstat("123.123", ret);
	return ret;
}

void Structure::print(string filename) {
	ofstream fout(filename);
	dfs_print(fout, root, 0);
}



#endif 
