/*
 * cryptofs.cpp
 * a fuse-based file system.
 */

#define FUSE_USE_VERSION 26

#include <iostream>
#include <fstream>
#include <unistd.h>
#include <stdlib.h>
#include <fuse.h>
#include <dirent.h>
#include <stdio.h>
#include <fcntl.h>  
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "Crypto.h"
#include "Structure.h"
#include "Util.h"

using std::ofstream;
using std::string;
using std::endl;
typedef Structure::State State;

#define sec_name real_name
#define raw_name fake_name

static int savefd;
static ofstream logStream;
static string mountPoint;
static Structure structure;
static Crypto::Crypto crypto;

static void logs(string s) {
	logStream << s << std::endl;
	logStream.flush();
}

static struct fuse_operations crypto_oper;

static void myassert(bool condition, string s) {
	if(!condition) logs(s);
}

static bool isAbsolutePath(std::string path)
{
	return path.size() > 0 && path[0] == '/';
}

static string getAbsolutePath(string path)
{
	string aPath = mountPoint;
	if(aPath.back() == '/')
		aPath.pop_back();
	return aPath + path;
}

static string getRelativePath(string path)
{
	myassert(path.size() > 0, "path length must greater than 1");
	if(path[0] == '/') {
		if(path.size() == 1)
			return string(".");
		else
			return path.substr(1);
	} else {
		return path;
	}
}

static string mergePath(string a, string b) {
	if(a.back() == '/')
		a.pop_back();
	if(b.front() == '.') {
		if(b.size() == 1) {
			return a;
		} else {
			return a + "/" + b.substr(1);
		}
	} else {
		return a + "/" + b;
	}
}

void mkdir(string path) {
	if(mkdir(path.c_str(), 0777)) {
		std::cout << "error: create file failed.\n" << std::endl;
		exit(1);
	}
}

static size_t file_length(string fname) {
	struct stat statbuf;
	if(stat(fname.c_str(), &statbuf) < 0)
		return 0;
	else
		return statbuf.st_size;
}

static void encode_file(State state, string raw_name, string sec_name) {
	crypto.saveSec(raw_name, state.salt, file_length(raw_name), sec_name);
}

static void decode_file(State state, string sec_name, string raw_name) {
	crypto.loadSec(sec_name, state.salt, raw_name, state.st_size);
}

static void delete_file(string file_name) {
	remove(file_name.c_str());
}

/*
 * get mountPoint and logStream
 */
static void processArgs(int argc, char *argv[]) {
	if(argc <= 1) {
		std::cerr <<  "Usage: cryptofs mountpoint [other arguments]" << std::endl;
		exit(1);
	} else {
		if(isAbsolutePath(argv[1])) {
			mountPoint = std::string(argv[1]);
		} else {
			mountPoint = mergePath(get_current_dir_name(), argv[1]);
		}
		std::cerr << "Mount point: " << mountPoint << std::endl;
		logStream = ofstream("./log.txt");
	}
	if(mountPoint.back() == '/')
		mountPoint.pop_back();
	if(!isAbsolutePath(mountPoint)) {
		std::cerr << "error: mount point must be an absolute path" << std::endl;
		exit(1);
	}
}

static void *cryptofs_init(struct fuse_conn_info *info);
static int cryptofs_getattr(const char *orig_path, struct stat *stbuf);
static int cryptofs_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
static int cryptofs_mknod(const char *orig_path, mode_t mode, dev_t rdev);
static int cryptofs_mkdir(const char *orig_path, mode_t mode);
static int cryptofs_rmdir(const char *orig_path);
static int cryptofs_open(const char *orig_path, struct fuse_file_info *fi);
static int cryptofs_read(const char *orig_path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int cryptofs_write(const char *orig_path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int cryptofs_release(const char *orig_path, struct fuse_file_info *fi);
static void cryptofs_destroy(void *private_data);


int main(int argc, char *argv[])
{
	processArgs(argc, argv);
	savefd = open(mountPoint.c_str(), 0);
	if(savefd == -1) {
		logs("error: savefd open failed\n");
		exit(1);
	}
	close(savefd);
	savefd = open((mountPoint + "/.cfs").c_str(), 0);
	if(savefd == -1) {
		std::cout << "The Crypto file system does not found and will create a new one" << std::endl;
		mkdir(mountPoint + "/.cfs");
		savefd = open((mountPoint + "/.cfs").c_str(), 0);
		mkdir(mountPoint + "/.cfs/keys");
		crypto.generateKeys();
		crypto.saveKeys(mountPoint + "/.cfs/keys");
		structure.save(mountPoint + "/.cfs/structure.sec", crypto);
	} 
	crypto.loadKeys(mountPoint + "/.cfs/keys");
	
	crypto_oper.init	= cryptofs_init;
	crypto_oper.getattr	= cryptofs_getattr;
	crypto_oper.readdir	= cryptofs_readdir;
	crypto_oper.mknod   = cryptofs_mknod;
	crypto_oper.mkdir	= cryptofs_mkdir;
	crypto_oper.rmdir	= cryptofs_rmdir;
	crypto_oper.open	= cryptofs_open;
	crypto_oper.read	= cryptofs_read;
	crypto_oper.write	= cryptofs_write;
	crypto_oper.release	= cryptofs_release;
    crypto_oper.destroy = cryptofs_destroy;

	int result = fuse_main(argc, argv, &crypto_oper, NULL);
	return result;
}

static void *cryptofs_init(struct fuse_conn_info *info)
{
	logs("cryptofs_init");
    fchdir(savefd);
    close(savefd);
	structure.load("./structure.sec", crypto);
    return NULL;
}

const mode_t reg_file_mode = 0x81FF;
const mode_t dir_file_mode = 0x41FF;

static int cryptofs_getattr(const char *orig_path, struct stat *stbuf)
{
	logs("getattr " + string(orig_path));
	memset(stbuf, 0, sizeof(*stbuf));
	State state = structure.get_state(orig_path);
	if(!state.exist) {
		return -2;
	}
	stbuf->st_mode = state.isfolder ? dir_file_mode : reg_file_mode;
	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_size = state.st_size;
    return 0;
}
 
static int cryptofs_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler,
                            off_t offset, struct fuse_file_info *fi)
{
	logs("readdir " + string(orig_path));

	pair<bool, vector<State> > state_list = structure.get_state_list(orig_path);
	if(state_list.first == false) {
		return -2;
	}
	vector<State> & vc = state_list.second;
	for(State state : vc) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_mode = state.isfolder ? dir_file_mode : reg_file_mode;
		if(filler(buf, state.fake_name.c_str(), &st, 0))
			break;
	}

	/*
    dp = opendir(rPath.c_str());
    if (dp == NULL)
    {
        res = -errno;
		logs("readdir opendir failed " + rPath);
        return res;
    }

    while ((de = readdir(dp)) != NULL)
    {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
	*/

    return 0;
}

static int cryptofs_mknod(const char *orig_path, mode_t mode, dev_t rdev)
{
	logs("cryptofs_mknod" + string(orig_path));
	if(S_ISREG(mode)) {
		logs("mknod regular file " + getRelativePath(orig_path));
		structure.add_file(orig_path, 0, false, crypto);
	} else {
		return -1;
	}
	return 0;

	/*
    int res;
    string aPath = getAbsolutePath(orig_path);
    string rPath = getRelativePath(orig_path);

    if (S_ISREG(mode)) {
		logs("mknod regular file " + rPath);
        res = open(rPath.c_str(), O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0) res = close(res);
    } else {
		res = -1;
		return 0;
    }

	lchown(rPath.c_str(), fuse_get_context()->uid, fuse_get_context()->gid);
	*/
    return 0;
}

static int cryptofs_mkdir(const char *orig_path, mode_t mode)
{
	logs("cryptofs_mkdir" + string(orig_path));
	structure.add_file(orig_path, 0, true, crypto);
	/*
    string aPath = getAbsolutePath(orig_path);
    string rPath = getRelativePath(orig_path);
	logs("mkdir " + rPath);
    int res = mkdir(rPath.c_str(), mode);

    if (res == -1) return -errno;

	lchown(rPath.c_str(), fuse_get_context()->uid, fuse_get_context()->gid);
	*/
    return 0;
}

static int cryptofs_rmdir(const char *orig_path)
{
	logs("cryptofs_rmdir" + string(orig_path));
	structure.del_file(orig_path);
	/*
    string aPath = getAbsolutePath(orig_path);
    string rPath = getRelativePath(orig_path);
	logs("rmdir " + rPath);
    int res = rmdir(rPath.c_str());
    if (res == -1) return -errno;
	*/
    return 0;
}

static int cryptofs_open(const char *orig_path, struct fuse_file_info *fi)
{
	logs("cryptofs_open" + string(orig_path));
	State state = structure.get_state(orig_path);
	if(!state.exist) return -2;
	if(state.isfolder) return -1;
	decode_file(state, "./contents/" + state.sec_name + ".sec", "./contents/" + state.raw_name + ".raw");
	int res = open(("./contents/" + state.raw_name + ".raw").c_str(), fi->flags);
	if(res == -1) return -errno;
	fi->fh = res;
	return 0;
	/*
    string aPath = getAbsolutePath(orig_path);
    string path = getRelativePath(orig_path);

    // what type of open ? read, write, or read-write ?
    if (fi->flags & O_RDONLY)
    {
		logs("open readonly " + path);
    }
    else if (fi->flags & O_WRONLY)
    {
		logs("open writeonly " + path);
    }
    else if (fi->flags & O_RDWR)
    {
		logs("open readwrite " + path);
    }
    else {
		logs("open " + path);
	}

    int res = open(path.c_str(), fi->flags);
    if (res == -1) return -errno;

    fi->fh = res;
    return 0;
	*/
}

static int cryptofs_read(const char *orig_path, char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi)
{
	logs("cryptofs_read" + string(orig_path));
	State state = structure.get_state(orig_path);
	if(!state.exist) return -2;
	if(state.isfolder) return -1;
	int res = pread(fi->fh, buf, size, offset);
	if(res == -1)
		return -errno;
	return res;
	/*
    string aPath = getAbsolutePath(orig_path);
    int res;

	logs("read " + aPath);
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;
    return res;
	*/
}

static int cryptofs_write(const char *orig_path, const char *buf, size_t size,
                          off_t offset, struct fuse_file_info *fi)
{
	logs("cryptofs_write" + string(orig_path));
	int res = pwrite(fi->fh, buf, size, offset);
	if(res == -1)
		return -errno;
	return res;
	/*
    int fd;
    int res;
    string aPath = getAbsolutePath(orig_path);
    string path = getRelativePath(orig_path);
    (void)fi;

	logs("write " + path);

    fd = open(path.c_str(), O_WRONLY);
    if (fd == -1) {
        res = -errno;
        return res;
	}

    res = pwrite(fd, buf, size, offset);

    if (res == -1)
        res = -errno;

    close(fd);

    return res;
	*/
}

static int cryptofs_release(const char *orig_path, struct fuse_file_info *fi)
{
	logs("cryptofs_release" + string(orig_path));
	State state = structure.get_state(orig_path);
	encode_file(state, "./contents/" + state.raw_name + ".raw", "./contents/" + state.sec_name + ".sec");
	delete_file("./contents/" + state.sec_name + ".sec");
	close(fi->fh);
	return 0;
	/*
    string aPath = getAbsolutePath(orig_path);
    (void)orig_path;

	logs("release " + getRelativePath(orig_path));

    close(fi->fh);
    return 0;
	*/
}

static void cryptofs_destroy (void *private_data) {
    logs ("cryptofs_destroy");
	structure.save("./structure.sec", crypto);
}
