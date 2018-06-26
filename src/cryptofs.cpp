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

using std::ofstream;
using std::string;
using std::endl;


static int savefd;
static ofstream logStream;
static string mountPoint;

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

/*
 * get mountPoint and logStream
 */
static void processArgs(int argc, char *argv[]) {
	if(argc == 2) {
		mountPoint = std::string(argv[1]);
		logStream = ofstream("./log.txt");
	} else if(argc == 3) {
		mountPoint = std::string(argv[1]);
		logStream = ofstream(argv[2]);
	} else {
		std::cerr <<  "Usage: cryptofs mountpoint [logfile]" << std::endl;
		exit(1);
	}
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
static int cryptofs_rename(const char *orig_from, const char *orig_to);
static int cryptofs_chmod(const char *orig_path, mode_t mode);
static int cryptofs_chown(const char *orig_path, uid_t uid, gid_t gid);
static int cryptofs_truncate(const char *orig_path, off_t size);
static int cryptofs_utimens(const char *orig_path, const struct timespec ts[2]);
static int cryptofs_open(const char *orig_path, struct fuse_file_info *fi);
static int cryptofs_read(const char *orig_path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int cryptofs_write(const char *orig_path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
static int cryptofs_statfs(const char *orig_path, struct statvfs *stbuf);
static int cryptofs_release(const char *orig_path, struct fuse_file_info *fi);
static int cryptofs_fsync(const char *orig_path, int isdatasync, struct fuse_file_info *fi);


int main(int argc, char *argv[])
{

	processArgs(argc, argv);
	savefd = open(mountPoint.c_str(), 0);
	if(savefd == -1) {
		logs("error: savefd open failed\n");
		exit(1);
	}
	crypto_oper.init	= cryptofs_init;
	crypto_oper.getattr	= cryptofs_getattr;
	crypto_oper.readdir	= cryptofs_readdir;
	crypto_oper.mknod   = cryptofs_mknod;
	crypto_oper.mkdir	= cryptofs_mkdir;
	crypto_oper.rmdir	= cryptofs_rmdir;
	crypto_oper.rename	= cryptofs_rename;
	crypto_oper.chmod	= cryptofs_chmod;
	crypto_oper.chown	= cryptofs_chown;
	crypto_oper.truncate= cryptofs_truncate;
	crypto_oper.utimens	= cryptofs_utimens;
	crypto_oper.open	= cryptofs_open;
	crypto_oper.read	= cryptofs_read;
	crypto_oper.write	= cryptofs_write;
	crypto_oper.statfs	= cryptofs_statfs;
	crypto_oper.release	= cryptofs_release;
	crypto_oper.fsync	= cryptofs_fsync;

	int result = fuse_main(argc, argv, &crypto_oper, NULL);
	return result;
}

static void *cryptofs_init(struct fuse_conn_info *info)
{
    fchdir(savefd);
    close(savefd);
    return NULL;
}

static int cryptofs_getattr(const char *orig_path, struct stat *stbuf)
{
    string aPath = getAbsolutePath(orig_path);
    string rPath = getRelativePath(orig_path);
	logs("getattr " + rPath);
    int res = lstat(rPath.c_str(), stbuf);
    if (res == -1) return -errno;

    return 0;
}
 
static int cryptofs_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler,
                            off_t offset, struct fuse_file_info *fi)
{
    DIR *dp;
    struct dirent *de;
    int res;

    (void)offset;
    (void)fi;

	logs("readdir " + string(orig_path));

    string aPath = getAbsolutePath(orig_path);
    string rPath = getRelativePath(orig_path);

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

    return 0;
}

static int cryptofs_mknod(const char *orig_path, mode_t mode, dev_t rdev)
{
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

    return 0;
}

static int cryptofs_mkdir(const char *orig_path, mode_t mode)
{
    string aPath = getAbsolutePath(orig_path);
    string rPath = getRelativePath(orig_path);
	logs("mkdir " + rPath);
    int res = mkdir(rPath.c_str(), mode);

    if (res == -1) return -errno;

	lchown(rPath.c_str(), fuse_get_context()->uid, fuse_get_context()->gid);
    return 0;
}

static int cryptofs_rmdir(const char *orig_path)
{
    string aPath = getAbsolutePath(orig_path);
    string rPath = getRelativePath(orig_path);
	logs("rmdir " + rPath);
    int res = rmdir(rPath.c_str());
    if (res == -1) return -errno;
    return 0;
}

static int cryptofs_rename(const char *orig_from, const char *orig_to)
{
    string aFrom = getAbsolutePath(orig_from);
    string aTo = getAbsolutePath(orig_to);
    string from = getRelativePath(orig_from);
    string to = getRelativePath(orig_to);
	logs("rename " + from + " " + to);
    int res = rename(from.c_str(), to.c_str());

    if (res == -1) return -errno;

    return 0;
}

static int cryptofs_chmod(const char *orig_path, mode_t mode)
{
    string aPath = getAbsolutePath(orig_path);
    string path = getRelativePath(orig_path);
	logs("chmod " + path);
    int res = chmod(path.c_str(), mode);
    if (res == -1) return -errno;

    return 0;
}

static int cryptofs_chown(const char *orig_path, uid_t uid, gid_t gid)
{
    string aPath = getAbsolutePath(orig_path);
    string path = getRelativePath(orig_path);
    int res = lchown(path.c_str(), uid, gid);
	logs("chown " + path);
    if (res == -1) return -errno;

    return 0;
}

static int cryptofs_truncate(const char *orig_path, off_t size)
{
    string aPath = getAbsolutePath(orig_path);
    string path = getRelativePath(orig_path);
	logs("truncate " + path);
    int res = truncate(path.c_str(), size);
    if (res == -1) return -errno;

    return 0;
}
static int cryptofs_utimens(const char *orig_path, const struct timespec ts[2])
{
    string aPath = getAbsolutePath(orig_path);
    string path = getRelativePath(orig_path);
	logs("utimens " + path);
    int res = utimensat(AT_FDCWD, path.c_str(), ts, AT_SYMLINK_NOFOLLOW);

    if (res == -1) return -errno;

    return 0;
}

static int cryptofs_open(const char *orig_path, struct fuse_file_info *fi)
{
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
}

static int cryptofs_read(const char *orig_path, char *buf, size_t size, off_t offset,
                         struct fuse_file_info *fi)
{
    string aPath = getAbsolutePath(orig_path);
    int res;

	logs("read " + aPath);
    res = pread(fi->fh, buf, size, offset);
    if (res == -1)
        res = -errno;
    return res;
}

static int cryptofs_write(const char *orig_path, const char *buf, size_t size,
                          off_t offset, struct fuse_file_info *fi)
{
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
}

static int cryptofs_statfs(const char *orig_path, struct statvfs *stbuf)
{
    int res;
    string aPath = getAbsolutePath(orig_path);
    string path = getRelativePath(orig_path);
	logs("statfs " + path);
    res = statvfs(path.c_str(), stbuf);
    if (res == -1) return -errno;

    return 0;
}

static int cryptofs_release(const char *orig_path, struct fuse_file_info *fi)
{
    string aPath = getAbsolutePath(orig_path);
    (void)orig_path;

	logs("release " + getRelativePath(orig_path));

    close(fi->fh);
    return 0;
}

static int cryptofs_fsync(const char *orig_path, int isdatasync, struct fuse_file_info *fi)
{
    string aPath = getAbsolutePath(orig_path);
    (void)orig_path;
    (void)isdatasync;
    (void)fi;
	logs("fsync " + getRelativePath(orig_path));
    return 0;
}
