/*
 * cryptofs.cpp
 * a fuse-based file system.
 */

#define FUSE_USE_VERSION 26

#include <unistd.h>
#include <stdlib.h>
#include <fuse.h>
#include <stdio.h>
#include <fcntl.h>  
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static int savefd;
static FILE * logfile;
static char * mountPoint;

static void logs(const char *str) {
	fprintf(logfile, "%s", str);
	fflush(logfile);
}

static struct fuse_operations crypto_oper;

static void processArgs(int argc, char *argv[]) {
	if(argc != 2) {
		fprintf(stderr, "Usage: cryptofs mountpoint\n");
		exit(1);
	}
	mountPoint = strdup(argv[1]);
}

int main(int argc, char *argv[])
{
	processArgs(argc, argv);
	logfile = fopen("./log.txt", "w");
	savefd = open(mountPoint, 0);
	if(savefd == -1) {
		logs("savefd open failed\n");
		exit(1);
	}
	crypto_oper.init	= crypto_init;
	crypto_oper.getattr	= crypto_getattr;
	crypto_oper.readdir	= crypto_readdir;
	crypto_oper.open	= crypto_open;
	crypto_oper.read	= crypto_read;
	int result = fuse_main(argc, argv, &crypto_oper, NULL);
	fclose(logfile);
	return result;
}

static bool isAbsolutePath(const char *fileName)
{
    if (fileName && fileName[0] != '\0' && fileName[0] == '/')
        return true;
    else
        return false;
}

static char *getAbsolutePath(const char *path)
{
    char *realPath = new char[strlen(path) + strlen(loggedfsArgs->mountPoint) + 1];

    strcpy(realPath, loggedfsArgs->mountPoint);
    if (realPath[strlen(realPath) - 1] == '/')
        realPath[strlen(realPath) - 1] = '\0';
    strcat(realPath, path);
    return realPath;
}

static char *getRelativePath(const char *path)
{
    if (path[0] == '/')
    {
        if (strlen(path) == 1)
        {
            return strdup(".");
        }
        const char *substr = &path[1];
        return strdup(substr);
    }

    return strdup(path);
}
static void *cryptofs_init(struct fuse_conn_info *info)
{
    fchdir(savefd);
    close(savefd);
    return NULL;
}

static int cryptofs_getattr(const char *orig_path, struct stat *stbuf)
{
    int res;

    char *aPath = getAbsolutePath(orig_path);
    char *rPath = getRelativePath(orig_path);
    res = lstat(rPath, stbuf);
    delete[] aPath;
    free(path);
    if (res == -1)
        return -errno;

    return 0;
}
// 
// static int cryptofs_access(const char *orig_path, int mask)
// {
//     int res;
// 
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = access(path, mask);
//     loggedfs_log(aPath, "access", res, "access %s", aPath);
//     delete[] aPath;
//     free(path);
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// static int cryptofs_readlink(const char *orig_path, char *buf, size_t size)
// {
//     int res;
// 
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = readlink(path, buf, size - 1);
//     loggedfs_log(aPath, "readlink", res, "readlink %s", aPath);
//     delete[] aPath;
//     free(path);
//     if (res == -1)
//         return -errno;
// 
//     buf[res] = '\0';
// 
//     return 0;
// }
// 
// static int cryptofs_readdir(const char *orig_path, void *buf, fuse_fill_dir_t filler,
//                             off_t offset, struct fuse_file_info *fi)
// {
//     DIR *dp;
//     struct dirent *de;
//     int res;
// 
//     (void)offset;
//     (void)fi;
// 
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
// 
//     dp = opendir(path);
//     if (dp == NULL)
//     {
//         res = -errno;
//         loggedfs_log(aPath, "readdir", -1, "readdir %s", aPath);
//         delete[] aPath;
//         free(path);
//         return res;
//     }
// 
//     while ((de = readdir(dp)) != NULL)
//     {
//         struct stat st;
//         memset(&st, 0, sizeof(st));
//         st.st_ino = de->d_ino;
//         st.st_mode = de->d_type << 12;
//         if (filler(buf, de->d_name, &st, 0))
//             break;
//     }
// 
//     closedir(dp);
//     loggedfs_log(aPath, "readdir", 0, "readdir %s", aPath);
//     delete[] aPath;
//     free(path);
// 
//     return 0;
// }
// 
// static int cryptofs_mknod(const char *orig_path, mode_t mode, dev_t rdev)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
// 
//     if (S_ISREG(mode))
//     {
//         res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
//         loggedfs_log(aPath, "mknod", res, "mknod %s %o S_IFREG (normal file creation)", aPath, mode);
//         if (res >= 0)
//             res = close(res);
//     }
//     else if (S_ISFIFO(mode))
//     {
//         res = mkfifo(path, mode);
//         loggedfs_log(aPath, "mkfifo", res, "mkfifo %s %o S_IFFIFO (fifo creation)", aPath, mode);
//     }
//     else
//     {
//         res = mknod(path, mode, rdev);
//         if (S_ISCHR(mode))
//         {
//             loggedfs_log(aPath, "mknod", res, "mknod %s %o (character device creation)", aPath, mode);
//         }
//         /*else if (S_IFBLK(mode))
// 		{
// 		loggedfs_log(aPath,"mknod",res,"mknod %s %o (block device creation)",aPath, mode);
// 		}*/
//         else
//             loggedfs_log(aPath, "mknod", res, "mknod %s %o", aPath, mode);
//     }
// 
//     delete[] aPath;
// 
//     if (res == -1)
//     {
//         free(path);
//         return -errno;
//     }
//     else
//         lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);
// 
//     free(path);
// 
//     return 0;
// }
// 
// static int cryptofs_mkdir(const char *orig_path, mode_t mode)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = mkdir(path, mode);
//     loggedfs_log(path, "mkdir", res, "mkdir %s %o", aPath, mode);
//     delete[] aPath;
// 
//     if (res == -1)
//     {
//         free(path);
//         return -errno;
//     }
//     else
//         lchown(path, fuse_get_context()->uid, fuse_get_context()->gid);
// 
//     free(path);
//     return 0;
// }
// 
// static int cryptofs_unlink(const char *orig_path)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = unlink(path);
//     loggedfs_log(aPath, "unlink", res, "unlink %s", aPath);
//     delete[] aPath;
//     free(path);
// 
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// static int cryptofs_rmdir(const char *orig_path)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = rmdir(path);
//     loggedfs_log(aPath, "rmdir", res, "rmdir %s", aPath);
//     delete[] aPath;
//     free(path);
//     if (res == -1)
//         return -errno;
//     return 0;
// }
// 
// static int cryptofs_symlink(const char *from, const char *orig_to)
// {
//     int res;
// 
//     char *aTo = getAbsolutePath(orig_to);
//     char *to = getRelativePath(orig_to);
// 
//     res = symlink(from, to);
// 
//     loggedfs_log(aTo, "symlink", res, "symlink from %s to %s", aTo, from);
//     delete[] aTo;
// 
//     if (res == -1)
//     {
//         free(to);
//         return -errno;
//     }
//     else
//         lchown(to, fuse_get_context()->uid, fuse_get_context()->gid);
// 
//     free(to);
//     return 0;
// }
// 
// static int cryptofs_rename(const char *orig_from, const char *orig_to)
// {
//     int res;
//     char *aFrom = getAbsolutePath(orig_from);
//     char *aTo = getAbsolutePath(orig_to);
//     char *from = getRelativePath(orig_from);
//     char *to = getRelativePath(orig_to);
//     res = rename(from, to);
//     loggedfs_log(aFrom, "rename", res, "rename %s to %s", aFrom, aTo);
//     delete[] aFrom;
//     delete[] aTo;
//     free(from);
//     free(to);
// 
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// static int cryptofs_link(const char *orig_from, const char *orig_to)
// {
//     int res;
// 
//     char *aFrom = getAbsolutePath(orig_from);
//     char *aTo = getAbsolutePath(orig_to);
//     char *from = getRelativePath(orig_from);
//     char *to = getRelativePath(orig_to);
// 
//     res = link(from, to);
//     loggedfs_log(aTo, "link", res, "hard link from %s to %s", aTo, aFrom);
//     delete[] aFrom;
//     delete[] aTo;
//     free(from);
// 
//     if (res == -1)
//     {
//         delete[] to;
//         return -errno;
//     }
//     else
//         lchown(to, fuse_get_context()->uid, fuse_get_context()->gid);
// 
//     free(to);
// 
//     return 0;
// }
// 
// static int cryptofs_chmod(const char *orig_path, mode_t mode)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = chmod(path, mode);
//     loggedfs_log(aPath, "chmod", res, "chmod %s to %o", aPath, mode);
//     delete[] aPath;
//     free(path);
// 
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// static char *getusername(uid_t uid)
// {
//     struct passwd *p = getpwuid(uid);
//     if (p != NULL)
//         return p->pw_name;
//     return NULL;
// }
// 
// static char *getgroupname(gid_t gid)
// {
//     struct group *g = getgrgid(gid);
//     if (g != NULL)
//         return g->gr_name;
//     return NULL;
// }
// 
// static int cryptofs_chown(const char *orig_path, uid_t uid, gid_t gid)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = lchown(path, uid, gid);
// 
//     char *username = getusername(uid);
//     char *groupname = getgroupname(gid);
// 
//     if (username != NULL && groupname != NULL)
//         loggedfs_log(aPath, "chown", res, "chown %s to %d:%d %s:%s", aPath, uid, gid, username, groupname);
//     else
//         loggedfs_log(aPath, "chown", res, "chown %s to %d:%d", aPath, uid, gid);
//     delete[] aPath;
//     free(path);
// 
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// static int cryptofs_truncate(const char *orig_path, off_t size)
// {
//     int res;
// 
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = truncate(path, size);
//     loggedfs_log(aPath, "truncate", res, "truncate %s to %d bytes", aPath, size);
//     delete[] aPath;
//     free(path);
// 
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// #if (FUSE_USE_VERSION == 25)
// static int cryptofs_utime(const char *orig_path, struct utimbuf *buf)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = utime(path, buf);
//     loggedfs_log(aPath, "utime", res, "utime %s", aPath);
//     delete[] aPath;
//     free(path);
// 
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// #else
// 
// static int cryptofs_utimens(const char *orig_path, const struct timespec ts[2])
// {
//     int res;
// 
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
// 
//     res = utimensat(AT_FDCWD, path, ts, AT_SYMLINK_NOFOLLOW);
// 
//     loggedfs_log(aPath, "utimens", res, "utimens %s", aPath);
//     delete[] aPath;
//     free(path);
// 
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// #endif
// 
// static int cryptofs_open(const char *orig_path, struct fuse_file_info *fi)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = open(path, fi->flags);
// 
//     // what type of open ? read, write, or read-write ?
//     if (fi->flags & O_RDONLY)
//     {
//         loggedfs_log(aPath, "open-readonly", res, "open readonly %s", aPath);
//     }
//     else if (fi->flags & O_WRONLY)
//     {
//         loggedfs_log(aPath, "open-writeonly", res, "open writeonly %s", aPath);
//     }
//     else if (fi->flags & O_RDWR)
//     {
//         loggedfs_log(aPath, "open-readwrite", res, "open readwrite %s", aPath);
//     }
//     else
//         loggedfs_log(aPath, "open", res, "open %s", aPath);
// 
//     delete[] aPath;
//     free(path);
// 
//     if (res == -1)
//         return -errno;
// 
//     fi->fh = res;
//     return 0;
// }
// 
// static int cryptofs_read(const char *orig_path, char *buf, size_t size, off_t offset,
//                          struct fuse_file_info *fi)
// {
//     char *aPath = getAbsolutePath(orig_path);
//     int res;
// 
//     loggedfs_log(aPath, "read", 0, "read %d bytes from %s at offset %d", size, aPath, offset);
//     res = pread(fi->fh, buf, size, offset);
//     if (res == -1)
//     {
//         res = -errno;
//         loggedfs_log(aPath, "read", -1, "read %d bytes from %s at offset %d", size, aPath, offset);
//     }
//     else
//     {
//         loggedfs_log(aPath, "read", 0, "%d bytes read from %s at offset %d", res, aPath, offset);
//     }
//     delete[] aPath;
//     return res;
// }
// 
// static int cryptofs_write(const char *orig_path, const char *buf, size_t size,
//                           off_t offset, struct fuse_file_info *fi)
// {
//     int fd;
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     (void)fi;
// 
//     fd = open(path, O_WRONLY);
//     if (fd == -1)
//     {
//         res = -errno;
//         loggedfs_log(aPath, "write", -1, "write %d bytes to %s at offset %d", size, aPath, offset);
//         delete[] aPath;
//         free(path);
//         return res;
//     }
//     else
//     {
//         loggedfs_log(aPath, "write", 0, "write %d bytes to %s at offset %d", size, aPath, offset);
//     }
// 
//     res = pwrite(fd, buf, size, offset);
// 
//     if (res == -1)
//         res = -errno;
//     else
//         loggedfs_log(aPath, "write", 0, "%d bytes written to %s at offset %d", res, aPath, offset);
// 
//     close(fd);
//     delete[] aPath;
//     free(path);
// 
//     return res;
// }
// 
// static int cryptofs_statfs(const char *orig_path, struct statvfs *stbuf)
// {
//     int res;
//     char *aPath = getAbsolutePath(orig_path);
//     char *path = getRelativePath(orig_path);
//     res = statvfs(path, stbuf);
//     loggedfs_log(aPath, "statfs", res, "statfs %s", aPath);
//     delete[] aPath;
//     free(path);
//     if (res == -1)
//         return -errno;
// 
//     return 0;
// }
// 
// static int cryptofs_release(const char *orig_path, struct fuse_file_info *fi)
// {
//     char *aPath = getAbsolutePath(orig_path);
//     (void)orig_path;
// 
//     loggedfs_log(aPath, "release", 0, "release %s", aPath);
//     delete[] aPath;
// 
//     close(fi->fh);
//     return 0;
// }
// 
// static int cryptofs_fsync(const char *orig_path, int isdatasync,
//                           struct fuse_file_info *fi)
// {
//     char *aPath = getAbsolutePath(orig_path);
//     (void)orig_path;
//     (void)isdatasync;
//     (void)fi;
//     loggedfs_log(aPath, "fsync", 0, "fsync %s", aPath);
//     delete[] aPath;
//     return 0;
// }
/*
static int crypto_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	logs("getattr\n");
	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, crypto_path) == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(crypto_str);
	} else
		res = -ENOENT;

	return res;
}

static int crypto_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	logs("readdir\n");
	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	//filler(buf, "adsfasf", NULL, 0);
	filler(buf, crypto_path + 1, NULL, 0);

	return 0;
}

static int crypto_open(const char *path, struct fuse_file_info *fi)
{
	logs("open\n");
	if (strcmp(path, crypto_path) != 0)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int crypto_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	logs("read\n");
	size_t len;
	(void) fi;
	if(strcmp(path, crypto_path) != 0)
		return -ENOENT;

	len = strlen(crypto_str);
	if (offset < (signed)len) {
		if (offset + size > len)
			size = len - offset;
		//memcpy(buf, crypto_str + offset, size);
		memcpy(buf, crypto_str, 100);
	} else
		size = 0;
	create_file();
	return size;
}
*/
