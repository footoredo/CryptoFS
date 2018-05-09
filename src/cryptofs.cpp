/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
  gcc -Wall crypto.c `pkg-config fuse --cflags --libs` -o crypto
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

static const char *crypto_str = "Hello World!\n";
static const char *crypto_path = "/crypto";

static int crypto_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

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

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, crypto_path + 1, NULL, 0);

	return 0;
}

static int crypto_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, crypto_path) != 0)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int crypto_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;
	if(strcmp(path, crypto_path) != 0)
		return -ENOENT;

	len = strlen(crypto_str);
	if (offset < (signed)len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, crypto_str + offset, size);
	} else
		size = 0;

	return size;
}

static struct fuse_operations crypto_oper;

int main(int argc, char *argv[])
{
	crypto_oper.getattr	= crypto_getattr;
	crypto_oper.readdir	= crypto_readdir;
	crypto_oper.open		= crypto_open;
	crypto_oper.read		= crypto_read;
	return fuse_main(argc, argv, &crypto_oper, NULL);
}
