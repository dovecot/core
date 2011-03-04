/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "hostpid.h"
#include "randgen.h"
#include "read-full.h"
#include "fs-sis-common.h"
#include "doveadm.h"
#include "doveadm-print.h"

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

/* Files are in <rootdir>/ha/sh/<hash>-<guid>
   They may be hard linked to hashes/<hash>
*/

static const char *sis_get_dir(const char *rootdir, const char *hash)
{
	if (strlen(hash) < 4 || strchr(hash, '/') != NULL)
		i_fatal("Invalid hash in filename: %s", hash);
	return t_strdup_printf("%s/%c%c/%c%c", rootdir,
			       hash[0], hash[1], hash[2], hash[3]);
}

static int
file_contents_equal(const char *path1, const char *path2, ino_t *path2_inode_r)
{
	struct stat st1, st2;
	int fd1, fd2, ret = -1;

	*path2_inode_r = 0;

	/* do a byte-by-byte comparison for the files to find out if they're
	   the same or if this is a hash collision */
	fd1 = open(path1, O_RDONLY);
	if (fd1 == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", path1);
		return -1;
	}
	fd2 = open(path2, O_RDONLY);
	if (fd1 == -1) {
		if (errno != ENOENT)
			i_error("open(%s) failed: %m", path2);
		(void)close(fd1);
		return -1;
	}

	if (fstat(fd1, &st1) < 0)
		i_error("fstat(%s) failed: %m", path1);
	else if (fstat(fd2, &st2) < 0)
		i_error("fstat(%s) failed: %m", path1);
	else if (st1.st_size != st2.st_size)
		ret = 0;
	else {
		/* @UNSAFE: sizes match. compare. */
		unsigned char buf1[IO_BLOCK_SIZE], buf2[IO_BLOCK_SIZE];
		ssize_t ret1;
		int ret2;

		while ((ret1 = read(fd1, buf1, sizeof(buf1))) > 0) {
			if ((ret2 = read_full(fd2, buf2, ret1)) <= 0) {
				if (ret2 < 0)
					i_error("read(%s) failed: %m", path2);
				else
					ret = 0;
				break;
			}
			if (memcmp(buf1, buf2, ret1) != 0) {
				ret = 0;
				break;
			}
		}
		if (ret1 < 0)
			i_error("read(%s) failed: %m", path1);
		else if (ret1 == 0)
			ret = 1;
		*path2_inode_r = st2.st_ino;
	}

	if (close(fd1) < 0)
		i_error("close(%s) failed: %m", path1);
	if (close(fd2) < 0)
		i_error("close(%s) failed: %m", path2);

	return ret;
}

static int
hardlink_replace(const char *src, const char *dest, ino_t src_inode)
{
	const char *p, *destdir, *tmppath;
	unsigned char randbuf[8];
	struct stat st;

	p = strrchr(dest, '/');
	i_assert(p != NULL);
	destdir = t_strdup_until(dest, p);

	random_fill_weak(randbuf, sizeof(randbuf));
	tmppath = t_strdup_printf("%s/temp.%s.%s.%s",
				  destdir, my_hostname, my_pid,
				  binary_to_hex(randbuf, sizeof(randbuf)));
	if (link(src, tmppath) < 0) {
		if (errno == EMLINK)
			return 0;
		i_error("link(%s, %s) failed: %m", src, tmppath);
		return -1;
	}
	if (stat(tmppath, &st) < 0) {
		i_error("stat(%s) failed: %m", tmppath);
		return -1;
	}
	if (st.st_ino != src_inode) {
		if (unlink(tmppath) < 0)
			i_error("unlink(%s) failed: %m", tmppath);
		return 0;
	}
	if (rename(tmppath, dest) < 0) {
		i_error("rename(%s, %s) failed: %m", src, tmppath);
		if (unlink(tmppath) < 0)
			i_error("unlink(%s) failed: %m", tmppath);
		return -1;
	}
	return 1;
}

static int sis_try_deduplicate(const char *rootdir, const char *fname)
{
	const char *p, *hash, *hashdir, *path, *hashes_dir, *hashes_path;
	struct stat st;
	ino_t inode;
	int ret;

	/* fname should be in <hash>-<guid> format */
	p = strchr(fname, '-');
	i_assert(p != NULL);

	hash = t_strdup_until(fname, p);
	hashdir = sis_get_dir(rootdir, hash);
	path = t_strdup_printf("%s/%s", hashdir, fname);

	hashes_dir = t_strconcat(hashdir, "/", HASH_DIR_NAME, NULL);
	hashes_path = t_strconcat(hashes_dir, "/", hash, NULL);
	if (link(path, hashes_path) == 0) {
		/* first file with this hash. we're done */
		return 0;
	}
	if (errno == ENOENT) {
		/* either path was already deleted or hashes dir
		   doesn't exist */
		if (mkdir(hashes_dir, 0700) < 0) {
			if (errno == EEXIST)
				return 0;
			i_error("mkdir(%s) failed: %m", hashes_dir);
			return -1;
		}
		/* try again */
		if (link(path, hashes_path) == 0 || errno == ENOENT)
			return 0;
	}
	if (errno != EEXIST) {
		i_error("link(%s, %s) failed: %m", path, hashes_path);
		return -1;
	}

	/* need to do a byte-by-byte comparison. but check first if someone
	   else already had deduplicated the file. */
	if (stat(path, &st) < 0) {
		if (errno == ENOENT) {
			/* just got deleted */
			return 0;
		}
		i_error("stat(%s) failed: %m", path);
		return -1;
	}
	if (st.st_nlink > 1) {
		/* already deduplicated */
		return 0;
	}

	ret = file_contents_equal(path, hashes_path, &inode);
	if (ret < 0) {
		if (errno == ENOENT) {
			/* either path or hashes_path was deleted. */
			return sis_try_deduplicate(rootdir, fname);
		}
		return -1;
	}
	if (ret > 0) {
		/* equal, replace with hard link */
		ret = hardlink_replace(hashes_path, path, inode);
		if (ret > 0)
			return 0;
		else if (ret < 0)
			return -1;
		/* too many hard links or inode changed */
	}

	/* replace hashes link with this  */
	return hardlink_replace(path, hashes_path, st.st_ino) < 0 ? -1 : 0;
}

static void cmd_sis_deduplicate(int argc, char *argv[])
{
	const char *rootdir, *queuedir;
	DIR *dir;
	struct dirent *d;
	struct stat st, first_st;
	string_t *path;
	unsigned int dir_len;
	int ret;

	if (argc < 3)
		help(&doveadm_cmd_sis_deduplicate);

	/* go through the filenames in the queue dir and see if
	   we can deduplicate them. */
	rootdir = argv[1];
	queuedir = argv[2];

	if (stat(rootdir, &st) < 0)
		i_fatal("stat(%s) failed: %m", rootdir);

	path = t_str_new(256);
	str_append(path, queuedir);
	str_append_c(path, '/');
	dir_len = str_len(path);

	dir = opendir(queuedir);
	if (dir == NULL)
		i_fatal("opendir(%s) failed: %m", queuedir);

	first_st.st_size = -1;
	while ((d = readdir(dir)) != NULL) {
		if (d->d_name[0] == '.')
			continue;

		str_truncate(path, dir_len);
		str_append(path, d->d_name);

		if (first_st.st_size < 0) {
			if (stat(str_c(path), &first_st) < 0)
				i_fatal("stat(%s) failed: %m", str_c(path));
		}
		if (strchr(d->d_name, '-') == NULL || first_st.st_size != 0) {
			i_fatal("%s is not a valid sis-queue file, "
				"is the queue directory correct?",
				str_c(path));
		}

		T_BEGIN {
			ret = sis_try_deduplicate(rootdir, d->d_name);
		} T_END;
		if (ret == 0) {
			if (unlink(str_c(path)) < 0)
				i_error("unlink(%s) failed: %m", str_c(path));
		}
	}
	if (closedir(dir) < 0)
		i_error("closedir(%s) failed: %m", queuedir);
}

static void cmd_sis_find(int argc, char *argv[])
{
	const char *rootdir, *path, *hash;
	DIR *dir;
	struct dirent *d;
	struct stat st;
	string_t *str;
	unsigned int dir_len, hash_len;

	if (argc < 3 || strlen(argv[2]) < 4)
		help(&doveadm_cmd_sis_find);

	rootdir = argv[1];
	if (stat(rootdir, &st) < 0) {
		if (errno == ENOENT)
			i_fatal("Attachment dir doesn't exist: %s", rootdir);
		i_fatal("stat(%s) failed: %m", rootdir);
	}
	hash = argv[2];
	hash_len = strlen(hash);

	path = sis_get_dir(rootdir, hash);
	str = t_str_new(256);
	str_append(str, path);
	str_append_c(str, '/');
	dir_len = str_len(str);

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT)
			return;
		i_fatal("opendir(%s) failed: %m", path);
	}

	doveadm_print_init(DOVEADM_PRINT_TYPE_FLOW);
	doveadm_print_header("path", "path",
			     DOVEADM_PRINT_HEADER_FLAG_HIDE_TITLE);
	while ((d = readdir(dir)) != NULL) {
		if (strncmp(d->d_name, hash, hash_len) == 0) {
			str_truncate(str, dir_len);
			str_append(str, d->d_name);
			doveadm_print(str_c(str));
		}
	}
	if (closedir(dir) < 0)
		i_error("closedir(%s) failed: %m", path);
}

struct doveadm_cmd doveadm_cmd_sis_deduplicate = {
	cmd_sis_deduplicate, "sis deduplicate", "<root dir> <queue dir>"
};
struct doveadm_cmd doveadm_cmd_sis_find = {
	cmd_sis_find, "sis find", "<root dir> <hash>"
};
