/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

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

static void cmd_sis_find(struct doveadm_cmd_context *cctx)
{
	const char *rootdir, *path, *hash;
	DIR *dir;
	struct dirent *d;
	struct stat st;
	string_t *str;
	size_t dir_len, hash_len;

	if (!doveadm_cmd_param_str(cctx, "root-dir", &rootdir) ||
	    !doveadm_cmd_param_str(cctx, "hash", &hash) ||
	    strlen(hash) < 4)
		help_ver2(&doveadm_cmd_sis_find);

	if (stat(rootdir, &st) < 0) {
		if (errno == ENOENT)
			i_fatal("Attachment dir doesn't exist: %s", rootdir);
		i_fatal("stat(%s) failed: %m", rootdir);
	}
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
		e_error(cctx->event, "closedir(%s) failed: %m", path);
}

struct doveadm_cmd_ver2 doveadm_cmd_sis_find = {
	.name = "sis find",
	.cmd = cmd_sis_find,
	.usage = "<root dir> <hash>",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('\0', "root-dir", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAM('\0', "hash", CMD_PARAM_STR, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
