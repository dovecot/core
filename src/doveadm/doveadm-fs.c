/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "fs-api.h"
#include "doveadm.h"

#include <stdio.h>

static void fs_cmd_help(doveadm_command_t *cmd);

static struct fs *
cmd_fs_init(int *argc, char **argv[], int own_arg_count, doveadm_command_t *cmd)
{
	struct ssl_iostream_settings ssl_set;
	struct fs_settings fs_set;
	struct fs *fs;
	const char *error;

	if (*argc != 3 + own_arg_count)
		fs_cmd_help(cmd);

	memset(&ssl_set, 0, sizeof(ssl_set));
	ssl_set.ca_dir = doveadm_settings->ssl_client_ca_dir;
	ssl_set.ca_file = doveadm_settings->ssl_client_ca_file;
	ssl_set.verbose = doveadm_debug;

	memset(&fs_set, 0, sizeof(fs_set));
	fs_set.ssl_client_set = &ssl_set;
	fs_set.temp_dir = "/tmp";
	fs_set.base_dir = doveadm_settings->base_dir;
	fs_set.debug = doveadm_debug;

	if (fs_init((*argv)[1], (*argv)[2], &fs_set, &fs, &error) < 0)
		i_fatal("fs_init() failed: %s", error);

	*argc += 3;
	*argv += 3;
	return fs;
}

static void cmd_fs_get(int argc, char *argv[])
{
	struct fs *fs;
	struct fs_file *file;
	struct istream *input;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	fs = cmd_fs_init(&argc, &argv, 1, cmd_fs_get);

	file = fs_file_init(fs, argv[0], FS_OPEN_MODE_READONLY);
	input = fs_read_stream(file, IO_BLOCK_SIZE);
	while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0) {
		fwrite(data, 1, size, stdout);
		i_stream_skip(input, size);
	}
	i_assert(ret == -1);
	if (input->stream_errno == ENOENT) {
		i_error("%s doesn't exist", fs_file_path(file));
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else if (input->stream_errno != 0) {
		i_error("read(%s) failed: %m", fs_file_path(file));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	i_stream_unref(&input);
	fs_file_deinit(&file);
	fs_deinit(&fs);
}

static void cmd_fs_put(int argc, char *argv[])
{
	struct fs *fs;
	const char *src_path, *dest_path;
	struct fs_file *file;
	struct istream *input;
	struct ostream *output;
	off_t ret;

	fs = cmd_fs_init(&argc, &argv, 2, cmd_fs_put);
	src_path = argv[0];
	dest_path = argv[1];

	file = fs_file_init(fs, dest_path, FS_OPEN_MODE_REPLACE);
	output = fs_write_stream(file);
	input = i_stream_create_file(src_path, IO_BLOCK_SIZE);
	if ((ret = o_stream_send_istream(output, input)) < 0) {
		if (output->stream_errno != 0)
			i_error("write(%s) failed: %m", dest_path);
		else
			i_error("read(%s) failed: %m", src_path);
		doveadm_exit_code = EX_TEMPFAIL;
	}
	i_stream_destroy(&input);
	if (fs_write_stream_finish(file, &output) < 0) {
		i_error("fs_write_stream_finish() failed: %s",
			fs_file_last_error(file));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	fs_file_deinit(&file);
	fs_deinit(&fs);
}

static void cmd_fs_copy(int argc, char *argv[])
{
	struct fs *fs;
	struct fs_file *src_file, *dest_file;
	const char *src_path, *dest_path;

	fs = cmd_fs_init(&argc, &argv, 2, cmd_fs_copy);
	src_path = argv[0];
	dest_path = argv[1];

	src_file = fs_file_init(fs, src_path, FS_OPEN_MODE_READONLY);
	dest_file = fs_file_init(fs, dest_path, FS_OPEN_MODE_REPLACE);
	if (fs_copy(src_file, dest_file) == 0) ;
	else if (errno == ENOENT) {
		i_error("%s doesn't exist", src_path);
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else {
		i_error("fs_copy(%s, %s) failed: %s",
			src_path, dest_path, fs_last_error(fs));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	fs_file_deinit(&src_file);
	fs_file_deinit(&dest_file);
	fs_deinit(&fs);
}

static void cmd_fs_stat(int argc, char *argv[])
{
	struct fs *fs;
	struct fs_file *file;
	struct stat st;

	fs = cmd_fs_init(&argc, &argv, 1, cmd_fs_stat);

	file = fs_file_init(fs, argv[0], FS_OPEN_MODE_READONLY);
	if (fs_stat(file, &st) == 0) {
		printf("%s size=%lld\n", fs_file_path(file),
		       (long long)st.st_size);
	} else if (errno == ENOENT) {
		i_error("%s doesn't exist", fs_file_path(file));
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else {
		i_error("fs_stat(%s) failed: %s",
			fs_file_path(file), fs_file_last_error(file));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	fs_file_deinit(&file);
	fs_deinit(&fs);
}

static void cmd_fs_delete(int argc, char *argv[])
{
	struct fs *fs;
	struct fs_file *file;

	fs = cmd_fs_init(&argc, &argv, 1, cmd_fs_delete);

	file = fs_file_init(fs, argv[0], FS_OPEN_MODE_READONLY);
	if (fs_delete(file) == 0)
		;
	else if (errno == ENOENT) {
		i_error("%s doesn't exist", fs_file_path(file));
		doveadm_exit_code = DOVEADM_EX_NOTFOUND;
	} else {
		i_error("fs_delete(%s) failed: %s",
			fs_file_path(file), fs_file_last_error(file));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	fs_file_deinit(&file);
	fs_deinit(&fs);
}

static void cmd_fs_iter_full(int argc, char *argv[], enum fs_iter_flags flags,
			     doveadm_command_t *cmd)
{
	struct fs *fs;
	struct fs_iter *iter;
	const char *fname;

	fs = cmd_fs_init(&argc, &argv, 1, cmd);

	iter = fs_iter_init(fs, argv[0], flags);
	while ((fname = fs_iter_next(iter)) != NULL)
		printf("%s\n", fname);
	if (fs_iter_deinit(&iter) < 0) {
		i_error("fs_iter_deinit(%s) failed: %s",
			argv[0], fs_last_error(fs));
		doveadm_exit_code = EX_TEMPFAIL;
	}
	fs_deinit(&fs);
}

static void cmd_fs_iter(int argc, char *argv[])
{
	cmd_fs_iter_full(argc, argv, 0, cmd_fs_iter);
}

static void cmd_fs_iter_dirs(int argc, char *argv[])
{
	cmd_fs_iter_full(argc, argv, FS_ITER_FLAG_DIRS, cmd_fs_iter_dirs);
}

struct doveadm_cmd doveadm_cmd_fs[] = {
	{ cmd_fs_get, "fs get", "<fs-driver> <fs-args> <path>" },
	{ cmd_fs_put, "fs put", "<fs-driver> <fs-args> <input path> <path>" },
	{ cmd_fs_copy, "fs copy", "<fs-driver> <fs-args> <source path> <dest path>" },
	{ cmd_fs_stat, "fs stat", "<fs-driver> <fs-args> <path>" },
	{ cmd_fs_delete, "fs delete", "<fs-driver> <fs-args> <path>" },
	{ cmd_fs_iter, "fs iter", "<fs-driver> <fs-args> <path>" },
	{ cmd_fs_iter_dirs, "fs iter-dirs", "<fs-driver> <fs-args> <path>" },
};

static void fs_cmd_help(doveadm_command_t *cmd)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_fs); i++) {
		if (doveadm_cmd_fs[i].cmd == cmd)
			help(&doveadm_cmd_fs[i]);
	}
	i_unreached();
}

void doveadm_register_fs_commands(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(doveadm_cmd_fs); i++)
		doveadm_register_cmd(&doveadm_cmd_fs[i]);
}
