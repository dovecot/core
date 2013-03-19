/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-ssl.h"
#include "fs-api.h"

#include <stdio.h>

static const struct ssl_iostream_settings ssl_set = {
	.ca_dir = "/etc/ssl/certs" /* FIXME: some parameter to change this? */
};

static const struct fs_settings fs_set = {
	.ssl_client_set = &ssl_set,
	.temp_dir = "/tmp"
};

static void fs_test_file_get(struct fs *fs, const char *path)
{
	struct fs_file *file;
	struct istream *input;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY);
	input = fs_read_stream(file, IO_BLOCK_SIZE);
	while ((ret = i_stream_read_data(input, &data, &size, 0)) > 0) {
		fwrite(data, 1, size, stdout);
		i_stream_skip(input, size);
	}
	i_stream_unref(&input);
	fs_file_deinit(&file);
}

static void
fs_test_file_put(struct fs *fs, const char *src_path, const char *dest_path)
{
	struct fs_file *file;
	struct istream *input;
	struct ostream *output;
	off_t ret;

	if (dest_path == NULL)
		i_fatal("dest path missing");

	file = fs_file_init(fs, dest_path, FS_OPEN_MODE_REPLACE);
	output = fs_write_stream(file);
	input = i_stream_create_file(src_path, IO_BLOCK_SIZE);
	if ((ret = o_stream_send_istream(output, input)) < 0) {
		if (output->stream_errno != 0)
			i_error("write(%s) failed: %m", dest_path);
		else
			i_error("read(%s) failed: %m", src_path);
	} else {
		printf("%"PRIuUOFF_T" bytes written\n", ret);
	}
	i_stream_destroy(&input);
	if (fs_write_stream_finish(file, &output) < 0) {
		i_error("fs_write_stream_finish() failed: %s",
			fs_file_last_error(file));
	}
	fs_file_deinit(&file);
}

static void
fs_test_file_copy(struct fs *fs, const char *src_path, const char *dest_path)
{
	struct fs_file *src_file, *dest_file;

	if (dest_path == NULL)
		i_fatal("dest path missing");

	src_file = fs_file_init(fs, src_path, FS_OPEN_MODE_READONLY);
	dest_file = fs_file_init(fs, dest_path, FS_OPEN_MODE_REPLACE);
	if (fs_copy(src_file, dest_file) < 0) {
		i_error("fs_copy(%s, %s) failed: %s",
			src_path, dest_path, fs_last_error(fs));
	}
	fs_file_deinit(&src_file);
	fs_file_deinit(&dest_file);
}

static void fs_test_file_stat(struct fs *fs, const char *path)
{
	struct fs_file *file;
	struct stat st;

	file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY);
	if (fs_stat(file, &st) < 0) {
		i_error("fs_stat(%s) failed: %s",
			path, fs_file_last_error(file));
	} else {
		printf("%s size=%lld\n", path, (long long)st.st_size);
	}
	fs_file_deinit(&file);
}

static void fs_test_file_delete(struct fs *fs, const char *path)
{
	struct fs_file *file;

	file = fs_file_init(fs, path, FS_OPEN_MODE_READONLY);
	if (fs_delete(file) < 0) {
		i_error("fs_delete(%s) failed: %s",
			path, fs_file_last_error(file));
	}
	fs_file_deinit(&file);
}

static void
fs_test_file_iter(struct fs *fs, const char *path, enum fs_iter_flags flags)
{
	struct fs_iter *iter;
	const char *fname;

	iter = fs_iter_init(fs, path, flags);
	while ((fname = fs_iter_next(iter)) != NULL)
		printf("%s\n", fname);
	if (fs_iter_deinit(&iter) < 0) {
		i_error("fs_iter_deinit(%s) failed: %s",
			path, fs_last_error(fs));
	}
}

int main(int argc, char *argv[])
{
	struct ioloop *ioloop;
	struct fs *fs;
	const char *error;

	lib_init();
	ioloop = io_loop_create();

	if (argc < 5)
		i_fatal("Usage: <driver> <driver args> <cmd> <args>");
	if (fs_init(argv[1], argv[2], &fs_set, &fs, &error) < 0)
		i_fatal("fs_init() failed: %s", error);

	if (strcmp(argv[3], "get") == 0)
		fs_test_file_get(fs, argv[4]);
	else if (strcmp(argv[3], "put") == 0)
		fs_test_file_put(fs, argv[4], argv[5]);
	else if (strcmp(argv[3], "copy") == 0)
		fs_test_file_copy(fs, argv[4], argv[5]);
	else if (strcmp(argv[3], "stat") == 0)
		fs_test_file_stat(fs, argv[4]);
	else if (strcmp(argv[3], "delete") == 0)
		fs_test_file_delete(fs, argv[4]);
	else if (strcmp(argv[3], "iter") == 0)
		fs_test_file_iter(fs, argv[4], 0);
	else if (strcmp(argv[3], "iter-dir") == 0)
		fs_test_file_iter(fs, argv[4], FS_ITER_FLAG_DIRS);
	else
		i_fatal("Unknown command: %s", argv[3]);

	fs_deinit(&fs);
	io_loop_destroy(&ioloop);
	lib_deinit();
	return 0;
}
