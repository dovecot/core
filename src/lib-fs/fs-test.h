#ifndef FS_TEST_H
#define FS_TEST_H

#include "fs-api-private.h"

struct test_fs {
	struct fs fs;
	enum fs_properties properties;
	ARRAY_TYPE(const_string) iter_files;
};

struct test_fs_file {
	struct fs_file file;
	enum fs_open_mode mode;

	fs_file_async_callback_t *async_callback;
	void *async_context;

	buffer_t *contents;
	struct istream *input;

	bool prefetched;
	bool locked;
	bool exists;
	bool seekable;
	bool closed;
};

struct test_fs_iter {
	struct fs_iter iter;
	char *prefix, *prev_dir;
	unsigned int prefix_len, idx;
	bool failed;
};

struct test_fs_file *test_fs_file_get(struct fs *fs, unsigned int n);

#endif
