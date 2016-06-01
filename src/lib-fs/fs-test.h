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
	struct test_fs_file *copy_src;

	bool prefetched;
	bool locked;
	bool exists;
	bool seekable;
	bool closed;
	bool io_failure;
	bool wait_async;
};

struct test_fs_iter {
	struct fs_iter iter;
	char *prefix, *prev_dir;
	unsigned int prefix_len, idx;
	bool failed;
};

struct test_fs *test_fs_get(struct fs *fs);
struct test_fs_file *test_fs_file_get(struct fs *fs, const char *path);

void test_fs_async(const char *test_name, enum fs_properties properties,
		   const char *driver, const char *args);

#endif
