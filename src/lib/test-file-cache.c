/* Copyright (c) 2020 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"
#include "ostream.h"
#include "file-cache.h"

#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define TEST_FILENAME ".test_file_cache"

static void test_file_cache_read(void)
{
	test_begin("file_cache_read");

	/* create a file */
	struct ostream *os = o_stream_create_file(TEST_FILENAME, 0, 0600, 0);
	o_stream_nsend_str(os, "initial data\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_destroy(&os);

	int fd = open(TEST_FILENAME, O_RDONLY);
	i_assert(fd > -1);
	struct file_cache *cache = file_cache_new_path(fd, TEST_FILENAME);

	/* this should be 0 before read */
	size_t size;
	const char *map = file_cache_get_map(cache, &size);
	test_assert(size == 0);

	test_assert(file_cache_read(cache, 0, 13) == 13);
	map = file_cache_get_map(cache, &size);
	test_assert(size == 13);
	test_assert_strcmp(map, "initial data\n");

	file_cache_free(&cache);
	i_close_fd(&fd);
	i_unlink(TEST_FILENAME);

	test_end();
}

static void test_file_cache_write_read(void)
{
	test_begin("file_cache_write_read");

	/* create a file */
	struct ostream *os = o_stream_create_file(TEST_FILENAME, 0, 0600, 0);
	o_stream_nsend_str(os, "initial data\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_destroy(&os);

	int fd = open(TEST_FILENAME, O_RDONLY);
	i_assert(fd > -1);
	struct file_cache *cache = file_cache_new_path(fd, TEST_FILENAME);

	/* this should be 0 before read */
	size_t size;
	const char *map = file_cache_get_map(cache, &size);
	test_assert(size == 0);
	test_assert(file_cache_read(cache, 0, 13) == 13);
	file_cache_write(cache, "updated data\n", 13, 0);
	map = file_cache_get_map(cache, &size);
	test_assert_strcmp(map, "updated data\n");
	file_cache_free(&cache);
	i_close_fd(&fd);

	struct istream *is = i_stream_create_file(TEST_FILENAME, (size_t)-1);
	const unsigned char *data;
	test_assert(i_stream_read_more(is, &data, &size) > 0 && size == 13);
	test_assert(memcmp(data, "initial data\n", 13) == 0);
	i_stream_destroy(&is);
	i_unlink(TEST_FILENAME);

	test_end();
}

static void test_file_cache_read_invalidate(void)
{
	test_begin("file_cache_read_invalidate");

	/* create a file */
	struct ostream *os = o_stream_create_file(TEST_FILENAME, 0, 0600, 0);
	o_stream_nsend_str(os, "initial data\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_destroy(&os);

	int fd = open(TEST_FILENAME, O_RDONLY);
	i_assert(fd > -1);
	struct file_cache *cache = file_cache_new_path(fd, TEST_FILENAME);

	/* this should be 0 before read */
	size_t size;
	test_assert(file_cache_read(cache, 0, 13) == 13);
	const char *map = file_cache_get_map(cache, &size);
	test_assert_strcmp(map, "initial data\n");

	/* update file */
	os = o_stream_create_file(TEST_FILENAME, 0, 0600, 0);
	o_stream_nsend_str(os, "updated data\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_destroy(&os);

	map = file_cache_get_map(cache, &size);
	test_assert_strcmp(map, "initial data\n");

	/* invalidate cache */
	file_cache_invalidate(cache, 0, size);
	test_assert(file_cache_read(cache, 0, 13) == 13);
	map = file_cache_get_map(cache, &size);
	test_assert(size == 13);
	test_assert_strcmp(map, "updated data\n");
	file_cache_free(&cache);
	i_close_fd(&fd);
	i_unlink(TEST_FILENAME);

	test_end();
}

static void test_file_cache_multipage(void)
{
	test_begin("file_cache_multipage");

	size_t page_size = getpagesize();
	struct ostream *os = o_stream_create_file(TEST_FILENAME, 0, 0600, 0);
	size_t total_size = 0;
	for (size_t i = 0; i < page_size * 3 + 100; i += 12) {
		o_stream_nsend_str(os, "initial data");
		total_size += 12;
	}
	test_assert(o_stream_finish(os) == 1);
	o_stream_destroy(&os);

	int fd = open(TEST_FILENAME, O_RDONLY);
	i_assert(fd > -1);
	struct file_cache *cache = file_cache_new_path(fd, TEST_FILENAME);

	/* read everything to memory page at a time */
	test_assert(file_cache_read(cache, 0, page_size) == (ssize_t)page_size);
	test_assert(file_cache_read(cache, page_size, page_size) ==
		    (ssize_t)page_size);
	test_assert(file_cache_read(cache, page_size*2, page_size) ==
		    (ssize_t)page_size);
	test_assert(file_cache_read(cache, page_size*3, page_size) ==
		    (ssize_t)total_size-(ssize_t)page_size*3);

	size_t size;
	const char *map = file_cache_get_map(cache, &size);
	test_assert(size == total_size);
	test_assert(map != NULL);

	/* write-read-invalidate-read */
	for(size_t i = 0; i < page_size * 3; i+= page_size / 3) {
		char orig[13];
		const char *ptr = CONST_PTR_OFFSET(map, i);
		memcpy(orig, ptr, 12);
		orig[12] = '\0';
		file_cache_write(cache, "updated data", 12, i);
		map = file_cache_get_map(cache, &size);
		ptr = CONST_PTR_OFFSET(map, i);
		test_assert(strncmp(ptr, "updated data", 12) == 0);
		/* invalidate cache */
		file_cache_invalidate(cache, i, 12);
		/* check that it's back what it was */
		test_assert(file_cache_read(cache, i, 12) == 12);
		map = file_cache_get_map(cache, &size);
		ptr = CONST_PTR_OFFSET(map, i);
		test_assert(strncmp(ptr, orig, 12) == 0);
	}

	file_cache_free(&cache);
	i_close_fd(&fd);
	i_unlink(TEST_FILENAME);
	test_end();
}

static void test_file_cache_anon(void)
{
	/* file-cache should work as anonymous cache for small files */
	test_begin("file_cache_anon");
	test_assert(access(TEST_FILENAME, F_OK) == -1 && errno == ENOENT);
	struct file_cache *cache = file_cache_new_path(-1, TEST_FILENAME);

	test_assert(file_cache_set_size(cache, 1024) == 0);
	file_cache_write(cache, "initial data", 12, 0);

	size_t size;
	const char *map = file_cache_get_map(cache, &size);
	test_assert(size == 12);
	test_assert(map != NULL);
	test_assert_strcmp(map, "initial data");

	file_cache_free(&cache);
	i_unlink_if_exists(TEST_FILENAME);
	test_end();
}

static void test_file_cache_switch_fd(void)
{
	test_begin("file_cache_switch_fd");
	test_assert(access(TEST_FILENAME, F_OK) == -1 && errno == ENOENT);
	struct file_cache *cache = file_cache_new_path(-1, TEST_FILENAME);

	test_assert(file_cache_set_size(cache, 13) == 0);
	file_cache_write(cache, "initial data\n", 13, 0);

	/* create a file */
	struct ostream *os = o_stream_create_file(TEST_FILENAME, 0, 0600, 0);
	o_stream_nsend_str(os, "updated data\n");
	test_assert(o_stream_finish(os) == 1);
	o_stream_destroy(&os);

	int fd = open(TEST_FILENAME, O_RDONLY);
	i_assert(fd > -1);
	/* map should be invalidated and updated data read
	   from given file */
	file_cache_set_fd(cache, fd);
	test_assert(file_cache_read(cache, 0, 13) == 13);
	size_t size;
	const char *map = file_cache_get_map(cache, &size);
	test_assert(size == 13);
	test_assert(map != NULL);
	test_assert_strcmp(map, "updated data\n");

	file_cache_free(&cache);
	i_close_fd(&fd);
	i_unlink(TEST_FILENAME);
	test_end();
}

static void test_file_cache_errors(void)
{
	test_begin("file_cache_errors");

	size_t page_size = getpagesize();

	test_assert(access(TEST_FILENAME, F_OK) == -1 && errno == ENOENT);
	int fd = open(TEST_FILENAME, O_RDONLY);
	struct file_cache *cache = file_cache_new_path(fd, TEST_FILENAME);
	size_t size;

	/* file does not exist and we try large enough mapping */
	test_expect_error_string("fstat(.test_file_cache) failed: "
				 "Bad file descriptor");
	test_assert(file_cache_read(cache, 0, 2*1024*1024) == -1);
	const char *map = file_cache_get_map(cache, &size);
	test_assert(size == 0);
	test_assert(map == NULL);

	/* temporarily set a small memory limit to make mmap attempt fail */
	struct rlimit rl_cur;
	test_assert(getrlimit(RLIMIT_AS, &rl_cur) == 0);
	struct rlimit rl_new = {
		.rlim_cur = 1,
		.rlim_max = rl_cur.rlim_max
	};
	const char *errstr =
		t_strdup_printf("mmap_anon(.test_file_cache, %zu) failed: "
				"Cannot allocate memory", page_size);
	test_assert(setrlimit(RLIMIT_AS, &rl_new) == 0);
	test_expect_error_string(errstr);
	test_assert(file_cache_set_size(cache, 1024) == -1);
	test_assert(setrlimit(RLIMIT_AS, &rl_cur) == 0);

	/* same for mremap */
	errstr = t_strdup_printf("mremap_anon(.test_file_cache, %zu) failed: "
				 "Cannot allocate memory", page_size*2);
	test_assert(file_cache_set_size(cache, 1) == 0);
	test_assert(setrlimit(RLIMIT_AS, &rl_new) == 0);
	test_expect_error_string(errstr);
	test_assert(file_cache_set_size(cache, page_size*2) == -1);
	test_assert(setrlimit(RLIMIT_AS, &rl_cur) == 0);

	file_cache_free(&cache);
	i_close_fd(&fd);
	i_unlink_if_exists(TEST_FILENAME);
	test_end();
}

void test_file_cache(void)
{
	test_file_cache_read();
	test_file_cache_write_read();
	test_file_cache_read_invalidate();
	test_file_cache_multipage();
	test_file_cache_anon();
	test_file_cache_switch_fd();
	test_file_cache_errors();
}
