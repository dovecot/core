/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "istream.h"

static void test_istream_children(void)
{
	struct istream *parent, *child1, *child2;
	const unsigned char *data;
	size_t size;

	test_begin("istream children");

	parent = test_istream_create_data("123456789", 9);
	test_istream_set_max_buffer_size(parent, 3);

	child1 = i_stream_create_limit(parent, (uoff_t)-1);
	child2 = i_stream_create_limit(parent, (uoff_t)-1);

	/* child1 read beginning */
	test_assert(i_stream_read(child1) == 3);
	data = i_stream_get_data(child1, &size);
	test_assert(size == 3 && memcmp(data, "123", 3) == 0);
	i_stream_skip(child1, 3);
	/* child1 read middle.. */
	test_assert(i_stream_read(child1) == 3);
	data = i_stream_get_data(child1, &size);
	test_assert(size == 3 && memcmp(data, "456", 3) == 0);
	/* child2 read beginning.. */
	test_assert(i_stream_read(child2) == 3);
	data = i_stream_get_data(child2, &size);
	test_assert(size == 3 && memcmp(data, "123", 3) == 0);
	/* child1 check middle again.. the parent has been modified,
	   so it can't return the original data (without some code changes). */
	test_assert(i_stream_get_data_size(child1) == 0);
	i_stream_skip(child1, 3);
	/* child1 read end */
	test_assert(i_stream_read(child1) == 3);
	data = i_stream_get_data(child1, &size);
	test_assert(size == 3 && memcmp(data, "789", 3) == 0);
	i_stream_skip(child1, 3);
	test_assert(i_stream_read(child1) == -1);
	/* child2 check beginning again.. */
	test_assert(i_stream_get_data_size(child1) == 0);
	i_stream_skip(child2, 3);
	/* child2 read middle */
	test_assert(i_stream_read(child2) == 3);
	data = i_stream_get_data(child2, &size);
	test_assert(size == 3 && memcmp(data, "456", 3) == 0);
	i_stream_skip(child2, 3);

	i_stream_destroy(&child1);
	i_stream_destroy(&child2);
	i_stream_destroy(&parent);

	test_end();
}

void test_istream(void)
{
	test_istream_children();
}
