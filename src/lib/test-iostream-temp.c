/* Copyright (c) 2016-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "ostream.h"
#include "iostream-temp.h"

static void test_iostream_temp_create_sized_memory(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() memory");
	output = iostream_temp_create_sized(".intentional-nonexistent-error/", 0, "test", 4);
	test_assert(o_stream_send(output, "123", 3) == 3);
	test_assert(o_stream_send(output, "4", 1) == 1);
	test_assert(o_stream_get_fd(output) == -1);

	/* now we'll try to switch to writing to a file, but it'll fail */
	test_expect_errors(1);
	test_assert(o_stream_send(output, "5", 1) == 1);
	test_expect_no_more_errors();

	test_assert(o_stream_get_fd(output) == -1);
	o_stream_destroy(&output);
	test_end();
}

static void test_iostream_temp_create_sized_disk(void)
{
	struct ostream *output;

	test_begin("iostream_temp_create_sized() disk");
	output = iostream_temp_create_sized(".", 0, "test", 4);
	test_assert(o_stream_send(output, "123", 3) == 3);
	test_assert(o_stream_send(output, "4", 1) == 1);
	test_assert(o_stream_get_fd(output) == -1);
	test_assert(o_stream_send(output, "5", 1) == 1);
	test_assert(o_stream_get_fd(output) != -1);
	o_stream_destroy(&output);
	test_end();
}

void test_iostream_temp(void)
{
	test_iostream_temp_create_sized_memory();
	test_iostream_temp_create_sized_disk();
}
