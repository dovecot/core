/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "safe-mkstemp.h"
#include "randgen.h"
#include "ostream.h"

#include <stdlib.h>
#include <unistd.h>

#define MAX_BUFSIZE 256

static void test_ostream_file_random(void)
{
	struct ostream *output;
	string_t *path = t_str_new(128);
	char buf[MAX_BUFSIZE*4], buf2[MAX_BUFSIZE*4], randbuf[MAX_BUFSIZE];
	unsigned int i, offset, size;
	ssize_t ret;
	int fd;

	memset(buf, 0, sizeof(buf));
	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1)
		i_fatal("safe_mkstemp(%s) failed: %m", str_c(path));
	if (unlink(str_c(path)) < 0)
		i_fatal("unlink(%s) failed: %m", str_c(path));
	output = o_stream_create_fd(fd, MAX_BUFSIZE, FALSE);
	o_stream_cork(output);

	size = (rand() % MAX_BUFSIZE) + 1;
	random_fill_weak(randbuf, size);
	memcpy(buf, randbuf, size);
	o_stream_send(output, buf, size);

	for (i = 0; i < 10; i++) {
		offset = rand() % (MAX_BUFSIZE*3);
		size = (rand() % MAX_BUFSIZE) + 1;
		random_fill_weak(randbuf, size);
		memcpy(buf + offset, randbuf, size);
		o_stream_pwrite(output, randbuf, size, offset);
		if (rand() % 10 == 0)
			o_stream_flush(output);
	}

	o_stream_flush(output);
	o_stream_uncork(output);
	ret = pread(fd, buf2, sizeof(buf2), 0);
	if (ret < 0)
		i_fatal("pread() failed: %m");
	else {
		i_assert(ret > 0);
		test_assert(memcmp(buf, buf2, ret) == 0);
	}
	o_stream_unref(&output);
	(void)close(fd);
}

void test_ostream_file(void)
{
	unsigned int i;

	test_begin("ostream pwrite random");
	for (i = 0; i < 100; i++) T_BEGIN {
		test_ostream_file_random();
	} T_END;
	test_end();
}
