/*
 randgen.c : Random generator

    Copyright (c) 2002 Timo Sirainen

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
    OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
    IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
    CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
    SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "lib.h"
#include "randgen.h"

#ifdef HAVE_DEV_URANDOM

#include "fd-close-on-exec.h"
#include <unistd.h>
#include <fcntl.h>

static int init_refcount = 0;
static int urandom_fd;

void random_fill(void *buf, size_t size)
{
	size_t pos;
	ssize_t ret;

	i_assert(init_refcount > 0);
	i_assert(size < SSIZE_T_MAX);

	for (pos = 0; pos < size; pos += ret) {
		ret = read(urandom_fd, (char *) buf + pos, size - pos);
		if (ret < 0 && errno != EINTR)
			i_fatal("Error reading from /dev/urandom: %m");
	}
}

void random_init(void)
{
	if (init_refcount++ > 0)
		return;

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd == -1) {
		if (errno == ENOENT) {
			i_fatal("/dev/urandom doesn't exist, "
				"currently we require it");
		} else {
			i_fatal("Can't open /dev/urandom: %m");
		}
	}

	fd_close_on_exec(urandom_fd, TRUE);
}

void random_deinit(void)
{
	if (--init_refcount > 0)
		return;

	(void)close(urandom_fd);
	urandom_fd = -1;
}

#elif defined(HAVE_OPENSSL_RAND_H)
#include <openssl/rand.h>
#include <openssl/err.h>

static const char *ssl_last_error(void)
{
	unsigned long err;
	char *buf;
	size_t err_size = 256;

	err = ERR_get_error();
	if (err == 0)
		return strerror(errno);

	buf = t_malloc(err_size);
	buf[err_size-1] = '\0';
	ERR_error_string_n(err, buf, err_size-1);
	return buf;
}

void random_fill(void *buf, size_t size)
{
	if (RAND_bytes(buf, size) != 1)
		i_fatal("RAND_pseudo_bytes() failed: %s", ssl_last_error());
}

void random_init(void) {}
void random_deinit(void) {}

#else
#  error No random number generator, use eg. OpenSSL.
#endif
