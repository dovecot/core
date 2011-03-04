/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "write-full.h"
#include "ssl-params.h"

#ifdef HAVE_OPENSSL

#include <openssl/err.h>
#include <openssl/ssl.h>

/* 2 or 5. Haven't seen their difference explained anywhere, but 2 is the
   default.. */
#define DH_GENERATOR 2

static int dh_param_bitsizes[] = { 512, 1024 };

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

static void generate_dh_parameters(int bitsize, int fd, const char *fname)
{
        DH *dh = DH_generate_parameters(bitsize, DH_GENERATOR, NULL, NULL);
	unsigned char *buf, *p;
	int len;

	if (dh == NULL) {
		i_fatal("DH_generate_parameters(bits=%d, gen=%d) failed: %s",
			bitsize, DH_GENERATOR, ssl_last_error());
	}

	len = i2d_DHparams(dh, NULL);
	if (len < 0)
		i_fatal("i2d_DHparams() failed: %s", ssl_last_error());

	buf = p = i_malloc(len);
	len = i2d_DHparams(dh, &p);

	if (write_full(fd, &bitsize, sizeof(bitsize)) < 0 ||
	    write_full(fd, &len, sizeof(len)) < 0 ||
	    write_full(fd, buf, len) < 0)
		i_fatal("write_full() failed for file %s: %m", fname);
	i_free(buf);
}

void ssl_generate_parameters(int fd, const char *fname)
{
	unsigned int i;
	int bits;

	for (i = 0; i < N_ELEMENTS(dh_param_bitsizes); i++)
		generate_dh_parameters(dh_param_bitsizes[i], fd, fname);
	bits = 0;
	if (write_full(fd, &bits, sizeof(bits)) < 0)
		i_fatal("write_full() failed for file %s: %m", fname);
}

#endif
