/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "write-full.h"
#include "ssl-init.h"

#ifdef HAVE_OPENSSL

#include <openssl/err.h>
#include <openssl/ssl.h>

/* 2 or 5. Haven't seen their difference explained anywhere, but 2 is the
   default.. */
#define DH_GENERATOR 2

static int dh_param_bitsizes[] = { 512, 1024 };
#define DH_PARAM_BITSIZE_COUNT \
        (sizeof(dh_param_bitsizes)/sizeof(dh_param_bitsizes[0]))

static void generate_dh_parameters(int bitsize, int fd, const char *fname)
{
        DH *dh = DH_generate_parameters(bitsize, DH_GENERATOR, NULL, NULL);
	unsigned char *buf, *p;
	int len;

	len = i2d_DHparams(dh, NULL);
	if (len < 0)
		i_fatal("i2d_DHparams() failed: %lu", ERR_get_error());

	if (len == 0) {
		i_fatal("i2d_DHparams() returned 0 for data from "
			"DH_generate_parameters(bits=%d, generator=%d)",
			bitsize, DH_GENERATOR);
	}

	buf = p = i_malloc(len);
	len = i2d_DHparams(dh, &p);

	if (write_full(fd, &bitsize, sizeof(bitsize)) < 0 ||
	    write_full(fd, &len, sizeof(len)) < 0 ||
	    write_full(fd, buf, len) < 0)
		i_fatal("write_full() failed for file %s: %m", fname);
	i_free(buf);
}

void _ssl_generate_parameters(int fd, const char *fname)
{
	unsigned int i;
	int bits;

	for (i = 0; i < DH_PARAM_BITSIZE_COUNT; i++)
		generate_dh_parameters(dh_param_bitsizes[i], fd, fname);
	bits = 0;
	write_full(fd, &bits, sizeof(bits));
}

#endif
