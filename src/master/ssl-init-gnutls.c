/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "write-full.h"
#include "ssl-init.h"

#ifdef HAVE_GNUTLS

#include <stdlib.h>
#include <gnutls/gnutls.h>

static int prime_nums[] = { 768, 1024, 0 };

static void write_datum(int fd, const char *fname, gnutls_datum *dbits)
{
	if (write_full(fd, &dbits->size, sizeof(dbits->size)) < 0)
		i_fatal("write_full() failed for file %s: %m", fname);

	if (write_full(fd, dbits->data, dbits->size) < 0)
		i_fatal("write_full() failed for file %s: %m", fname);
}

static void generate_dh_parameters(int fd, const char *fname)
{
	gnutls_datum dbits, prime, generator;
	int ret, bits, i;

	dbits.size = sizeof(bits);
	dbits.data = (unsigned char *) &bits;

	for (i = 0; prime_nums[i] != 0; i++) {
		bits = prime_nums[i];

		ret = gnutls_dh_params_generate(&prime, &generator, bits);
		if (ret < 0) {
			i_fatal("gnutls_dh_params_generate(%d) failed: %s",
				bits, gnutls_strerror(ret));
		}

		write_datum(fd, fname, &dbits);
		write_datum(fd, fname, &prime);
		write_datum(fd, fname, &generator);

		free(prime.data);
		free(generator.data);
	}

	bits = 0;
	write_datum(fd, fname, &dbits);
}

static void generate_rsa_parameters(int fd, const char *fname)
{
	gnutls_datum m, e, d, p, q, u;
	int ret;

        ret = gnutls_rsa_params_generate(&m, &e, &d, &p, &q, &u, 512);
	if (ret < 0) {
		i_fatal("gnutls_rsa_params_generate() faile: %s",
			strerror(ret));
	}

	write_datum(fd, fname, &m);
	write_datum(fd, fname, &e);
	write_datum(fd, fname, &d);
	write_datum(fd, fname, &p);
	write_datum(fd, fname, &q);
	write_datum(fd, fname, &u);
}

void ssl_generate_parameters(int fd, const char *fname)
{
	int ret;

	if ((ret = gnutls_global_init() < 0)) {
		i_fatal("gnu_tls_global_init() failed: %s",
			gnutls_strerror(ret));
	}

	generate_dh_parameters(fd, fname);
	generate_rsa_parameters(fd, fname);

	gnutls_global_deinit();
}

#endif
