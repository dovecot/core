/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ssl-init.h"

#if 0
#ifdef HAVE_OPENSSL

#include <openssl/ssl.h>
#include <openssl/err.h>

static int rsa_bits[] = { 512, 1024, 0 };
static int dh_bits[] = { 768, 1024, 0 };

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

	for (i = 0; dh_bits[i] != 0; i++) {
		bits = dh_bits[i];

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
	RSA *rsa;
	int ret;

	for (i = 0; rsa_bits[i] != 0; i++) {
		rsa = RSA_generate_key(rsa_bits[i], RSA_F4, NULL, NULL);
		if (rsa == NULL) {
			i_fatal("RSA_generate_keys(%d bits) failed: %s",
				rsa_bits[i], ssl_last_error());
		}



		RSA_free(rsa);
	}

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

void _ssl_generate_parameters(int fd, const char *fname)
{
	SSL_CTX *ssl_ctx;

	SSL_library_init();
	SSL_load_error_strings();

	if ((ssl_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
		i_fatal("SSL_CTX_new() failed");

	generate_dh_parameters(fd, fname);
	generate_rsa_parameters(fd, fname);

	SSL_CTX_free(ssl_ctx);
}

struct ssl_key_cache {
	RSA *key;
	int keylength;
};

static RSA *ssl_gen_rsa_key(SSL *ssl __attr_unused__,
			    int is_export __attr_unused__, int keylength)
{
	static buffer_t *key_cache = NULL;
	const struct ssl_key_cache *cache;
	struct ssl_key_cache tmp_cache;
	size_t i, size;

	if (key_cache == NULL)
		key_cache = buffer_create_dynamic(system_pool, 64, (size_t)-1);

	cache = buffer_get_data(key_cache, &size);
	size /= sizeof(struct ssl_key_cache);

	for (i = 0; i < size; i++) {
		if (cache[i].keylength == keylength)
			return cache[i].key;
	}

	tmp_cache.key = RSA_generate_key(keylength, RSA_F4, NULL, NULL);
	if (tmp_cache.key == NULL) {
		i_error("Can't create temporary RSA key with length %d: %s",
			keylength, ssl_last_error());
		return NULL;
	}
	tmp_cache.keylength = keylength;
	buffer_append(key_cache, &tmp_cache, sizeof(tmp_cache));

	return tmp_cache.key;
}

#endif
#else
void _ssl_generate_parameters(int fd __attr_unused__,
			      const char *fname __attr_unused__)
{
}
#endif
