/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "str.h"
#include "buffer.h"
#include "hash-method.h"
#include "pkcs5.h"

struct test_vector {
	const char *prf;
	unsigned char *p;
	size_t pLen;
	unsigned char *s;
	size_t sLen;
	unsigned int i;
	unsigned char *dk;
	size_t dkLen;
};

#define TEST_BUF(x) (unsigned char*)x, sizeof(x)-1

/* RFC 6070 test vectors */
static const struct test_vector test_vectors_v2[] = {
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 1, TEST_BUF("\x0c\x60\xc8\x0f\x96\x1f\x0e\x71\xf3\xa9\xb5\x24\xaf\x60\x12\x06\x2f\xe0\x37\xa6") },
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 2, TEST_BUF("\xea\x6c\x01\x4d\xc7\x2d\x6f\x8c\xcd\x1e\xd9\x2a\xce\x1d\x41\xf0\xd8\xde\x89\x57") },
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 4096, TEST_BUF("\x4b\x00\x79\x01\xb7\x65\x48\x9a\xbe\xad\x49\xd9\x26\xf7\x21\xd0\x65\xa4\x29\xc1") },
/* enable the next test only when you need it, it takes quite long time */
/*	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 16777216, TEST_BUF("\xee\xfe\x3d\x61\xcd\x4d\xa4\xe4\xe9\x94\x5b\x3d\x6b\xa2\x15\x8c\x26\x34\xe9\x84") }, */
	{ "sha1", TEST_BUF("passwordPASSWORDpassword"), TEST_BUF("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096, TEST_BUF("\x3d\x2e\xec\x4f\xe4\x1c\x84\x9b\x80\xc8\xd8\x36\x62\xc0\xe4\x4a\x8b\x29\x1a\x96\x4c\xf2\xf0\x70\x38") },
	{ "sha1", TEST_BUF("pass\0word"), TEST_BUF("sa\0lt"), 4096, TEST_BUF("\x56\xfa\x6a\xa7\x55\x48\x09\x9d\xcc\x37\xd7\xf0\x34\x25\xe0\xc3") }
};

void test_pkcs5_pbkdf2(void)
{
	buffer_t *res = buffer_create_dynamic(default_pool, 25);

	test_begin("pkcs5_pbkdf2");

	for(size_t i = 0; i < N_ELEMENTS(test_vectors_v2); i++) {
		buffer_set_used_size(res, 0);
		const struct test_vector *vec = &(test_vectors_v2[i]);
		pkcs5_pbkdf(PKCS5_PBKDF2, hash_method_lookup(vec->prf), vec->p, vec->pLen, vec->s, vec->sLen, vec->i, vec->dkLen, res);
		test_assert_idx(memcmp(res->data, vec->dk, vec->dkLen) == 0, i);
	}

	buffer_free(&res);

	test_end();
}
