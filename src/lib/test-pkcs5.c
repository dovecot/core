/* Copyright (c) Dovecot authors, see top-level COPYING file */

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

/* PBKDF1 has no published vectors, so these come straight from the
   definition in RFC 8018 section 5.1: T_1 = Hash(P || S), T_i = Hash(T_i-1)
   for i = 2..c, and DK is the leftmost dkLen octets of T_c. */
static const struct test_vector test_vectors_v1[] = {
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 1, TEST_BUF("\xc8\x8e\x9c\x67\x04\x1a\x74\xe0\x35\x7b\xef\xdf\xf9\x3f\x87\xdd\xe0\x90\x42\x14") },
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 2, TEST_BUF("\x47\xe9\x7e\x39\xe2\xb3\x2b\x15\xeb\x92\x78\xe5\x3f\x7b\xfc\xa5\x7f\x8e\x6b\x2c") },
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 1000, TEST_BUF("\x4a\x8f\xd4\x8e\x42\x6e\xd0\x81\xb5\x35\xbe\x57\x69\x89\x2f\xa3\x96\x29\x3e\xfb") },
	/* a derived key shorter than the digest is truncated, not padded */
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 1000, TEST_BUF("\x4a\x8f\xd4\x8e\x42\x6e\xd0\x81\xb5\x35\xbe\x57\x69\x89\x2f\xa3") },
	{ "sha1", TEST_BUF("password"), TEST_BUF("salt"), 1000, TEST_BUF("\x4a") },
	/* embedded NULs in the password and the salt */
	{ "sha1", TEST_BUF("pass\x00word"), TEST_BUF("sa\x00lt"), 4096, TEST_BUF("\x2b\x66\x4b\x45\xa9\xa1\x29\xdb\xf2\xdc\xb9\x98\x98\x34\x7d\xb1") },
	{ "sha256", TEST_BUF("password"), TEST_BUF("salt"), 1000, TEST_BUF("\x56\xae\x28\xa7\x3d\x11\xfd\xd6\x74\xf1\x02\xf1\x14\xe2\x5a\xa3\xa7\xbc\xc5\x7e\x16\xef\x0b\xf1\x02\x1e\x78\xd4\xd8\x42\x87\xe7") },
	{ "sha256", TEST_BUF("password"), TEST_BUF("salt"), 1000, TEST_BUF("\x56\xae\x28\xa7\x3d\x11\xfd\xd6\x74\xf1\x02\xf1\x14\xe2\x5a\xa3") },
	{ "md5", TEST_BUF("password"), TEST_BUF("salt"), 1000, TEST_BUF("\x84\x75\xc6\xa8\x53\x1a\x5d\x27\xe3\x86\xcd\x49\x64\x57\x81\x2c") }
};

void test_pkcs5_pbkdf1(void)
{
	buffer_t *res = buffer_create_dynamic(default_pool, 32);

	test_begin("pkcs5_pbkdf1");

	for (size_t i = 0; i < N_ELEMENTS(test_vectors_v1); i++) {
		const struct test_vector *vec = &test_vectors_v1[i];

		buffer_set_used_size(res, 0);
		test_assert_idx(pkcs5_pbkdf(PKCS5_PBKDF1,
					    hash_method_lookup(vec->prf),
					    vec->p, vec->pLen,
					    vec->s, vec->sLen,
					    vec->i, vec->dkLen, res) == 0, i);
		test_assert_idx(res->used == vec->dkLen, i);
		test_assert_idx(res->used == vec->dkLen &&
				memcmp(res->data, vec->dk, vec->dkLen) == 0, i);
	}

	/* a derived key longer than the digest has no definition */
	buffer_set_used_size(res, 0);
	test_assert(pkcs5_pbkdf(PKCS5_PBKDF1, hash_method_lookup("sha1"),
				(const unsigned char *)"password", 8,
				(const unsigned char *)"salt", 4,
				1000, 21, res) < 0);
	/* and neither does a zero iteration count */
	buffer_set_used_size(res, 0);
	test_assert(pkcs5_pbkdf(PKCS5_PBKDF1, hash_method_lookup("sha1"),
				(const unsigned char *)"password", 8,
				(const unsigned char *)"salt", 4,
				0, 20, res) < 0);

	buffer_free(&res);

	test_end();
}

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
