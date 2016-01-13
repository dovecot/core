/* Copyright (c) 2014-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "mmap-util.h"
#include "hash-method.h"

#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
#  define MAP_ANONYMOUS MAP_ANON
#endif

static unsigned char *buf;
static unsigned int buf_size;

static void test_hash_method_one(const struct hash_method *method)
{
	unsigned char *ctx, *digest;
	unsigned int i;

	test_begin(t_strdup_printf("hash method %s", method->name));

	ctx = i_malloc(method->context_size);
	digest = i_malloc(method->digest_size);
	method->init(ctx);

	/* make sure the code doesn't try to access data past boundaries */
	for (i = 0; i < buf_size; i++)
		method->loop(ctx, buf + buf_size - i, i);
	method->result(ctx, digest);

	i_free(ctx);
	i_free(digest);
	test_end();
}

void test_hash_method(void)
{
	unsigned int i;

	buf_size = mmap_get_page_size();
#ifdef MAP_ANONYMOUS
	buf = mmap(NULL, buf_size*2, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	mprotect(buf + buf_size, buf_size, PROT_NONE);
#else
	buf = i_malloc(buf_size);
#endif
	memset(buf, 0, buf_size);

	for (i = 0; hash_methods[i] != NULL; i++)
		test_hash_method_one(hash_methods[i]);
}
