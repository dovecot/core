/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md4.h"
#include "md5.h"
#include "sha1.h"
#include "sha2.h"
#include "sha3.h"
#include "hash-method.h"

const struct hash_method *hash_method_lookup(const char *name)
{
	unsigned int i;

	for (i = 0; hash_methods[i] != NULL; i++) {
		if (strcmp(hash_methods[i]->name, name) == 0)
			return hash_methods[i];
	}
	return NULL;
}

static void hash_method_init_size(void *context)
{
	uint64_t *ctx = context;

	*ctx = 0;
}

static void
hash_method_loop_size(void *context, const void *data ATTR_UNUSED, size_t size)
{
	uint64_t *ctx = context;

	*ctx += size;
}

static void hash_method_result_size(void *context, unsigned char *result_r)
{
	uint64_t *ctx = context;

	result_r[0] = (*ctx & 0xff00000000000000ULL) >> 56;
	result_r[1] = (*ctx & 0x00ff000000000000ULL) >> 48;
	result_r[2] = (*ctx & 0x0000ff0000000000ULL) >> 40;
	result_r[3] = (*ctx & 0x000000ff00000000ULL) >> 32;
	result_r[4] = (*ctx & 0x00000000ff000000ULL) >> 24;
	result_r[5] = (*ctx & 0x0000000000ff0000ULL) >> 16;
	result_r[6] = (*ctx & 0x000000000000ff00ULL) >> 8;
	result_r[7] = (*ctx & 0x00000000000000ffULL);
}

void hash_method_get_digest(const struct hash_method *meth,
			    const void *data, size_t data_len,
			    unsigned char *result_r)
{
	i_assert(meth != NULL);
	i_assert(data_len == 0 || data != NULL);
	unsigned char ctx[meth->context_size];

	meth->init(ctx);
	meth->loop(ctx, data == NULL ? "" : data, data_len);
	meth->result(ctx, result_r);
}

buffer_t *t_hash_data(const struct hash_method *meth,
		      const void *data, size_t data_len)
{
	i_assert(meth != NULL);
	buffer_t *result = t_buffer_create(meth->digest_size);
	unsigned char *resptr = buffer_append_space_unsafe(result,
							   meth->digest_size);

	hash_method_get_digest(meth, data, data_len, resptr);
	return result;
}

static const struct hash_method hash_method_size = {
	"size",
	sizeof(uint64_t),
	sizeof(uint64_t),

	hash_method_init_size,
	hash_method_loop_size,
	hash_method_result_size
};

const struct hash_method *hash_methods[] = {
	&hash_method_md4,
	&hash_method_md5,
	&hash_method_sha1,
	&hash_method_sha256,
	&hash_method_sha512,
	&hash_method_sha3_256,
	&hash_method_sha3_512,
	&hash_method_size,
	NULL
};
