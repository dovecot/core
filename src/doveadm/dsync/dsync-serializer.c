/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "dsync-serializer.h"

struct dsync_serializer {
	pool_t pool;
	const char *const *keys;
	unsigned int keys_count;
};

struct dsync_serializer_encoder {
	pool_t pool;
	struct dsync_serializer *serializer;
	ARRAY_TYPE(const_string) values;
};

struct dsync_serializer *dsync_serializer_init(const char *const keys[])
{
	struct dsync_serializer *serializer;
	pool_t pool;
	const char **dup_keys;
	unsigned int i, count;

	pool = pool_alloconly_create("dsync serializer", 512);
	serializer = p_new(pool, struct dsync_serializer, 1);
	serializer->pool = pool;

	count = str_array_length(keys);
	dup_keys = p_new(pool, const char *, count + 1);
	for (i = 0; i < count; i++)
		dup_keys[i] = p_strdup(pool, keys[i]);
	serializer->keys = dup_keys;
	serializer->keys_count = count;
	return serializer;
}

void dsync_serializer_deinit(struct dsync_serializer **_serializer)
{
	struct dsync_serializer *serializer = *_serializer;

	*_serializer = NULL;

	pool_unref(&serializer->pool);
}

const char *
dsync_serializer_encode_header_line(struct dsync_serializer *serializer)
{
	string_t *str = t_str_new(128);
	unsigned int i;

	for (i = 0; serializer->keys[i] != NULL; i++) {
		if (i > 0)
			str_append_c(str, '\t');
		str_append_tabescaped(str, serializer->keys[i]);
	}
	str_append_c(str, '\n');
	return str_c(str);
}

struct dsync_serializer_encoder *
dsync_serializer_encode_begin(struct dsync_serializer *serializer)
{
	struct dsync_serializer_encoder *encoder;
	pool_t pool = pool_alloconly_create("dsync serializer encode", 1024);

	encoder = p_new(pool, struct dsync_serializer_encoder, 1);
	encoder->pool = pool;
	encoder->serializer = serializer;
	p_array_init(&encoder->values, pool, serializer->keys_count);
	return encoder;
}

void dsync_serializer_encode_add(struct dsync_serializer_encoder *encoder,
				 const char *key, const char *value)
{
	unsigned int i;

	for (i = 0; encoder->serializer->keys[i] != NULL; i++) {
		if (strcmp(encoder->serializer->keys[i], key) == 0) {
			value = p_strdup(encoder->pool, value);
			array_idx_set(&encoder->values, i, &value);
			return;
		}
	}
	i_panic("Unknown key: %s", key);
}

void dsync_serializer_encode_finish(struct dsync_serializer_encoder **_encoder,
				    string_t *output)
{
	struct dsync_serializer_encoder *encoder = *_encoder;
	const char *const *values;
	unsigned int i, count;

	*_encoder = NULL;

	values = array_get(&encoder->values, &count);
	for (i = 0; i < count; i++) {
		if (i > 0)
			str_append_c(output, '\t');
		if (values[i] == NULL)
			str_append_c(output, NULL_CHR);
		else  {
			if (values[i][0] == NULL_CHR)
				str_append_c(output, NULL_CHR);
			str_append_tabescaped(output, values[i]);
		}
	}
	str_append_c(output, '\n');

	pool_unref(&encoder->pool);
}
