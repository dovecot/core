/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "dsync-serializer.h"
#include "dsync-deserializer.h"

struct dsync_deserializer {
	pool_t pool;
	const char *name;
	const char *const *required_fields;
	const char *const *keys;
	unsigned int *required_field_indexes;
	unsigned int required_field_count;
};

struct dsync_deserializer_decoder {
	pool_t pool;
	struct dsync_deserializer *deserializer;
	const char *const *values;
	unsigned int values_count;
};

static bool field_find(const char *const *names, const char *name,
		       unsigned int *idx_r)
{
	unsigned int i;

	for (i = 0; names[i] != NULL; i++) {
		if (strcmp(names[i], name) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

int dsync_deserializer_init(const char *name, const char *const *required_fields,
			    const char *header_line,
			    struct dsync_deserializer **deserializer_r,
			    const char **error_r)
{
	struct dsync_deserializer *deserializer;
	const char **dup_required_fields;
	unsigned int i, required_count;
	pool_t pool;

	*deserializer_r = NULL;

	pool = pool_alloconly_create("dsync deserializer", 1024);
	deserializer = p_new(pool, struct dsync_deserializer, 1);
	deserializer->pool = pool;
	deserializer->name = p_strdup(pool, name);
	deserializer->keys = (void *)p_strsplit_tabescaped(pool, header_line);

	deserializer->required_field_count = required_count =
		required_fields == NULL ? 0 :
		str_array_length(required_fields);
	dup_required_fields = p_new(pool, const char *, required_count + 1);
	deserializer->required_field_indexes =
		p_new(pool, unsigned int, required_count + 1);
	for (i = 0; i < required_count; i++) {
		dup_required_fields[i] =
			p_strdup(pool, required_fields[i]);
		if (!field_find(deserializer->keys, required_fields[i],
				&deserializer->required_field_indexes[i])) {
			*error_r = t_strdup_printf(
				"Header missing required field %s",
				required_fields[i]);
			pool_unref(&pool);
			return -1;
		}
	}
	deserializer->required_fields = dup_required_fields;

	*deserializer_r = deserializer;
	return 0;
}

void dsync_deserializer_deinit(struct dsync_deserializer **_deserializer)
{
	struct dsync_deserializer *deserializer = *_deserializer;

	*_deserializer = NULL;

	pool_unref(&deserializer->pool);
}

int dsync_deserializer_decode_begin(struct dsync_deserializer *deserializer,
				    const char *input,
				    struct dsync_deserializer_decoder **decoder_r,
				    const char **error_r)
{
	struct dsync_deserializer_decoder *decoder;
	unsigned int i;
	char **values;
	pool_t pool;

	*decoder_r = NULL;

	pool = pool_alloconly_create("dsync deserializer decode", 1024);
	decoder = p_new(pool, struct dsync_deserializer_decoder, 1);
	decoder->pool = pool;
	decoder->deserializer = deserializer;
	values = p_strsplit_tabescaped(pool, input);

	/* fix NULLs */
	for (i = 0; values[i] != NULL; i++) {
		if (values[i][0] == NULL_CHR) {
			/* NULL? */
			if (values[i][1] == '\0')
				values[i] = NULL;
			else
				values[i] += 1;
		}
	}
	decoder->values_count = i;

	/* see if all required fields exist */
	for (i = 0; i < deserializer->required_field_count; i++) {
		unsigned int ridx = deserializer->required_field_indexes[i];

		if (ridx >= decoder->values_count || values[ridx] == NULL) {
			*error_r = t_strdup_printf("Missing required field %s",
				deserializer->required_fields[i]);
			pool_unref(&pool);
			return -1;
		}
	}
	decoder->values = (void *)values;

	*decoder_r = decoder;
	return 0;
}

static bool
dsync_deserializer_find_field(struct dsync_deserializer *deserializer,
			      const char *key, unsigned int *idx_r)
{
	unsigned int i;

	for (i = 0; deserializer->keys[i] != NULL; i++) {
		if (strcmp(deserializer->keys[i], key) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

bool dsync_deserializer_decode_try(struct dsync_deserializer_decoder *decoder,
				   const char *key, const char **value_r)
{
	unsigned int idx;

	if (!dsync_deserializer_find_field(decoder->deserializer, key, &idx) ||
	    idx >= decoder->values_count) {
		*value_r = NULL;
		return FALSE;
	} else {
		*value_r = decoder->values[idx];
		return *value_r != NULL;
	}
}

const char *
dsync_deserializer_decode_get(struct dsync_deserializer_decoder *decoder,
			      const char *key)
{
	const char *value;

	if (!dsync_deserializer_decode_try(decoder, key, &value)) {
		i_panic("dsync_deserializer_decode_get() "
			"used for non-required key %s", key);
	}
	return value;
}

const char *
dsync_deserializer_decoder_get_name(struct dsync_deserializer_decoder *decoder)
{
	return decoder->deserializer->name;
}

void dsync_deserializer_decode_finish(struct dsync_deserializer_decoder **_decoder)
{
	struct dsync_deserializer_decoder *decoder = *_decoder;

	*_decoder = NULL;

	pool_unref(&decoder->pool);
}
