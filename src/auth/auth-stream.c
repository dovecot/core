/* Copyright (c) 2005-2012 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "auth-request.h"
#include "auth-stream.h"

struct auth_stream_reply {
	pool_t pool;
	ARRAY_TYPE(auth_stream_field) fields;
};

struct auth_stream_reply *auth_stream_reply_init(pool_t pool)
{
	struct auth_stream_reply *reply;

	reply = p_new(pool, struct auth_stream_reply, 1);
	reply->pool = pool;
	p_array_init(&reply->fields, pool, 16);
	return reply;
}

static bool
auth_stream_reply_find_idx(struct auth_stream_reply *reply, const char *key,
			   unsigned int *idx_r)
{
	const struct auth_stream_field *fields;
	unsigned int i, count;

	fields = array_get(&reply->fields, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(fields[i].key, key) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

void auth_stream_reply_add(struct auth_stream_reply *reply,
			   const char *key, const char *value,
			   enum auth_stream_field_flags flags)
{
	struct auth_stream_field *field;
	unsigned int idx;

	i_assert(*key != '\0');
	i_assert(strchr(key, '\t') == NULL &&
		 strchr(key, '\n') == NULL);

	if (!auth_stream_reply_find_idx(reply, key, &idx)) {
		field = array_append_space(&reply->fields);
		field->key = p_strdup(reply->pool, key);
	} else {
		field = array_idx_modifiable(&reply->fields, idx);
	}
	field->value = p_strdup_empty(reply->pool, value);
	field->flags = flags;
}

void auth_stream_reply_remove(struct auth_stream_reply *reply, const char *key)
{
	unsigned int idx;

	if (auth_stream_reply_find_idx(reply, key, &idx))
		array_delete(&reply->fields, idx, 1);
}

const char *auth_stream_reply_find(struct auth_stream_reply *reply,
				   const char *key)
{
	const struct auth_stream_field *field;
	unsigned int idx;

	if (!auth_stream_reply_find_idx(reply, key, &idx))
		return NULL;

	field = array_idx(&reply->fields, idx);
	return field->value == NULL ? "" : field->value;
}

bool auth_stream_reply_exists(struct auth_stream_reply *reply, const char *key)
{
	return auth_stream_reply_find(reply, key) != NULL;
}

void auth_stream_reply_reset(struct auth_stream_reply *reply)
{
	array_clear(&reply->fields);
}

void auth_stream_reply_import(struct auth_stream_reply *reply, const char *str,
			      enum auth_stream_field_flags flags)
{
	T_BEGIN {
		const char *const *arg = t_strsplit_tab(str);
		const char *key, *value;

		for (; *arg != NULL; arg++) {
			value = strchr(*arg, '=');
			if (value == NULL) {
				key = *arg;
				value = NULL;
			} else {
				key = t_strdup_until(*arg, value++);
			}
			auth_stream_reply_add(reply, key, value, flags);
		}
	} T_END;
}

const ARRAY_TYPE(auth_stream_field) *
auth_stream_reply_export(struct auth_stream_reply *reply)
{
	return &reply->fields;
}

void auth_stream_reply_append(struct auth_stream_reply *reply, string_t *dest,
			      bool include_hidden)
{
	const struct auth_stream_field *fields;
	unsigned int i, count;
	bool first = TRUE;

	fields = array_get(&reply->fields, &count);
	for (i = 0; i < count; i++) {
		if (!include_hidden &&
		    (fields[i].flags & AUTH_STREAM_FIELD_FLAG_HIDDEN) != 0)
			continue;

		if (first)
			first = FALSE;
		else
			str_append_c(dest, '\t');
		str_append(dest, fields[i].key);
		if (fields[i].value != NULL) {
			str_append_c(dest, '=');
			str_append_tabescaped(dest, fields[i].value);
		}
	}
}

bool auth_stream_is_empty(struct auth_stream_reply *reply)
{
	return reply == NULL || array_count(&reply->fields) == 0;
}
