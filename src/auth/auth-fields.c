/* Copyright (c) 2005-2013 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "auth-request.h"
#include "auth-fields.h"

struct auth_fields {
	pool_t pool;
	ARRAY_TYPE(auth_field) fields, snapshot_fields;
	unsigned int snapshot_idx;
	bool snapshotted;
};

struct auth_fields *auth_fields_init(pool_t pool)
{
	struct auth_fields *fields;

	fields = p_new(pool, struct auth_fields, 1);
	fields->pool = pool;
	return fields;
}

static void auth_fields_snapshot_preserve(struct auth_fields *fields)
{
	if (!fields->snapshotted || array_is_created(&fields->snapshot_fields))
		return;

	p_array_init(&fields->snapshot_fields, fields->pool,
		     array_count(&fields->fields));
	array_append_array(&fields->snapshot_fields, &fields->fields);
}

static bool
auth_fields_find_idx(struct auth_fields *fields, const char *key,
		     unsigned int *idx_r)
{
	const struct auth_field *f;
	unsigned int i, count;

	if (!array_is_created(&fields->fields))
		return FALSE;

	f = array_get(&fields->fields, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(f[i].key, key) == 0) {
			*idx_r = i;
			return TRUE;
		}
	}
	return FALSE;
}

void auth_fields_add(struct auth_fields *fields,
		     const char *key, const char *value,
		     enum auth_field_flags flags)
{
	struct auth_field *field;
	unsigned int idx;

	i_assert(*key != '\0');
	i_assert(strchr(key, '\t') == NULL &&
		 strchr(key, '\n') == NULL);

	if (!auth_fields_find_idx(fields, key, &idx)) {
		if (!array_is_created(&fields->fields))
			p_array_init(&fields->fields, fields->pool, 16);

		field = array_append_space(&fields->fields);
		field->key = p_strdup(fields->pool, key);
	} else {
		auth_fields_snapshot_preserve(fields);
		field = array_idx_modifiable(&fields->fields, idx);
	}
	field->value = p_strdup_empty(fields->pool, value);
	field->flags = flags | AUTH_FIELD_FLAG_CHANGED;
}

void auth_fields_remove(struct auth_fields *fields, const char *key)
{
	unsigned int idx;

	if (auth_fields_find_idx(fields, key, &idx)) {
		auth_fields_snapshot_preserve(fields);
		array_delete(&fields->fields, idx, 1);
	}
}

const char *auth_fields_find(struct auth_fields *fields, const char *key)
{
	const struct auth_field *field;
	unsigned int idx;

	if (!auth_fields_find_idx(fields, key, &idx))
		return NULL;

	field = array_idx(&fields->fields, idx);
	return field->value == NULL ? "" : field->value;
}

bool auth_fields_exists(struct auth_fields *fields, const char *key)
{
	return auth_fields_find(fields, key) != NULL;
}

void auth_fields_reset(struct auth_fields *fields)
{
	if (array_is_created(&fields->fields)) {
		auth_fields_snapshot_preserve(fields);
		array_clear(&fields->fields);
	}
}

void auth_fields_import(struct auth_fields *fields, const char *str,
			enum auth_field_flags flags)
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
			auth_fields_add(fields, key, value, flags);
		}
	} T_END;
}

const ARRAY_TYPE(auth_field) *auth_fields_export(struct auth_fields *fields)
{
	if (!array_is_created(&fields->fields))
		p_array_init(&fields->fields, fields->pool, 1);
	return &fields->fields;
}

void auth_fields_append(struct auth_fields *fields, string_t *dest,
			enum auth_field_flags flags_mask,
			enum auth_field_flags flags_result)
{
	const struct auth_field *f;
	unsigned int i, count;
	bool first = TRUE;

	if (!array_is_created(&fields->fields))
		return;

	f = array_get(&fields->fields, &count);
	for (i = 0; i < count; i++) {
		if ((f[i].flags & flags_mask) != flags_result)
			continue;

		if (first)
			first = FALSE;
		else
			str_append_c(dest, '\t');
		str_append(dest, f[i].key);
		if (f[i].value != NULL) {
			str_append_c(dest, '=');
			str_append_tabescaped(dest, f[i].value);
		}
	}
}

bool auth_fields_is_empty(struct auth_fields *fields)
{
	return fields == NULL || !array_is_created(&fields->fields) ||
		array_count(&fields->fields) == 0;
}

void auth_fields_booleanize(struct auth_fields *fields, const char *key)
{
	struct auth_field *field;
	unsigned int idx;

	if (auth_fields_find_idx(fields, key, &idx)) {
		field = array_idx_modifiable(&fields->fields, idx);
		field->value = NULL;
	}
}

void auth_fields_snapshot(struct auth_fields *fields)
{
	struct auth_field *field;

	fields->snapshotted = TRUE;
	if (!array_is_created(&fields->fields))
		return;

	if (!array_is_created(&fields->snapshot_fields)) {
		/* try to avoid creating this array */
		fields->snapshot_idx = array_count(&fields->fields);
	} else {
		array_clear(&fields->snapshot_fields);
		array_append_array(&fields->snapshot_fields, &fields->fields);
	}
	array_foreach_modifiable(&fields->fields, field)
		field->flags &= ~AUTH_FIELD_FLAG_CHANGED;
}

void auth_fields_rollback(struct auth_fields *fields)
{
	if (array_is_created(&fields->snapshot_fields)) {
		array_clear(&fields->fields);
		array_append_array(&fields->fields, &fields->snapshot_fields);
	} else if (array_is_created(&fields->fields)) {
		array_delete(&fields->fields, fields->snapshot_idx,
			     array_count(&fields->fields) -
			     fields->snapshot_idx);
	}
}
