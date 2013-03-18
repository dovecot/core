#ifndef AUTH_FIELDS_H
#define AUTH_FIELDS_H

struct auth_request;

enum auth_field_flags {
	/* This field is internal to auth process and won't be sent to client */
	AUTH_FIELD_FLAG_HIDDEN	= 0x01,
	/* Changed since last snapshot. Set/cleared automatically. */
	AUTH_FIELD_FLAG_CHANGED	= 0x02
};

struct auth_field {
	const char *key, *value;
	enum auth_field_flags flags;
};
ARRAY_DEFINE_TYPE(auth_field, struct auth_field);

struct auth_fields *auth_fields_init(pool_t pool);
void auth_fields_add(struct auth_fields *fields,
		     const char *key, const char *value,
		     enum auth_field_flags flags) ATTR_NULL(3);
void auth_fields_reset(struct auth_fields *fields);
void auth_fields_remove(struct auth_fields *fields, const char *key);

const char *auth_fields_find(struct auth_fields *fields, const char *key);
bool auth_fields_exists(struct auth_fields *fields, const char *key);

void auth_fields_import(struct auth_fields *fields, const char *str,
			enum auth_field_flags flags);
const ARRAY_TYPE(auth_field) *auth_fields_export(struct auth_fields *fields);
/* Append fields where (flag & flags_mask) == flags_result. */
void auth_fields_append(struct auth_fields *fields, string_t *dest,
			enum auth_field_flags flags_mask,
			enum auth_field_flags flags_result);
bool auth_fields_is_empty(struct auth_fields *fields);
/* If the field exists, clear its value (so the exported string will be "key"
   instead of e.g. "key=y"). */
void auth_fields_booleanize(struct auth_fields *fields, const char *key);

/* Remember the current fields. */
void auth_fields_snapshot(struct auth_fields *fields);
/* Rollback to previous snapshot, or clear the fields if there isn't any. */
void auth_fields_rollback(struct auth_fields *fields);

#endif
