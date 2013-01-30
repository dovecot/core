#ifndef AUTH_FIELDS_H
#define AUTH_FIELDS_H

struct auth_request;

enum auth_field_flags {
	/* This field is internal to auth process and won't be sent to client */
	AUTH_FIELD_FLAG_HIDDEN	= 0x01
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
void auth_fields_append(struct auth_fields *fields, string_t *dest,
			bool include_hidden);
bool auth_fields_is_empty(struct auth_fields *fields);

#endif
