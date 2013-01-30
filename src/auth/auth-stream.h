#ifndef AUTH_STREAM_H
#define AUTH_STREAM_H

struct auth_request;

enum auth_stream_field_flags {
	/* This field is internal to auth process and won't be sent to client */
	AUTH_STREAM_FIELD_FLAG_HIDDEN	= 0x01
};

struct auth_stream_field {
	const char *key, *value;
	enum auth_stream_field_flags flags;
};
ARRAY_DEFINE_TYPE(auth_stream_field, struct auth_stream_field);

struct auth_stream_reply *auth_stream_reply_init(pool_t pool);
void auth_stream_reply_add(struct auth_stream_reply *reply,
			   const char *key, const char *value,
			   enum auth_stream_field_flags flags) ATTR_NULL(3);
void auth_stream_reply_reset(struct auth_stream_reply *reply);
void auth_stream_reply_remove(struct auth_stream_reply *reply, const char *key);

const char *auth_stream_reply_find(struct auth_stream_reply *reply,
				   const char *key);
bool auth_stream_reply_exists(struct auth_stream_reply *reply, const char *key);

void auth_stream_reply_import(struct auth_stream_reply *reply, const char *str,
			      enum auth_stream_field_flags flags);
const ARRAY_TYPE(auth_stream_field) *
auth_stream_reply_export(struct auth_stream_reply *reply);
void auth_stream_reply_append(struct auth_stream_reply *reply, string_t *dest,
			      bool include_hidden);
bool auth_stream_is_empty(struct auth_stream_reply *reply);

#endif
