#ifndef AUTH_STREAM_H
#define AUTH_STREAM_H

struct auth_request;

struct auth_stream_reply *auth_stream_reply_init(pool_t pool);
void auth_stream_reply_add(struct auth_stream_reply *reply,
			   const char *key, const char *value);
void auth_stream_reply_reset(struct auth_stream_reply *reply);
void auth_stream_reply_remove(struct auth_stream_reply *reply, const char *key);

const char *auth_stream_reply_find(struct auth_stream_reply *reply,
				   const char *key);

void auth_stream_reply_import(struct auth_stream_reply *reply, const char *str);
const char *auth_stream_reply_export(struct auth_stream_reply *reply);
bool auth_stream_is_empty(struct auth_stream_reply *reply);

const char *const *auth_stream_split(struct auth_stream_reply *reply);
string_t *auth_stream_reply_get_str(struct auth_stream_reply *reply);

#endif
