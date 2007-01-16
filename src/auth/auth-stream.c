/* Copyright (C) 2005 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "ostream.h"
#include "auth-request.h"
#include "auth-stream.h"

struct auth_stream_reply {
	string_t *str;
};

struct auth_stream_reply *auth_stream_reply_init(struct auth_request *request)
{
	struct auth_stream_reply *reply;

	reply = p_new(request->pool, struct auth_stream_reply, 1);
	reply->str = str_new(request->pool, 256);
	return reply;
}

void auth_stream_reply_add(struct auth_stream_reply *reply,
			   const char *key, const char *value)
{
	if (str_len(reply->str) > 0)
		str_append_c(reply->str, '\t');
	if (key != NULL) {
		i_assert(*key != '\0');
		i_assert(strchr(key, '\t') == NULL &&
			 strchr(key, '\n') == NULL);

		str_append(reply->str, key);
		if (value != NULL)
			str_append_c(reply->str, '=');
	}
	if (value != NULL) {
		/* escape dangerous characters in the value */
		for (; *value != '\0'; value++) {
			switch (*value) {
			case '\001':
				str_append_c(reply->str, '\001');
				str_append_c(reply->str, '1');
				break;
			case '\t':
				str_append_c(reply->str, '\001');
				str_append_c(reply->str, 't');
				break;
			case '\n':
				str_append_c(reply->str, '\001');
				str_append_c(reply->str, 'n');
				break;
			default:
				str_append_c(reply->str, *value);
				break;
			}
		}
	}
}

void auth_stream_reply_reset(struct auth_stream_reply *reply)
{
	str_truncate(reply->str, 0);
}

void auth_stream_reply_import(struct auth_stream_reply *reply, const char *str)
{
	if (str_len(reply->str) > 0)
		str_append_c(reply->str, '\t');
	str_append(reply->str, str);
}

const char *auth_stream_reply_export(struct auth_stream_reply *reply)
{
	return str_c(reply->str);
}

bool auth_stream_is_empty(struct auth_stream_reply *reply)
{
	return reply == NULL || str_len(reply->str) == 0;
}
