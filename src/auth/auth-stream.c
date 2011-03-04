/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "auth-request.h"
#include "auth-stream.h"

struct auth_stream_reply {
	string_t *str;
};

struct auth_stream_reply *auth_stream_reply_init(pool_t pool)
{
	struct auth_stream_reply *reply;

	reply = p_new(pool, struct auth_stream_reply, 1);
	reply->str = str_new(pool, 128);
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
		str_tabescape_write(reply->str, value);
	}
}

static bool
auth_stream_reply_find_area(struct auth_stream_reply *reply, const char *key,
			    unsigned int *idx_r, unsigned int *len_r)
{
	const char *str = str_c(reply->str);
	unsigned int i, start, key_len = strlen(key);

	i = 0;
	while (str[i] != '\0') {
		start = i;
		for (; str[i] != '\0'; i++) {
			if (str[i] == '\t')
				break;
		}

		if (strncmp(str+start, key, key_len) == 0 &&
		    (str[start+key_len] == '=' ||
		     str[start+key_len] == '\t' ||
		     str[start+key_len] == '\0')) {
			*idx_r = start;
			*len_r = i - start;
			return TRUE;
		}
		if (str[i] == '\t')
			i++;
	}
	return FALSE;
}

void auth_stream_reply_remove(struct auth_stream_reply *reply, const char *key)
{
	unsigned int idx, len;

	if (!auth_stream_reply_find_area(reply, key, &idx, &len))
		return;

	if (str_len(reply->str) < idx + len) {
		/* remove also trailing tab */
		len++;
	} else if (str_len(reply->str) == idx + len && idx > 0) {
		/* removing last item, remove preceding tab */
		len++;
		idx--;
	}

	str_delete(reply->str, idx, len);
}

const char *auth_stream_reply_find(struct auth_stream_reply *reply,
				   const char *key)
{
	unsigned int idx, len, keylen;

	if (!auth_stream_reply_find_area(reply, key, &idx, &len))
		return NULL;
	else {
		keylen = strlen(key);
		if (len == keylen) {
			/* key without =value */
			return "";
		}
		i_assert(len > keylen);
		idx += keylen + 1;
		len -= keylen + 1;
		return t_strndup(str_c(reply->str) + idx, len);
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

const char *const *auth_stream_split(struct auth_stream_reply *reply)
{
	return t_strsplit(str_c(reply->str), "\t");
}

string_t *auth_stream_reply_get_str(struct auth_stream_reply *reply)
{
	return reply->str;
}
