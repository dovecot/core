/* Copyright (c) 2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "array.h"
#include "var-expand.h"
#include "dlua-script.h"
#include "dlua-script-private.h"
#include "mail-storage.h"
#include "mailbox-attribute.h"
#include "mail-storage-lua.h"
#include "mail-storage-lua-private.h"
#include "mail-user.h"

/* lookup mailbox attribute */
int lua_storage_mailbox_attribute_get(struct mailbox *box, const char *key,
				      const char **value_r, size_t *value_len_r,
				      const char **error_r)
{
	struct mail_attribute_value value;
	enum mail_attribute_type attr_type;
	int ret;

	if (str_begins(key, "/private/", &key))
		attr_type = MAIL_ATTRIBUTE_TYPE_PRIVATE;
	else if (str_begins(key, "/shared/", &key))
		attr_type = MAIL_ATTRIBUTE_TYPE_SHARED;
	else {
		*error_r = "Invalid key prefix, must be /private/ or /shared/";
		return -1;
	}

	/* get the attribute */
	if ((ret = mailbox_attribute_get_stream(box, attr_type, key, &value)) < 0) {
		*error_r = mailbox_get_last_error(box, NULL);
		return ret;
	} else if (ret == 0) {
		/* was not found */
		*value_r = NULL;
		*value_len_r = 0;
		return 0;
	}

	if (value.value_stream != NULL) {
		string_t *str = t_str_new(128);
		const unsigned char *data;
		size_t siz;
		while((ret = i_stream_read_more(value.value_stream, &data, &siz))>0) {
			str_append_data(str, data, siz);
			i_stream_skip(value.value_stream, siz);
		}
		i_assert(ret != 0);
		if (ret == -1 && !value.value_stream->eof) {
			/* we could not read the stream */
			*error_r = i_stream_get_error(value.value_stream);
			ret = -1;
		} else {
			*value_r = str->data;
			*value_len_r = str->used;
			ret = 1;
		}
		i_stream_unref(&value.value_stream);
		return ret;
	}

	*value_r = value.value;
	if (value.value != NULL)
		*value_len_r = strlen(value.value);
	else
		*value_len_r = 0;
	return 1;
}

int lua_storage_mailbox_attribute_set(struct mailbox *box, const char *key,
				      const char *value, size_t value_len,
				      const char **error_r)
{
	struct mail_attribute_value attr_value;
	enum mail_attribute_type attr_type;
	int ret;

	i_assert(value != NULL || value_len == 0);

	if (str_begins(key, "/private/", &key))
		attr_type = MAIL_ATTRIBUTE_TYPE_PRIVATE;
	else if (str_begins(key, "/shared/", &key))
		attr_type = MAIL_ATTRIBUTE_TYPE_SHARED;
	else {
		*error_r = "Invalid key prefix, must be /private/ or /shared/";
		return -1;
	}

	struct mailbox_transaction_context *t =
		mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_NO_NOTIFY, __func__);
	i_zero(&attr_value);

	if (value != NULL) {
		/* use stream API to allow NULs in data */
		attr_value.value_stream = i_stream_create_from_data(value, value_len);
	}

	ret = mailbox_attribute_set(t, attr_type, key, &attr_value);

	if (ret < 0) {
		*error_r = mailbox_get_last_error(box, NULL);
		mailbox_transaction_rollback(&t);
	} else if ((ret = mailbox_transaction_commit(&t)) < 0) {
		*error_r = mailbox_get_last_error(box, NULL);
	}

	if (attr_value.value_stream != NULL)
		i_stream_unref(&attr_value.value_stream);

	return ret;
}

int lua_storage_mailbox_attribute_list(struct mailbox *box, const char *prefix,
				       ARRAY_TYPE(lua_storage_keyvalue) *items_r,
				       const char **error_r)
{
	const char *key, *orig_prefix = prefix;
	enum mail_attribute_type attr_type;
	int ret;

	if (str_begins(prefix, "/private/", &prefix))
		attr_type = MAIL_ATTRIBUTE_TYPE_PRIVATE;
	else if (str_begins(prefix, "/shared/", &prefix))
		attr_type = MAIL_ATTRIBUTE_TYPE_SHARED;
	else {
		*error_r = "Invalid key prefix, must be /private/ or /shared/";
		return -1;
	}

	struct mailbox_attribute_iter *iter =
			mailbox_attribute_iter_init(box, attr_type, prefix);

	ret = 0;
	*error_r = NULL;
	while((key = mailbox_attribute_iter_next(iter)) != NULL) {
		struct lua_storage_keyvalue *item = array_append_space(items_r);
		item->key = t_strdup_printf("%s%s", orig_prefix, key);
		if (lua_storage_mailbox_attribute_get(box, item->key, &item->value,
						      &item->value_len, error_r) < 0) {
			ret = -1;
			break;
		}
	}

	if (mailbox_attribute_iter_deinit(&iter) < 0 || ret == -1) {
		if (*error_r == NULL)
			*error_r = mailbox_get_last_error(box, NULL);
		return -1;
	}

	return 0;
}
