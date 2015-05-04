/* Copyright (c) 2003-2015 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "mail-storage-private.h"

/*
 * Attribute API
 */

int mailbox_attribute_set(struct mailbox_transaction_context *t,
			  enum mail_attribute_type type, const char *key,
			  const struct mail_attribute_value *value)
{
	return t->box->v.attribute_set(t, type, key, value);
}

int mailbox_attribute_unset(struct mailbox_transaction_context *t,
			    enum mail_attribute_type type, const char *key)
{
	struct mail_attribute_value value;

	memset(&value, 0, sizeof(value));
	return t->box->v.attribute_set(t, type, key, &value);
}

int mailbox_attribute_value_to_string(struct mail_storage *storage,
				      const struct mail_attribute_value *value,
				      const char **str_r)
{
	string_t *str;
	const unsigned char *data;
	size_t size;

	if (value->value_stream == NULL) {
		*str_r = value->value;
		return 0;
	}
	str = t_str_new(128);
	i_stream_seek(value->value_stream, 0);
	while (i_stream_read_data(value->value_stream, &data, &size, 0) > 0) {
		if (memchr(data, '\0', size) != NULL) {
			mail_storage_set_error(storage, MAIL_ERROR_PARAMS,
				"Attribute string value has NULs");
			return -1;
		}
		str_append_n(str, data, size);
		i_stream_skip(value->value_stream, size);
	}
	if (value->value_stream->stream_errno != 0) {
		mail_storage_set_critical(storage, "read(%s) failed: %s",
			i_stream_get_name(value->value_stream),
			i_stream_get_error(value->value_stream));
		return -1;
	}
	i_assert(value->value_stream->eof);
	*str_r = str_c(str);
	return 0;
}

int mailbox_attribute_get(struct mailbox_transaction_context *t,
			  enum mail_attribute_type type, const char *key,
			  struct mail_attribute_value *value_r)
{
	int ret;

	memset(value_r, 0, sizeof(*value_r));
	if ((ret = t->box->v.attribute_get(t, type, key, value_r)) <= 0)
		return ret;
	i_assert(value_r->value != NULL);
	return 1;
}

int mailbox_attribute_get_stream(struct mailbox_transaction_context *t,
				 enum mail_attribute_type type, const char *key,
				 struct mail_attribute_value *value_r)
{
	int ret;

	memset(value_r, 0, sizeof(*value_r));
	value_r->flags |= MAIL_ATTRIBUTE_VALUE_FLAG_INT_STREAMS;
	if ((ret = t->box->v.attribute_get(t, type, key, value_r)) <= 0)
		return ret;
	i_assert(value_r->value != NULL || value_r->value_stream != NULL);
	return 1;
}

struct mailbox_attribute_iter *
mailbox_attribute_iter_init(struct mailbox *box, enum mail_attribute_type type,
			    const char *prefix)
{
	return box->v.attribute_iter_init(box, type, prefix);
}

const char *mailbox_attribute_iter_next(struct mailbox_attribute_iter *iter)
{
	return iter->box->v.attribute_iter_next(iter);
}

int mailbox_attribute_iter_deinit(struct mailbox_attribute_iter **_iter)
{
	struct mailbox_attribute_iter *iter = *_iter;

	*_iter = NULL;
	return iter->box->v.attribute_iter_deinit(iter);
}

