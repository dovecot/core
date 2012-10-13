/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dict.h"
#include "index-storage.h"

#define KEY_PREFIX_PRIVATE "priv/"
#define KEY_PREFIX_SHARED "shared/"

struct index_storage_attribute_iter {
	struct mailbox_attribute_iter iter;
	struct dict_iterate_context *diter;
	char *prefix;
	unsigned int prefix_len;
};

static int index_storage_get_dict(struct mailbox *box, struct dict **dict_r,
				  const char **mailbox_prefix_r)
{
	struct mailbox_metadata metadata;
	const char *error;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_GUID, &metadata) < 0)
		return -1;
	*mailbox_prefix_r = guid_128_to_string(metadata.guid);

	if (box->_attr_dict != NULL) {
		*dict_r = box->_attr_dict;
		return 0;
	}
	if (*box->storage->set->mail_attribute_dict == '\0') {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTPOSSIBLE,
				       "Mailbox attributes not enabled");
		return -1;
	}
	if (box->attr_dict_failed) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}

	if (dict_init(box->storage->set->mail_attribute_dict,
		      DICT_DATA_TYPE_STRING,
		      box->storage->user->username,
		      box->storage->user->set->base_dir,
		      &box->_attr_dict, &error) < 0) {
		mail_storage_set_critical(box->storage,
			"mail_attribute_dict: dict_init(%s) failed: %s",
			box->storage->set->mail_attribute_dict, error);
		return -1;
	}
	*dict_r = box->_attr_dict;
	return 0;
}

static const char *
key_get_prefixed(enum mail_attribute_type type, const char *mailbox_prefix,
		 const char *key)
{
	switch (type) {
	case MAIL_ATTRIBUTE_TYPE_PRIVATE:
		return t_strconcat(KEY_PREFIX_PRIVATE, mailbox_prefix, "/",
				   key, NULL);
	case MAIL_ATTRIBUTE_TYPE_SHARED:
		return t_strconcat(KEY_PREFIX_SHARED, mailbox_prefix, "/",
				   key, NULL);
	}
	i_unreached();
}

int index_storage_attribute_set(struct mailbox *box,
				enum mail_attribute_type type,
				const char *key, const char *value)
{
	struct dict_transaction_context *dtrans;
	struct dict *dict;
	const char *mailbox_prefix;

	if (index_storage_get_dict(box, &dict, &mailbox_prefix) < 0)
		return -1;

	T_BEGIN {
		key = key_get_prefixed(type, mailbox_prefix, key);
		dtrans = dict_transaction_begin(dict);
		if (value != NULL)
			dict_set(dtrans, key, value);
		else
			dict_unset(dtrans, key);
	} T_END;
	if (dict_transaction_commit(&dtrans) < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}
	return 0;
}

int index_storage_attribute_get(struct mailbox *box,
				enum mail_attribute_type type,
				const char *key, const char **value_r)
{
	struct dict *dict;
	const char *mailbox_prefix;
	int ret;

	if (index_storage_get_dict(box, &dict, &mailbox_prefix) < 0)
		return -1;

	ret = dict_lookup(dict, pool_datastack_create(),
			  key_get_prefixed(type, mailbox_prefix, key), value_r);
	if (ret < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}
	if (ret == 0)
		*value_r = NULL;
	return ret;
}

struct mailbox_attribute_iter *
index_storage_attribute_iter_init(struct mailbox *box,
				  enum mail_attribute_type type,
				  const char *prefix)
{
	struct index_storage_attribute_iter *iter;
	struct dict *dict;
	const char *mailbox_prefix;

	iter = i_new(struct index_storage_attribute_iter, 1);
	iter->iter.box = box;
	if (index_storage_get_dict(box, &dict, &mailbox_prefix) == 0) {
		iter->prefix = i_strdup(key_get_prefixed(type, mailbox_prefix,
							 prefix));
		iter->prefix_len = strlen(iter->prefix);
		iter->diter = dict_iterate_init(dict, iter->prefix,
						DICT_ITERATE_FLAG_RECURSE |
						DICT_ITERATE_FLAG_NO_VALUE);
	}
	return &iter->iter;
}

const char *
index_storage_attribute_iter_next(struct mailbox_attribute_iter *_iter)
{
	struct index_storage_attribute_iter *iter =
		(struct index_storage_attribute_iter *)_iter;
	const char *key, *value;

	if (iter->diter == NULL || !dict_iterate(iter->diter, &key, &value))
		return NULL;

	i_assert(strncmp(key, iter->prefix, iter->prefix_len) == 0);
	key += iter->prefix_len;
	return key;
}

int index_storage_attribute_iter_deinit(struct mailbox_attribute_iter *_iter)
{
	struct index_storage_attribute_iter *iter =
		(struct index_storage_attribute_iter *)_iter;
	int ret;

	ret = iter->diter == NULL ? -1 :
		dict_iterate_deinit(&iter->diter);
	if (ret < 0)
		mail_storage_set_internal_error(_iter->box->storage);
	i_free(iter->prefix);
	i_free(iter);
	return ret;
}
