/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "mail-storage-private.h"
#include "bsearch-insert-pos.h"
#include "mailbox-attribute-internal.h"

static ARRAY(struct mailbox_attribute_internal) mailbox_internal_attributes;
static pool_t mailbox_attribute_pool;

void mailbox_attributes_init(void)
{
	mailbox_attribute_pool =
		pool_alloconly_create("mailbox attributes", 2048);
	i_array_init(&mailbox_internal_attributes, 32);

	/* internal mailbox attributes */
	mailbox_attributes_internal_init();
}

void mailbox_attributes_deinit(void)
{
	pool_unref(&mailbox_attribute_pool);
	array_free(&mailbox_internal_attributes);
}

/*
 * Internal attributes
 */

static int
mailbox_attribute_internal_cmp(
	const struct mailbox_attribute_internal *reg1,
	const struct mailbox_attribute_internal *reg2)
{
	if (reg1->type != reg2->type)
		return (int)reg1->type - (int)reg2->type;
	return strcmp(reg1->key, reg2->key);
}

void mailbox_attribute_register_internal(
	const struct mailbox_attribute_internal *iattr)
{
	struct mailbox_attribute_internal ireg;
	unsigned int insert_idx;

	/* Validated attributes must have a set() callback that validates the
	   provided values. Also read-only _RANK_AUTHORITY attributes don't
	   need validation. */
	i_assert((iattr->flags & MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED) == 0 ||
		 iattr->set != NULL ||
		 iattr->rank == MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY);

	(void)array_bsearch_insert_pos(&mailbox_internal_attributes,
		iattr, mailbox_attribute_internal_cmp, &insert_idx);

	ireg = *iattr;
	ireg.key = p_strdup(mailbox_attribute_pool, iattr->key);
	array_insert(&mailbox_internal_attributes, insert_idx, &ireg, 1);
}

void mailbox_attribute_register_internals(
	const struct mailbox_attribute_internal *iattrs, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		mailbox_attribute_register_internal(&iattrs[i]);
}

void mailbox_attribute_unregister_internal(
	const struct mailbox_attribute_internal *iattr)
{
	unsigned int idx;

	if (!array_bsearch_insert_pos(&mailbox_internal_attributes,
				      iattr, mailbox_attribute_internal_cmp, &idx)) {
		i_panic("mailbox_attribute_unregister_internal(%s): "
			"key not found", iattr->key);
	}

	array_delete(&mailbox_internal_attributes, idx, 1);
}

void mailbox_attribute_unregister_internals(
	const struct mailbox_attribute_internal *iattrs, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		mailbox_attribute_unregister_internal(&iattrs[i]);
}

static const struct mailbox_attribute_internal *
mailbox_internal_attribute_get_int(enum mail_attribute_type type_flags,
				   const char *key)
{
	const struct mailbox_attribute_internal *iattr;
	struct mailbox_attribute_internal dreg;
	unsigned int insert_idx;

	i_zero(&dreg);
	dreg.type = type_flags & MAIL_ATTRIBUTE_TYPE_MASK;
	dreg.key = key;

	if (array_bsearch_insert_pos(&mailbox_internal_attributes,
				     &dreg, mailbox_attribute_internal_cmp,
				     &insert_idx)) {
		/* exact match */
		return array_idx(&mailbox_internal_attributes, insert_idx);
	}
	if (insert_idx == 0) {
		/* not found at all */
		return NULL;
	}
	iattr = array_idx(&mailbox_internal_attributes, insert_idx-1);
	if (!str_begins(key, iattr->key)) {
		/* iattr isn't a prefix of key */
		return NULL;
	} else if ((iattr->flags & MAIL_ATTRIBUTE_INTERNAL_FLAG_CHILDREN) != 0) {
		/* iattr is a prefix of key and it wants to handle the key */
		return iattr;
	} else {
		return NULL;
	}
}

static const struct mailbox_attribute_internal *
mailbox_internal_attribute_get(enum mail_attribute_type type_flags,
			       const char *key)
{
	const struct mailbox_attribute_internal *iattr;

	iattr = mailbox_internal_attribute_get_int(type_flags, key);
	if ((type_flags & MAIL_ATTRIBUTE_TYPE_FLAG_VALIDATED) != 0 &&
	    iattr != NULL &&
	    (iattr->flags & MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED) == 0) {
		/* only validated attributes can be accessed */
		iattr = NULL;
	}
	return iattr;
}

static void
mailbox_internal_attributes_get(enum mail_attribute_type type_flags,
	const char *prefix, bool have_dict, ARRAY_TYPE(const_string) *attrs)
{
	const struct mailbox_attribute_internal *regs;
	struct mailbox_attribute_internal dreg;
	char *bare_prefix;
	size_t plen;
	unsigned int count, i;

	bare_prefix = t_strdup_noconst(prefix);
	plen = strlen(bare_prefix);
	if (plen > 0 && bare_prefix[plen-1] == '/') {
		bare_prefix[plen-1] = '\0';
		plen--;
	}

	i_zero(&dreg);
	dreg.type = type_flags & MAIL_ATTRIBUTE_TYPE_MASK;
	dreg.key = bare_prefix;

	(void)array_bsearch_insert_pos(&mailbox_internal_attributes,
		&dreg, mailbox_attribute_internal_cmp, &i);

	regs = array_get(&mailbox_internal_attributes, &count);
	for (; i < count; i++) {
		const char *key = regs[i].key;

		if (regs[i].type != dreg.type)
			return;
		if ((type_flags & MAIL_ATTRIBUTE_TYPE_FLAG_VALIDATED) != 0 &&
		    (regs[i].flags & MAIL_ATTRIBUTE_INTERNAL_FLAG_VALIDATED) == 0)
			continue;

		if (plen > 0) {
			if (strncmp(key, bare_prefix, plen) != 0)
				return;
			if (key[plen] == '/') {
				/* remove prefix */
				key += plen + 1;
			} else if (key[plen] == '\0') {
				/* list the key itself, so this becomes an
				   empty key string. it's the same as how the
				   dict backend works too. */
				key += plen;
			} else {
				return;
			}
		}
		if (have_dict || regs[i].rank == MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY)
			array_push_back(attrs, &key);
	}
}

/*
 * Attribute API
 */

static int
mailbox_attribute_set_common(struct mailbox_transaction_context *t,
			     enum mail_attribute_type type_flags,
			     const char *key,
			     const struct mail_attribute_value *value)
{
	enum mail_attribute_type type =
		type_flags & MAIL_ATTRIBUTE_TYPE_MASK;
	const struct mailbox_attribute_internal *iattr;
	int ret;

	iattr = mailbox_internal_attribute_get(type_flags, key);

	/* allow internal server attribute only for inbox */
	if (iattr != NULL && !t->box->inbox_any &&
	    str_begins(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER))
		iattr = NULL;

	/* handle internal attribute */
	if (iattr != NULL) {
		switch (iattr->rank) {
		case MAIL_ATTRIBUTE_INTERNAL_RANK_DEFAULT:
		case MAIL_ATTRIBUTE_INTERNAL_RANK_OVERRIDE:
			/* notify about assignment */
			if (iattr->set != NULL && iattr->set(t, key, value) < 0)
				return -1;
			break;
		case MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY:
			if (iattr->set == NULL) {
				mail_storage_set_error(t->box->storage, MAIL_ERROR_NOTPOSSIBLE, t_strdup_printf(
					"The /%s/%s attribute cannot be changed",
					(type == MAIL_ATTRIBUTE_TYPE_SHARED ? "shared" : "private"), key));
				return -1;
			}
			/* assign internal attribute */
			return iattr->set(t, key, value);
		default:
			i_unreached();
		}
		/* the value was validated. */
		type_flags &= ~MAIL_ATTRIBUTE_TYPE_FLAG_VALIDATED;
	}

	ret = t->box->v.attribute_set(t, type_flags, key, value);
	return ret;
}

int mailbox_attribute_set(struct mailbox_transaction_context *t,
			  enum mail_attribute_type type_flags, const char *key,
			  const struct mail_attribute_value *value)
{
	return mailbox_attribute_set_common(t, type_flags, key, value);
}

int mailbox_attribute_unset(struct mailbox_transaction_context *t,
			    enum mail_attribute_type type_flags, const char *key)
{
	struct mail_attribute_value value;

	i_zero(&value);
	return mailbox_attribute_set_common(t, type_flags, key, &value);
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
	while (i_stream_read_more(value->value_stream, &data, &size) > 0) {
		if (memchr(data, '\0', size) != NULL) {
			mail_storage_set_error(storage, MAIL_ERROR_PARAMS,
				"Attribute string value has NULs");
			return -1;
		}
		str_append_data(str, data, size);
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

static int
mailbox_attribute_get_common(struct mailbox *box,
			     enum mail_attribute_type type_flags,
			     const char *key,
			     struct mail_attribute_value *value_r)
{
	const struct mailbox_attribute_internal *iattr;
	int ret;

	iattr = mailbox_internal_attribute_get(type_flags, key);

	/* allow internal server attributes only for the inbox */
	if (iattr != NULL && !box->inbox_user &&
	    str_begins(key, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER))
		iattr = NULL;

	/* internal attribute */
	if (iattr != NULL) {
		switch (iattr->rank) {
		case MAIL_ATTRIBUTE_INTERNAL_RANK_OVERRIDE:
			/* we already checked that this attribute has
			   validated-flag */
			type_flags &= ~MAIL_ATTRIBUTE_TYPE_FLAG_VALIDATED;

			if (iattr->get == NULL)
				break;
			if ((ret = iattr->get(box, key, value_r)) != 0) {
				if (ret < 0)
					return -1;
				value_r->flags |= MAIL_ATTRIBUTE_VALUE_FLAG_READONLY;
				return 1;
			}
			break;
		case MAIL_ATTRIBUTE_INTERNAL_RANK_DEFAULT:
			break;
		case MAIL_ATTRIBUTE_INTERNAL_RANK_AUTHORITY:
			if ((ret = iattr->get(box, key, value_r)) <= 0)
				return ret;
			value_r->flags |= MAIL_ATTRIBUTE_VALUE_FLAG_READONLY;
			return 1;
		default:
			i_unreached();
		}
	}

	ret = box->v.attribute_get(box, type_flags, key, value_r);
	if (ret != 0)
		return ret;

	/* default entries */
	if (iattr != NULL) {
		switch (iattr->rank) {
		case MAIL_ATTRIBUTE_INTERNAL_RANK_DEFAULT:
			if (iattr->get == NULL)
				ret = 0;
			else {
				if ((ret = iattr->get(box, key, value_r)) < 0)
					return ret;
			}
			if (ret > 0) {
				value_r->flags |= MAIL_ATTRIBUTE_VALUE_FLAG_READONLY;
				return 1;
			}
			break;
		case MAIL_ATTRIBUTE_INTERNAL_RANK_OVERRIDE:
			break;
		default:
			i_unreached();
		}
	}
	return 0;
}

int mailbox_attribute_get(struct mailbox *box,
			  enum mail_attribute_type type_flags, const char *key,
			  struct mail_attribute_value *value_r)
{
	int ret;
	i_zero(value_r);
	if ((ret = mailbox_attribute_get_common(box, type_flags, key,
				value_r)) <= 0)
		return ret;
	i_assert(value_r->value != NULL);
	return 1;
}

int mailbox_attribute_get_stream(struct mailbox *box,
				 enum mail_attribute_type type_flags,
				 const char *key,
				 struct mail_attribute_value *value_r)
{
	int ret;

	i_zero(value_r);
	value_r->flags |= MAIL_ATTRIBUTE_VALUE_FLAG_INT_STREAMS;
	if ((ret = mailbox_attribute_get_common(box, type_flags, key,
				value_r)) <= 0)
		return ret;
	i_assert(value_r->value != NULL || value_r->value_stream != NULL);
	return 1;
}

struct mailbox_attribute_internal_iter { 
	struct mailbox_attribute_iter iter;

	ARRAY_TYPE(const_string) extra_attrs;
	unsigned int extra_attr_idx;

	struct mailbox_attribute_iter *real_iter;
};

struct mailbox_attribute_iter *
mailbox_attribute_iter_init(struct mailbox *box,
			    enum mail_attribute_type type_flags,
			    const char *prefix)
{
	struct mailbox_attribute_internal_iter *intiter;
	struct mailbox_attribute_iter *iter;
	ARRAY_TYPE(const_string) extra_attrs;
	const char *const *attr;
	bool have_dict;

	iter = box->v.attribute_iter_init(box, type_flags, prefix);
	i_assert(iter->box != NULL);
	box->attribute_iter_count++;

	/* check which internal attributes may apply */
	t_array_init(&extra_attrs, 4);
	have_dict = box->storage->set->mail_attribute_dict[0] != '\0';
	mailbox_internal_attributes_get(type_flags, prefix,
					have_dict, &extra_attrs);

	/* any extra internal attributes to add? */
	if (array_count(&extra_attrs) == 0) {
		/* no */
		return iter;
	}

	/* yes */
	intiter = i_new(struct mailbox_attribute_internal_iter, 1);
	intiter->real_iter = iter;
	i_array_init(&intiter->extra_attrs, 4);

	/* copy relevant attributes */
	array_foreach(&extra_attrs, attr) {
		/* skip internal server attributes unless we're iterating inbox */
		if (!box->inbox_any &&
		    strncmp(*attr, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER,
			    strlen(MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER)) == 0)
			continue;
		array_push_back(&intiter->extra_attrs, attr);
	}
	return &intiter->iter;
}

const char *mailbox_attribute_iter_next(struct mailbox_attribute_iter *iter)
{
	struct mailbox_attribute_internal_iter *intiter;
	const char *const *attrs;
	unsigned int count, i;
	const char *result;

	if (iter->box != NULL) {
		/* no internal attributes to add */
		return iter->box->v.attribute_iter_next(iter);
	}

	/* filter out duplicate results */
	intiter = (struct mailbox_attribute_internal_iter *)iter;
	attrs = array_get(&intiter->extra_attrs, &count);
	while ((result = intiter->real_iter->box->
			v.attribute_iter_next(intiter->real_iter)) != NULL) {
		for (i = 0; i < count; i++) {
			if (strcasecmp(attrs[i], result) == 0)
				break;
		}
		if (i == count) {
			/* return normally */
			return result;
		}
		/* this attribute name is also to be returned as extra;
		   skip now */
	}

	/* return extra attributes at the end */
	if (intiter->extra_attr_idx < count)
		return attrs[intiter->extra_attr_idx++];
	return NULL;
}

int mailbox_attribute_iter_deinit(struct mailbox_attribute_iter **_iter)
{
	struct mailbox_attribute_iter *iter = *_iter;
	struct mailbox_attribute_internal_iter *intiter;
	int ret;

	*_iter = NULL;

	if (iter->box != NULL) {
		/* not wrapped */
		i_assert(iter->box->attribute_iter_count > 0);
		iter->box->attribute_iter_count--;
		return iter->box->v.attribute_iter_deinit(iter);
	}

	/* wrapped */
	intiter = (struct mailbox_attribute_internal_iter *)iter;

	i_assert(intiter->real_iter->box->attribute_iter_count > 0);
	intiter->real_iter->box->attribute_iter_count--;

	ret = intiter->real_iter->box->v.attribute_iter_deinit(intiter->real_iter);
	array_free(&intiter->extra_attrs);
	i_free(intiter);
	return ret;
}
