/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"

#include "imap-metadata.h"

struct imap_metadata_transaction {
	struct mailbox *box;
	struct mailbox_transaction_context *trans;

	enum mail_error error;
	char *error_string;

	bool server:1;
	bool validated_only:1;
};

bool imap_metadata_verify_entry_name(const char *name,
				     const char **client_error_r)
{
	unsigned int i;
	bool ok;

	if (name[0] != '/') {
		*client_error_r = "Entry name must begin with '/'";
		return FALSE;
	}
	for (i = 0; name[i] != '\0'; i++) {
		switch (name[i]) {
		case '/':
			if (i > 0 && name[i-1] == '/') {
				*client_error_r = "Entry name can't contain consecutive '/'";
				return FALSE;
			}
			if (name[i+1] == '\0') {
				*client_error_r = "Entry name can't end with '/'";
				return FALSE;
			}
			break;
		case '*':
			*client_error_r = "Entry name can't contain '*'";
			return FALSE;
		case '%':
			*client_error_r = "Entry name can't contain '%'";
			return FALSE;
		default:
			if (name[i] <= 0x19) {
				*client_error_r = "Entry name can't contain control chars";
				return FALSE;
			}
			break;
		}
	}
	T_BEGIN {
		const char *prefix, *p = strchr(name+1, '/');

		prefix = p == NULL ? name : t_strdup_until(name, p);
		ok = strcasecmp(prefix, IMAP_METADATA_PRIVATE_PREFIX) == 0 ||
			strcasecmp(prefix, IMAP_METADATA_SHARED_PREFIX) == 0;
	} T_END;
	if (!ok) {
		*client_error_r = "Entry name must begin with /private or /shared";
		return FALSE;
	}
	return TRUE;
}

static void
imap_metadata_transaction_set_error(struct imap_metadata_transaction *imtrans,
				    enum mail_error error, const char *string)
{
	i_free(imtrans->error_string);
	imtrans->error_string = i_strdup(string);
	imtrans->error = error;
}

static bool
imap_metadata_entry2key(struct imap_metadata_transaction *imtrans,
			const char *entry, enum mail_attribute_type *type_r,
			const char **key_r)
{
	const char *key_prefix = (imtrans->server ?
		MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT_SERVER : NULL);

	/* names are case-insensitive so we'll always lowercase them */
	entry = t_str_lcase(entry);

	if (str_begins(entry, IMAP_METADATA_PRIVATE_PREFIX)) {
		*key_r = entry + strlen(IMAP_METADATA_PRIVATE_PREFIX);
		*type_r = MAIL_ATTRIBUTE_TYPE_PRIVATE;
	} else {
		i_assert(str_begins(entry, IMAP_METADATA_SHARED_PREFIX));
		*key_r = entry + strlen(IMAP_METADATA_SHARED_PREFIX);
		*type_r = MAIL_ATTRIBUTE_TYPE_SHARED;
	}
	if ((*key_r)[0] == '\0') {
		/* /private or /shared prefix has no value itself */
	} else {
		i_assert((*key_r)[0] == '/');
		*key_r += 1;
	}

	if (imtrans->validated_only)
		*type_r |= MAIL_ATTRIBUTE_TYPE_FLAG_VALIDATED;

	if (str_begins(*key_r, MAILBOX_ATTRIBUTE_PREFIX_DOVECOT_PVT)) {
		/* Dovecot's internal attribute (mailbox or server).
		   don't allow accessing this. */
		return FALSE;
	}
	/* Add the server-prefix (after checking for the above internal
	   attribute). */
	if (key_prefix != NULL)
		*key_r = t_strconcat(key_prefix, *key_r, NULL);
	return TRUE;
}

static int
imap_metadata_get_mailbox_transaction(struct imap_metadata_transaction *imtrans)
{
	if (imtrans->trans != NULL)
		return 0;

	if (imtrans->box == NULL || mailbox_open(imtrans->box) < 0)
		return -1;
	imtrans->trans = mailbox_transaction_begin(imtrans->box,
			MAILBOX_TRANSACTION_FLAG_EXTERNAL, __func__);
	return 0;
}

int imap_metadata_set(struct imap_metadata_transaction *imtrans,
	const char *entry, const struct mail_attribute_value *value)
{
	enum mail_attribute_type type;
	const char *key;

	if (!imap_metadata_entry2key(imtrans, entry, &type, &key)) {
		imap_metadata_transaction_set_error(imtrans, MAIL_ERROR_PARAMS,
			"Internal mailbox attributes cannot be accessed");
		return -1;
	}

	if (imap_metadata_get_mailbox_transaction(imtrans) < 0)
		return -1;
	return (value->value == NULL && value->value_stream == NULL ?
		mailbox_attribute_unset(imtrans->trans, type, key) :
		mailbox_attribute_set(imtrans->trans, type, key, value));
}

int imap_metadata_unset(struct imap_metadata_transaction *imtrans,
			const char *entry)
{
	struct mail_attribute_value value;

	i_zero(&value);
	return imap_metadata_set(imtrans, entry, &value);
}

int imap_metadata_get(struct imap_metadata_transaction *imtrans,
		      const char *entry, struct mail_attribute_value *value_r)
{
	enum mail_attribute_type type;
	const char *key;

	i_zero(value_r);
	if (!imap_metadata_entry2key(imtrans, entry, &type, &key))
		return 0;
	return mailbox_attribute_get(imtrans->box, type, key, value_r);
}

int imap_metadata_get_stream(struct imap_metadata_transaction *imtrans,
		      const char *entry, struct mail_attribute_value *value_r)
{
	enum mail_attribute_type type;
	const char *key;

	i_zero(value_r);
	if (!imap_metadata_entry2key(imtrans, entry, &type, &key))
		return 0;
	return mailbox_attribute_get_stream(imtrans->box, type, key, value_r);
}

struct imap_metadata_iter {
	struct mailbox_attribute_iter *iter;
};

struct imap_metadata_iter *
imap_metadata_iter_init(struct imap_metadata_transaction *imtrans,
			const char *entry)
{
	struct imap_metadata_iter *iter;
	enum mail_attribute_type type;
	const char *key;

	iter = i_new(struct imap_metadata_iter, 1);
	if (imap_metadata_entry2key(imtrans, entry, &type, &key)) {
		const char *prefix =
			key[0] == '\0' ? "" : t_strconcat(key, "/", NULL);
		iter->iter = mailbox_attribute_iter_init(imtrans->box, type,
							 prefix);
	}
	return iter;
}

const char *imap_metadata_iter_next(struct imap_metadata_iter *iter)
{
	if (iter->iter == NULL)
		return NULL;
	return mailbox_attribute_iter_next(iter->iter);
}

int imap_metadata_iter_deinit(struct imap_metadata_iter **_iter)
{
	struct imap_metadata_iter *iter = *_iter;
	int ret;

	*_iter = NULL;

	if (iter->iter == NULL)
		ret = 0;
	else
		ret = mailbox_attribute_iter_deinit(&iter->iter);
	i_free(iter);
	return ret;
}

struct imap_metadata_transaction *
imap_metadata_transaction_begin(struct mailbox *box)
{
	struct imap_metadata_transaction *imtrans;

	imtrans = i_new(struct imap_metadata_transaction, 1);
	imtrans->box = box;
	return imtrans;
}

struct imap_metadata_transaction *
imap_metadata_transaction_begin_server(struct mail_user *user)
{
	struct mail_namespace *ns;
	struct mailbox *box;
	struct imap_metadata_transaction *imtrans;

	ns = mail_namespace_find_inbox(user->namespaces);
	/* Server metadata shouldn't depend on INBOX's ACLs, so ignore them. */
	box = mailbox_alloc(ns->list, "INBOX", MAILBOX_FLAG_IGNORE_ACLS);
	mailbox_set_reason(box, "Server METADATA");
	imtrans = imap_metadata_transaction_begin(box);
	imtrans->server = TRUE;
	return imtrans;
}

void imap_metadata_transaction_validated_only(struct imap_metadata_transaction *imtrans,
					      bool set)
{
	imtrans->validated_only = set;
}

static void
imap_metadata_transaction_finish(struct imap_metadata_transaction **_imtrans)
{
	struct imap_metadata_transaction *imtrans = *_imtrans;

	if (imtrans->server)
		mailbox_free(&imtrans->box);

	i_free(imtrans->error_string);
	i_free(imtrans);
	*_imtrans = NULL;
}

int imap_metadata_transaction_commit(
	struct imap_metadata_transaction **_imtrans,
	enum mail_error *error_code_r, const char **client_error_r)
{
	struct imap_metadata_transaction *imtrans = *_imtrans;
	int ret = 0;

	if (imtrans->trans != NULL) {
		const char *error = NULL;
		ret = mailbox_transaction_commit(&imtrans->trans);
		if (ret < 0)
			error = mailbox_get_last_error(imtrans->box, error_code_r);
		if (client_error_r != NULL)
			*client_error_r = error;
	}
	imap_metadata_transaction_finish(_imtrans);
	return ret;
}

void imap_metadata_transaction_rollback(
	struct imap_metadata_transaction **_imtrans)
{
	struct imap_metadata_transaction *imtrans = *_imtrans;

	if (imtrans->trans != NULL)
		mailbox_transaction_rollback(&imtrans->trans);
	imap_metadata_transaction_finish(_imtrans);
}

const char *
imap_metadata_transaction_get_last_error(
	struct imap_metadata_transaction *imtrans,
	enum mail_error *error_code_r)
{
	if  (imtrans->error != MAIL_ERROR_NONE) {
		if (error_code_r != NULL)
			*error_code_r = imtrans->error;
		return imtrans->error_string;
	}
	i_assert(imtrans->box != NULL);
	return mailbox_get_last_error(imtrans->box, error_code_r);
}
