/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "randgen.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "mailbox-list-iter.h"
#include "imap-urlauth-private.h"
#include "imap-urlauth-backend.h"

#define IMAP_URLAUTH_KEY MAILBOX_ATTRIBUTE_PREFIX_DOVECOT"imap-urlauth"

static int
imap_urlauth_backend_trans_set_mailbox_key(struct mailbox *box,
					   unsigned char mailbox_key_r[IMAP_URLAUTH_KEY_LEN],
					   const char **error_r,
					   enum mail_error *error_code_r)
{
	struct mail_attribute_value urlauth_key;
	const char *mailbox_key_hex = NULL;
	int ret;

	if (mailbox_open(box) < 0) {
		*error_r = mailbox_get_last_error(box, error_code_r);
		return -1;
	}

	struct mailbox_transaction_context *t =
		mailbox_transaction_begin(box,
				MAILBOX_TRANSACTION_FLAG_EXTERNAL,
				__func__);

	/* create new key */
	random_fill(mailbox_key_r, IMAP_URLAUTH_KEY_LEN);
	mailbox_key_hex = binary_to_hex(mailbox_key_r,
					IMAP_URLAUTH_KEY_LEN);
	i_zero(&urlauth_key);
	urlauth_key.value = mailbox_key_hex;
	ret = mailbox_attribute_set(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				    IMAP_URLAUTH_KEY, &urlauth_key);

	if (mailbox_transaction_commit(&t) < 0) {
		*error_r = mailbox_get_last_error(box, error_code_r);
		ret = -1;
	}

	return ret;
}

static int
imap_urlauth_backend_trans_get_mailbox_key(struct mailbox *box,
					   bool create,
					   unsigned char mailbox_key_r[IMAP_URLAUTH_KEY_LEN],
					   const char **error_r,
					   enum mail_error *error_code_r)
{
	struct mail_user *user = mail_storage_get_user(mailbox_get_storage(box));
	struct mail_attribute_value urlauth_key;
	const char *mailbox_key_hex = NULL;
	buffer_t key_buf;
	int ret;

	*error_r = "Internal server error";
	*error_code_r = MAIL_ERROR_TEMP;

	ret = mailbox_attribute_get(box, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				    IMAP_URLAUTH_KEY, &urlauth_key);
	if (ret < 0)
		return -1;

	e_debug(user->event, "imap-urlauth: %skey found for mailbox %s",
		(ret > 0 ? "" : "no "), mailbox_get_vname(box));

	if (ret == 0) {
		if (!create)
			return 0;

		ret = imap_urlauth_backend_trans_set_mailbox_key(box,
								 mailbox_key_r,
								 error_r,
								 error_code_r);

		if (ret < 0)
			return -1;
		e_debug(user->event, "imap-urlauth: created key for mailbox %s",
			mailbox_get_vname(box));
	} else {
		/* read existing key */
		buffer_create_from_data(&key_buf, mailbox_key_r,
					IMAP_URLAUTH_KEY_LEN);
		mailbox_key_hex = urlauth_key.value;
		if (strlen(mailbox_key_hex) != 2*IMAP_URLAUTH_KEY_LEN ||
		    hex_to_binary(mailbox_key_hex, &key_buf) < 0 ||
		    key_buf.used != IMAP_URLAUTH_KEY_LEN) {
			i_error("imap-urlauth: key found for mailbox %s is invalid",
				mailbox_get_vname(box));
			return -1;
		}
	}
	return 1;
}

int imap_urlauth_backend_get_mailbox_key(struct mailbox *box, bool create,
					 unsigned char mailbox_key_r[IMAP_URLAUTH_KEY_LEN],
					 const char **error_r,
					 enum mail_error *error_code_r)
{
	int ret;

	ret = imap_urlauth_backend_trans_get_mailbox_key(box, create, mailbox_key_r, error_r, error_code_r);
	return ret;
}

int imap_urlauth_backend_reset_mailbox_key(struct mailbox *box)
{
	struct mailbox_transaction_context *t;
	int ret;

	t = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_EXTERNAL,
				      __func__);
	ret = mailbox_attribute_unset(t, MAIL_ATTRIBUTE_TYPE_PRIVATE,
				      IMAP_URLAUTH_KEY);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	return ret;
}

static int imap_urlauth_backend_mailbox_reset_key(struct mailbox *box)
{
	const char *errstr;
	enum mail_error error;

	if (mailbox_open(box) < 0) {
		errstr = mailbox_get_last_internal_error(box, &error);
		if (error == MAIL_ERROR_NOTFOUND || error == MAIL_ERROR_PERM)
			return 0;
		i_error("urlauth key reset: Couldn't open mailbox %s: %s",
			mailbox_get_vname(box), errstr);
		return -1;
	}
	return imap_urlauth_backend_reset_mailbox_key(box);
}

int imap_urlauth_backend_reset_all_keys(struct mail_user *user)
{ 
	const char *const patterns[] = { "*", NULL };
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	struct mailbox *box;
	int ret = 0;

	iter = mailbox_list_iter_init_namespaces(user->namespaces, patterns,
						 MAIL_NAMESPACE_TYPE_MASK_ALL,
						 MAILBOX_LIST_ITER_NO_AUTO_BOXES |
						 MAILBOX_LIST_ITER_SKIP_ALIASES |
						 MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		box = mailbox_alloc(info->ns->list, info->vname, 0);
		mailbox_set_reason(box, "URLAUTH reset all keys");
		if (imap_urlauth_backend_mailbox_reset_key(box) < 0)
			ret = -1;
		mailbox_free(&box);
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		i_error("urlauth key reset: Couldn't iterate mailboxes: %s",
			mailbox_list_get_last_internal_error(user->namespaces->list, NULL));
		ret = -1;
	}
	return ret;
}
