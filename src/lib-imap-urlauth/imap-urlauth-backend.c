/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "hex-binary.h"
#include "randgen.h"
#include "dict.h"
#include "mail-user.h"
#include "mail-storage.h"
#include "imap-urlauth-private.h"
#include "imap-urlauth-backend.h"

#define IMAP_URLAUTH_PATH DICT_PATH_PRIVATE"imap-urlauth/"

struct imap_urlauth_backend {
	struct mail_user *user;
	struct dict *dict;
};

int imap_urlauth_backend_create(struct mail_user *user, const char *dict_uri,
				struct imap_urlauth_backend **backend_r)
{
	struct imap_urlauth_backend *backend;
	struct dict *dict;

	if (user->mail_debug)
		i_debug("imap-urlauth backend: opening backend dict URI %s", dict_uri);

	dict = dict_init(dict_uri, DICT_DATA_TYPE_STRING,
			 user->username, user->set->base_dir);
	if (dict == NULL)
		return -1;

	backend = i_new(struct imap_urlauth_backend, 1);
	backend->user = user;
	backend->dict = dict;

	random_init();
	*backend_r = backend;
	return 0;
}

void imap_urlauth_backend_destroy(struct imap_urlauth_backend **_backend)
{
	struct imap_urlauth_backend *backend = *_backend;

	*_backend = NULL;

	if (backend->dict != NULL) {
		(void)dict_wait(backend->dict);
		dict_deinit(&backend->dict);
	}
	i_free(backend);
	random_deinit();
}

static int
imap_urlauth_backend_set_key(struct imap_urlauth_backend *backend,
			     const char *path, const char *mailbox_key)
{
	struct dict_transaction_context *dtrans;

	dtrans = dict_transaction_begin(backend->dict);
	dict_set(dtrans, path, mailbox_key);
	return dict_transaction_commit(&dtrans) < 0 ? -1 : 1;
}

static int
imap_urlauth_backend_reset_key(struct imap_urlauth_backend *backend,
			       const char *path)
{
	struct dict_transaction_context *dtrans;

	dtrans = dict_transaction_begin(backend->dict);
	dict_unset(dtrans, path);
	return dict_transaction_commit(&dtrans) < 0 ? -1 : 1;
}

static int
imap_urlauth_backend_get_key(struct imap_urlauth_backend *backend,
			     const char *path, const char **mailbox_key_r)
{
	return dict_lookup(backend->dict, pool_datastack_create(), path,
			   mailbox_key_r);
}

int imap_urlauth_backend_get_mailbox_key(struct imap_urlauth_backend *backend,
					 struct mailbox *box, bool create,
					 unsigned char mailbox_key[IMAP_URLAUTH_KEY_LEN])
{
	const char *path, *mailbox_key_hex = NULL;
	const char *mailbox = mailbox_get_vname(box);
	buffer_t key_buf;
	int ret;

	path = t_strconcat(IMAP_URLAUTH_PATH, dict_escape_string(mailbox), NULL);
	if ((ret = imap_urlauth_backend_get_key(backend, path,
						&mailbox_key_hex)) < 0)
		return -1;

	if (backend->user->mail_debug) {
		i_debug("imap-urlauth backend: %skey found for mailbox %s at %s",
			(ret > 0 ? "" : "no "), mailbox, path);
	}

	if (ret == 0) {
		if (!create)
			return 0;

		/* create new key */
		random_fill(mailbox_key, IMAP_URLAUTH_KEY_LEN);
		mailbox_key_hex = binary_to_hex(mailbox_key,
						IMAP_URLAUTH_KEY_LEN);
		if ((ret = imap_urlauth_backend_set_key(backend, path,
							mailbox_key_hex)) < 0)
			return -1;
		if (backend->user->mail_debug) {
			i_debug("imap-urlauth backend: created key for mailbox %s at %s",
				mailbox, path);
		}
	} else {
		/* read existing key */
		buffer_create_from_data(&key_buf, mailbox_key,
					IMAP_URLAUTH_KEY_LEN);
		if (strlen(mailbox_key_hex) != 2*IMAP_URLAUTH_KEY_LEN ||
		    hex_to_binary(mailbox_key_hex, &key_buf) < 0 ||
		    key_buf.used != IMAP_URLAUTH_KEY_LEN) {
			i_error("imap-urlauth backend: key found for mailbox %s at %s is invalid",
				mailbox, path);
			return -1;
		}
		memcpy(mailbox_key, key_buf.data, IMAP_URLAUTH_KEY_LEN);
	}
	return 1;
}

int imap_urlauth_backend_reset_mailbox_key(struct imap_urlauth_backend *backend,
					   struct mailbox *box)
{
	const char *path, *mailbox = mailbox_get_vname(box);

	path = t_strconcat(IMAP_URLAUTH_PATH, dict_escape_string(mailbox), NULL);
	return imap_urlauth_backend_reset_key(backend, path) < 0 ? -1 : 1;
}

int imap_urlauth_backend_reset_all_keys(struct imap_urlauth_backend *backend)
{ 
	struct dict_transaction_context *dtrans;
	struct dict_iterate_context *diter;
	const char *path, *value;
	int ret = 1;

	dtrans = dict_transaction_begin(backend->dict);
	diter = dict_iterate_init(backend->dict, IMAP_URLAUTH_PATH,
				  DICT_ITERATE_FLAG_RECURSE);
	while (dict_iterate(diter, &path, &value))
		dict_unset(dtrans, path);
	
	if (dict_iterate_deinit(&diter) < 0)
		ret = -1;
	if (dict_transaction_commit(&dtrans) < 0)
		ret = -1;
	return ret;
}
