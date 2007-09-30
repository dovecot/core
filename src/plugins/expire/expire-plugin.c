/* Copyright (c) 2006-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "dict.h"
#include "mail-namespace.h"
#include "index-mail.h"
#include "index-storage.h"
#include "expire-env.h"
#include "expire-plugin.h"

#include <stdlib.h>

#define EXPIRE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, expire_storage_module)
#define EXPIRE_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, expire_mail_module)

struct expire {
	struct dict *db;
	struct expire_env *env;
	const char *username;

	void (*next_hook_mail_storage_created)(struct mail_storage *storage);
};

struct expire_mailbox {
	union mailbox_module_context module_ctx;
	time_t expire_secs;
};

struct expire_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	struct mail *mail;
	time_t first_save_time;

	unsigned int first_expunged:1;
};

const char *expire_plugin_version = PACKAGE_VERSION;

static struct expire expire;
static MODULE_CONTEXT_DEFINE_INIT(expire_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(expire_mail_module, &mail_module_register);

static struct mailbox_transaction_context *
expire_mailbox_transaction_begin(struct mailbox *box,
				 enum mailbox_transaction_flags flags)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct expire_transaction_context *xt;

	t = xpr_box->module_ctx.super.transaction_begin(box, flags);
	xt = i_new(struct expire_transaction_context, 1);
	xt->mail = mail_alloc(t, 0, NULL);

	MODULE_CONTEXT_SET(t, expire_storage_module, xt);
	return t;
}

static void first_nonexpunged_timestamp(struct mailbox_transaction_context *_t,
					time_t *stamp_r)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(_t);
	struct mail_index_view *view = t->trans_view;
	const struct mail_index_header *hdr;
	uint32_t seq;

	/* find the first non-expunged mail. we're here because the first
	   mail was expunged, so don't bother checking it. */
	hdr = mail_index_get_header(view);
	for (seq = 2; seq <= hdr->messages_count; seq++) {
		if (!mail_index_is_expunged(view, seq)) {
			mail_set_seq(xt->mail, seq);
			if (mail_get_save_date(xt->mail, stamp_r) == 0)
				return;
		}
	}

	/* everything expunged */
	*stamp_r = 0;
}

static int
expire_mailbox_transaction_commit(struct mailbox_transaction_context *t,
				  uint32_t *uid_validity_r,
				  uint32_t *first_saved_uid_r,
				  uint32_t *last_saved_uid_r)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(t);
	const char *key, *value;
	time_t new_stamp;
	bool update_dict;
	int ret;

	t_push();
	key = t_strconcat(DICT_PATH_SHARED, expire.username, "/",
			  t->box->name, NULL);

	if (xt->first_expunged) {
		/* first mail expunged. dict needs updating. */
		first_nonexpunged_timestamp(t, &new_stamp);
		update_dict = TRUE;
	} else {
		/* saved new mails. dict needs to be updated only if this is
		   the first mail in the database */
		ret = dict_lookup(expire.db, pool_datastack_create(),
				  key, &value);
		update_dict = ret == 0 || strtoul(value, NULL, 10) == 0;
		new_stamp = xt->first_save_time;
	}

	mail_free(&xt->mail);
	i_free(xt);

	if (xpr_box->module_ctx.super.
	    	transaction_commit(t, uid_validity_r,
				   first_saved_uid_r, last_saved_uid_r) < 0) {
		t_pop();
		return -1;
	}

	if (update_dict) {
		struct dict_transaction_context *dctx;

		new_stamp += xpr_box->expire_secs;

		dctx = dict_transaction_begin(expire.db);
		dict_set(dctx, key, dec2str(new_stamp));
		dict_transaction_commit(dctx);
	}
	t_pop();
	return 0;
}

static void
expire_mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(t);

	mail_free(&xt->mail);

	xpr_box->module_ctx.super.transaction_rollback(t);
	i_free(xt);
}

static void expire_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *xpr_mail = EXPIRE_MAIL_CONTEXT(mail);
	struct expire_transaction_context *xt =
		EXPIRE_CONTEXT(_mail->transaction);

	if (_mail->seq == 1) {
		/* first mail expunged, database needs to be updated */
		xt->first_expunged = TRUE;
	}
	xpr_mail->super.expunge(_mail);
}

static struct mail *
expire_mail_alloc(struct mailbox_transaction_context *t,
		  enum mail_fetch_field wanted_fields,
		  struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	union mail_module_context *xpr_mail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = xpr_box->module_ctx.super.
		mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	xpr_mail = p_new(mail->pool, union mail_module_context, 1);
	xpr_mail->super = mail->v;

	mail->v.expunge = expire_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, expire_mail_module, xpr_mail);
	return _mail;
}

static void
mail_set_save_time(struct mailbox_transaction_context *t, uint32_t seq)
{
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(t);
	struct index_transaction_context *it =
		(struct index_transaction_context *)t;

	if (xt->first_save_time == 0)
		xt->first_save_time = ioloop_time;

	mail_cache_add(it->cache_trans, seq, MAIL_CACHE_SAVE_DATE,
		       &ioloop_time, sizeof(ioloop_time));
}

static int
expire_save_init(struct mailbox_transaction_context *t,
		 enum mail_flags flags, struct mail_keywords *keywords,
		 time_t received_date, int timezone_offset,
		 const char *from_envelope, struct istream *input,
		 struct mail *dest_mail, struct mail_save_context **ctx_r)
{       
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(t);
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	int ret;

	if (dest_mail == NULL)
		dest_mail = xt->mail;

	ret = xpr_box->module_ctx.super.
		save_init(t, flags, keywords, received_date,
			  timezone_offset, from_envelope, input,
			  dest_mail, ctx_r);
	if (ret >= 0)
		mail_set_save_time(t, dest_mail->seq);
	return ret;
}

static int
expire_copy(struct mailbox_transaction_context *t, struct mail *mail,
	    enum mail_flags flags, struct mail_keywords *keywords,
	    struct mail *dest_mail)
{
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(t);
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	int ret;

	if (dest_mail == NULL)
		dest_mail = xt->mail;

	ret = xpr_box->module_ctx.super.
		copy(t, mail, flags, keywords, dest_mail);
	if (ret >= 0)
		mail_set_save_time(t, dest_mail->seq);
	return ret;
}

static void mailbox_expire_hook(struct mailbox *box, time_t expire_secs)
{
	struct expire_mailbox *xpr_box;

	xpr_box = p_new(box->pool, struct expire_mailbox, 1);
	xpr_box->module_ctx.super = box->v;

	box->v.transaction_begin = expire_mailbox_transaction_begin;
	box->v.transaction_commit = expire_mailbox_transaction_commit;
	box->v.transaction_rollback = expire_mailbox_transaction_rollback;
	box->v.mail_alloc = expire_mail_alloc;
	box->v.save_init = expire_save_init;
	box->v.copy = expire_copy;

	xpr_box->expire_secs = expire_secs;

	MODULE_CONTEXT_SET(box, expire_storage_module, xpr_box);
}

static struct mailbox *
expire_mailbox_open(struct mail_storage *storage, const char *name,
		    struct istream *input, enum mailbox_open_flags flags)
{
	union mail_storage_module_context *xpr_storage =
		EXPIRE_CONTEXT(storage);
	struct mailbox *box;
	const struct expire_box *expire_box;
	const char *full_name;

	box = xpr_storage->super.mailbox_open(storage, name, input, flags);
	if (box != NULL) {
		full_name = t_strconcat(storage->ns->prefix, name, NULL);
		expire_box = expire_box_find(expire.env, full_name);
		if (expire_box != NULL)
			mailbox_expire_hook(box, expire_box->expire_secs);
	}
	return box;
}

static void expire_mail_storage_created(struct mail_storage *storage)
{
	union mail_storage_module_context *xpr_storage;

	if (expire.next_hook_mail_storage_created != NULL)
		expire.next_hook_mail_storage_created(storage);

	xpr_storage =
		p_new(storage->pool, union mail_storage_module_context, 1);
	xpr_storage->super = storage->v;
	storage->v.mailbox_open = expire_mailbox_open;

	MODULE_CONTEXT_SET_SELF(storage, expire_storage_module, xpr_storage);
}

void expire_plugin_init(void)
{
	const char *env, *dict_uri;

	env = getenv("EXPIRE");
	if (env != NULL) {
		dict_uri = getenv("EXPIRE_DICT");
		if (dict_uri == NULL)
			i_fatal("expire plugin: expire_dict setting missing");

		expire.env = expire_env_init(env);
		expire.db = dict_init(dict_uri, DICT_DATA_TYPE_UINT32, NULL);
		expire.username = getenv("USER");

		expire.next_hook_mail_storage_created =
			hook_mail_storage_created;
		hook_mail_storage_created = expire_mail_storage_created;
	}
}

void expire_plugin_deinit(void)
{
	if (expire.db != NULL) {
		hook_mail_storage_created =
			expire.next_hook_mail_storage_created;

		dict_deinit(&expire.db);
		expire_env_deinit(expire.env);
	}
}
