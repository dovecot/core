/* Copyright (C) 2006 PT.COM / SAPO. Code by Tianyan Liu */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "dict.h"
#include "index-mail.h"
#include "index-storage.h"
#include "expire-env.h"
#include "expire-plugin.h"

#include <stdlib.h>

#define EXPIRE_CONTEXT(obj) \
	*((void **)array_idx_modifiable(&(obj)->module_contexts, \
					expire.storage_module_id))

struct expire {
	struct dict *db;
	struct expire_env *env;
	const char *username;

	unsigned int storage_module_id;
	bool storage_module_id_set;

	void (*next_hook_mail_storage_created)(struct mail_storage *storage);
};

struct expire_mail_storage {
	struct mail_storage_vfuncs super;
};

struct expire_mailbox {
	struct mailbox_vfuncs super;
	time_t expire_secs;
};

struct expire_mail {
	struct mail_vfuncs super;
};

struct expire_transaction_context {
	struct mail *mail;
	time_t first_save_time;

	unsigned int first_expunged:1;
};

/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

const char *expire_plugin_version = PACKAGE_VERSION;

static struct expire expire;

static struct mailbox_transaction_context *
expire_mailbox_transaction_begin(struct mailbox *box,
				 enum mailbox_transaction_flags flags)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct expire_transaction_context *xt;

	t = xpr_box->super.transaction_begin(box, flags);
	xt = i_new(struct expire_transaction_context, 1);
	xt->mail = mail_alloc(t, 0, NULL);

	array_idx_set(&t->module_contexts, expire.storage_module_id, &xt);
	return t;
}

static int first_nonexpunged_timestamp(struct mailbox_transaction_context *_t,
				       time_t *stamp_r)
{
	struct index_transaction_context *t =
		(struct index_transaction_context *)_t;
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(_t);
	struct mail_index_view *view = t->trans_view;
	const struct mail_index_header *hdr;
	const struct mail_index_record *rec;
	uint32_t seq;
	int ret = 0;

	/* find the first non-expunged mail. we're here because the first
	   mail was expunged, so don't bother checking it. */
	hdr = mail_index_get_header(view);
	for (seq = 2; seq <= hdr->messages_count; seq++) {
		ret = mail_index_lookup(view, seq, &rec);
		if (ret != 0)
			break;
	}
	if (ret < 0) {
		*stamp_r = 0;
		return -1;
	}

	if (ret > 0) {
		mail_set_seq(xt->mail, seq);
		*stamp_r = mail_get_save_date(xt->mail);
		if (*stamp_r == (time_t)-1)
			return -1;
	} else {
		/* everything expunged */
		*stamp_r = 0;
	}
	return 0;
}

static int
expire_mailbox_transaction_commit(struct mailbox_transaction_context *t,
				  enum mailbox_sync_flags flags)
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
		update_dict = first_nonexpunged_timestamp(t, &new_stamp) == 0;
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

	if (xpr_box->super.transaction_commit(t, flags) < 0) {
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

	xpr_box->super.transaction_rollback(t);
	i_free(xt);
}

static int expire_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	struct expire_mail *xpr_mail = EXPIRE_CONTEXT(mail);
	struct expire_transaction_context *xt =
		EXPIRE_CONTEXT(_mail->transaction);

	if (xpr_mail->super.expunge(_mail) < 0)
		return -1;

	if (_mail->seq == 1) {
		/* first mail expunged, database needs to be updated */
		xt->first_expunged = TRUE;
	}
	return 0;
}

static struct mail *
expire_mail_alloc(struct mailbox_transaction_context *t,
		  enum mail_fetch_field wanted_fields,
		  struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	struct expire_mail *xpr_mail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = xpr_box->super.mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	xpr_mail = p_new(mail->pool, struct expire_mail, 1);
	xpr_mail->super = mail->v;

	mail->v.expunge = expire_mail_expunge;
	array_idx_set(&mail->module_contexts, expire.storage_module_id,
		      &xpr_mail);
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

	ret = xpr_box->super.save_init(t, flags, keywords, received_date,
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

	ret = xpr_box->super.copy(t, mail, flags, keywords, dest_mail);
	if (ret >= 0)
		mail_set_save_time(t, dest_mail->seq);
	return ret;
}

static void mailbox_expire_hook(struct mailbox *box, time_t expire_secs)
{
	struct expire_mailbox *xpr_box;

	xpr_box = p_new(box->pool, struct expire_mailbox, 1);
	xpr_box->super = box->v;

	box->v.transaction_begin = expire_mailbox_transaction_begin;
	box->v.transaction_commit = expire_mailbox_transaction_commit;
	box->v.transaction_rollback = expire_mailbox_transaction_rollback;
	box->v.mail_alloc = expire_mail_alloc;
	box->v.save_init = expire_save_init;
	box->v.copy = expire_copy;

	xpr_box->expire_secs = expire_secs;

	array_idx_set(&box->module_contexts,
		      expire.storage_module_id, &xpr_box);
}

static struct mailbox *
expire_mailbox_open(struct mail_storage *storage, const char *name,
		    struct istream *input, enum mailbox_open_flags flags)
{
	struct expire_mail_storage *xpr_storage = EXPIRE_CONTEXT(storage);
	struct mailbox *box;
	const struct expire_box *expire_box;

	box = xpr_storage->super.mailbox_open(storage, name, input, flags);
	if (box != NULL) {
		expire_box = expire_box_find(expire.env, name);
		if (expire_box != NULL)
			mailbox_expire_hook(box, expire_box->expire_secs);
	}
	return box;
}

static void expire_mail_storage_created(struct mail_storage *storage)
{
	struct expire_mail_storage *xpr_storage;

	if (expire.next_hook_mail_storage_created != NULL)
		expire.next_hook_mail_storage_created(storage);

	xpr_storage = p_new(storage->pool, struct expire_mail_storage, 1);
	xpr_storage->super = storage->v;
	storage->v.mailbox_open = expire_mailbox_open;

	if (!expire.storage_module_id_set) {
		expire.storage_module_id = mail_storage_module_id++;
		expire.storage_module_id_set = TRUE;
	}

	array_idx_set(&storage->module_contexts,
		      expire.storage_module_id, &xpr_storage);
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
