/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "master-service.h"
#include "dict.h"
#include "mail-namespace.h"
#include "index-mail.h"
#include "index-storage.h"
#include "expire-set.h"
#include "expire-plugin.h"

#include <stdlib.h>

#define EXPIRE_CONTEXT(obj) \
	MODULE_CONTEXT(obj, expire_storage_module)
#define EXPIRE_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, expire_mail_module)
#define EXPIRE_USER_CONTEXT(obj) \
	MODULE_CONTEXT(obj, expire_mail_user_module)

struct expire_mail_user {
	union mail_user_module_context module_ctx;

	struct dict *db;
	struct expire_set *set;
};

struct expire_mailbox {
	union mailbox_module_context module_ctx;
};

struct expire_transaction_context {
	union mailbox_transaction_module_context module_ctx;

	unsigned int saves:1;
	unsigned int first_expunged:1;
};

const char *expire_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(expire_storage_module,
				  &mail_storage_module_register);
static MODULE_CONTEXT_DEFINE_INIT(expire_mail_module, &mail_module_register);
static MODULE_CONTEXT_DEFINE_INIT(expire_mail_user_module,
				  &mail_user_module_register);

static struct mailbox_transaction_context *
expire_mailbox_transaction_begin(struct mailbox *box,
				 enum mailbox_transaction_flags flags)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(box);
	struct mailbox_transaction_context *t;
	struct expire_transaction_context *xt;

	t = xpr_box->module_ctx.super.transaction_begin(box, flags);
	xt = i_new(struct expire_transaction_context, 1);

	MODULE_CONTEXT_SET(t, expire_storage_module, xt);
	return t;
}

static void first_nonexpunged_timestamp(struct mailbox_transaction_context *t,
					time_t *stamp_r)
{
	struct mail_index_view *view = t->view;
	const struct mail_index_header *hdr;
	struct mail *mail;
	uint32_t seq;

	mail = mail_alloc(t, 0, NULL);

	/* find the first non-expunged mail. we're here because the first
	   mail was expunged, so don't bother checking it. */
	hdr = mail_index_get_header(view);
	for (seq = 2; seq <= hdr->messages_count; seq++) {
		if (!mail_index_is_expunged(view, seq)) {
			mail_set_seq(mail, seq);
			if (mail_get_save_date(mail, stamp_r) == 0)
				break;
		}
	}
	mail_free(&mail);

	if (seq > hdr->messages_count) {
		/* everything expunged */
		*stamp_r = 0;
	}
}

static void first_save_timestamp(struct mailbox *box, time_t *stamp_r)
{
	struct mailbox_transaction_context *t;
	const struct mail_index_header *hdr;
	struct mail *mail;

	*stamp_r = ioloop_time;

	t = mailbox_transaction_begin(box, 0);
	mail = mail_alloc(t, 0, NULL);

	/* find the first non-expunged mail. we're here because the first
	   mail was expunged, so don't bother checking it. */
	hdr = mail_index_get_header(box->view);
	if (hdr->messages_count > 0) {
		mail_set_seq(mail, 1);
		(void)mail_get_save_date(mail, stamp_r);
	}
	mail_free(&mail);
	(void)mailbox_transaction_commit(&t);
}

static int
expire_mailbox_transaction_commit(struct mailbox_transaction_context *t,
				  struct mail_transaction_commit_changes *changes_r)
{
	struct mail_user *user = t->box->storage->user;
	struct expire_mail_user *euser = EXPIRE_USER_CONTEXT(user);
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(t);
	struct mailbox *box = t->box;
	time_t new_stamp = 0;
	bool update_dict = FALSE;
	int ret;

	if (xt->first_expunged) {
		/* first mail expunged. dict needs updating. */
		first_nonexpunged_timestamp(t, &new_stamp);
		if (new_stamp == 0 && xt->saves) {
			/* everything was expunged, but also within this
			   transaction a new message was saved */
			new_stamp = ioloop_time;
		}
		if (user->mail_debug) {
			i_debug("expire: Expunging first message in %s, "
				"updating timestamp to %ld",
				box->vname, (long)new_stamp);
		}
		update_dict = TRUE;
	}

	if (xpr_box->module_ctx.super.transaction_commit(t, changes_r) < 0) {
		i_free(xt);
		return -1;
	}
	/* transaction is freed now */
	t = NULL;

	if (xt->first_expunged || xt->saves) T_BEGIN {
		const char *key, *value;

		key = t_strconcat(DICT_EXPIRE_PREFIX,
				  box->storage->user->username, "/",
				  mailbox_get_vname(box), NULL);
		if (xt->first_expunged) {
			/* new_stamp is already set */
		} else {
			i_assert(xt->saves);
			/* saved new mails. dict needs to be updated only if
			   this is the first mail in the database */
			ret = dict_lookup(euser->db, pool_datastack_create(),
					  key, &value);
			if (ret == 0) {
				/* first time saving here with expire enabled */
				first_save_timestamp(box, &new_stamp);
				update_dict = TRUE;
			} else if (strcmp(value, "0") == 0) {
				/* we're saving the first mail to this mailbox.
				   ioloop_time may not be exactly the first
				   message's save time, but a few seconds
				   difference doesn't matter */
				new_stamp = ioloop_time;
				update_dict = TRUE;
			} else {
				/* already exists */
			}
			if (user->mail_debug && update_dict) {
				i_debug("expire: Saving first message to %s, "
					"updating timestamp to %ld",
					box->vname, (long)new_stamp);
			}
		}

		if (update_dict) {
			struct dict_transaction_context *dctx;

			dctx = dict_transaction_begin(euser->db);
			dict_set(dctx, key, dec2str(new_stamp));
			dict_transaction_commit(&dctx);
		}
	} T_END;
	i_free(xt);
	return 0;
}

static void
expire_mailbox_transaction_rollback(struct mailbox_transaction_context *t)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(t->box);
	struct expire_transaction_context *xt = EXPIRE_CONTEXT(t);

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

static void expire_mail_allocated(struct mail *_mail)
{
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(_mail->box);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *xpr_mail;

	if (xpr_box == NULL)
		return;

	xpr_mail = p_new(mail->pool, union mail_module_context, 1);
	xpr_mail->super = *v;
	mail->vlast = &xpr_mail->super;

	v->expunge = expire_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, expire_mail_module, xpr_mail);
}

static int expire_save_finish(struct mail_save_context *ctx)
{
	struct expire_transaction_context *xt =
		EXPIRE_CONTEXT(ctx->transaction);
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(ctx->transaction->box);

	xt->saves = TRUE;
	return xpr_box->module_ctx.super.save_finish(ctx);
}

static int
expire_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct expire_transaction_context *xt =
		EXPIRE_CONTEXT(ctx->transaction);
	struct expire_mailbox *xpr_box = EXPIRE_CONTEXT(ctx->transaction->box);

	xt->saves = TRUE;
	return xpr_box->module_ctx.super.copy(ctx, mail);
}

static void expire_mailbox_allocate_init(struct mailbox *box)
{
	struct mailbox_vfuncs *v = box->vlast;
	struct expire_mailbox *xpr_box;

	xpr_box = p_new(box->pool, struct expire_mailbox, 1);
	xpr_box->module_ctx.super = *v;
	box->vlast = &xpr_box->module_ctx.super;

	v->transaction_begin = expire_mailbox_transaction_begin;
	v->transaction_commit = expire_mailbox_transaction_commit;
	v->transaction_rollback = expire_mailbox_transaction_rollback;
	v->save_finish = expire_save_finish;
	v->copy = expire_copy;

	MODULE_CONTEXT_SET(box, expire_storage_module, xpr_box);
}

static void expire_mailbox_allocated(struct mailbox *box)
{
	struct expire_mail_user *euser =
		EXPIRE_USER_CONTEXT(box->storage->user);

	if (euser != NULL && expire_set_lookup(euser->set, box->vname))
		expire_mailbox_allocate_init(box);
}

static void expire_mail_user_deinit(struct mail_user *user)
{
	struct expire_mail_user *euser = EXPIRE_USER_CONTEXT(user);

	dict_deinit(&euser->db);
	expire_set_deinit(&euser->set);

	euser->module_ctx.super.deinit(user);
}

static const char *const *expire_get_patterns(struct mail_user *user)
{
	ARRAY_TYPE(const_string) patterns;
	const char *str;
	char set_name[20];
	unsigned int i;

	t_array_init(&patterns, 16);
	str = mail_user_set_plugin_getenv(user->set, "expire");
	for (i = 2; str != NULL; i++) {
		array_append(&patterns, &str, 1);

		i_snprintf(set_name, sizeof(set_name), "expire%u", i);
		str = mail_user_set_plugin_getenv(user->set, set_name);
	}
	(void)array_append_space(&patterns);
	return array_idx(&patterns, 0);
}

static void expire_mail_namespaces_created(struct mail_namespace *ns)
{
	struct mail_user *user = ns->user;
	struct expire_mail_user *euser;
	const char *dict_uri;

	dict_uri = mail_user_plugin_getenv(user, "expire_dict");
	if (mail_user_plugin_getenv(user, "expire") == NULL) {
		if (user->mail_debug)
			i_debug("expire: No expire setting - plugin disabled");
	} else if (dict_uri == NULL) {
		i_error("expire plugin: expire_dict setting missing");
	} else {
		struct mail_user_vfuncs *v = user->vlast;

		euser = p_new(user->pool, struct expire_mail_user, 1);
		euser->module_ctx.super = *v;
		user->vlast = &euser->module_ctx.super;
		v->deinit = expire_mail_user_deinit;

		euser->set = expire_set_init(expire_get_patterns(user));
		/* we're using only shared dictionary, the username
		   doesn't matter. */
		euser->db = dict_init(dict_uri, DICT_DATA_TYPE_UINT32, "",
				      user->set->base_dir);
		if (euser->db == NULL)
			i_error("expire plugin: dict_init(%s) failed", dict_uri);
		else
			MODULE_CONTEXT_SET(user, expire_mail_user_module, euser);
	}
}

static struct mail_storage_hooks expire_mail_storage_hooks = {
	.mail_namespaces_created = expire_mail_namespaces_created,
	.mailbox_allocated = expire_mailbox_allocated,
	.mail_allocated = expire_mail_allocated
};

void expire_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &expire_mail_storage_hooks);
}

void expire_plugin_deinit(void)
{
	mail_storage_hooks_remove(&expire_mail_storage_hooks);
}
