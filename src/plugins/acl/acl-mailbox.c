/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

/* FIXME: If we don't have permission to change flags/keywords, the changes
   should still be stored temporarily for this session. However most clients
   don't care and it's a huge job, so I currently this isn't done. The same
   problem actually exists when opening read-only mailboxes. */
#include "lib.h"
#include "array.h"
#include "istream.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-plugin.h"

#include <sys/stat.h>

#define ACL_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT(obj, acl_mail_module)

struct acl_mailbox {
	union mailbox_module_context module_ctx;
	struct acl_object *aclobj;

	unsigned int save_hack:1;
};

struct acl_transaction_context {
	union mailbox_transaction_module_context module_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(acl_mail_module, &mail_module_register);
static struct acl_transaction_context acl_transaction_failure;

struct acl_backend *acl_storage_get_backend(struct mail_storage *storage)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);

	return astorage->rights.backend;
}

struct acl_object *acl_storage_get_default_aclobj(struct mail_storage *storage)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(storage);

	return astorage->rights.backend->default_aclobj;
}

struct acl_object *acl_mailbox_get_aclobj(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	return abox->aclobj;
}

int acl_mailbox_right_lookup(struct mailbox *box, unsigned int right_idx)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	struct acl_mail_storage *astorage = ACL_CONTEXT(box->storage);
	int ret;

	ret = acl_object_have_right(abox->aclobj,
			astorage->rights.acl_storage_right_idx[right_idx]);
	if (ret > 0)
		return 1;
	if (ret < 0) {
		mail_storage_set_internal_error(box->storage);
		return -1;
	}

	mail_storage_set_error(box->storage, MAIL_ERROR_PERM,
			       MAIL_ERRSTR_NO_PERMISSION);
	return 0;
}

static bool acl_is_readonly(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	enum acl_storage_rights save_right;

	if (abox->module_ctx.super.is_readonly(box))
		return TRUE;

	save_right = (box->open_flags & MAILBOX_OPEN_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(box, save_right) > 0)
		return FALSE;
	if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_EXPUNGE) > 0)
		return FALSE;

	/* Next up is the "shared flag rights" */
	if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE) > 0)
		return FALSE;
	if ((box->private_flags_mask & MAIL_DELETED) == 0 &&
	    acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_DELETED) > 0)
		return FALSE;
	if ((box->private_flags_mask & MAIL_SEEN) == 0 &&
	    acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_SEEN) > 0)
		return FALSE;

	return TRUE;
}

static bool acl_allow_new_keywords(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	if (!abox->module_ctx.super.allow_new_keywords(box))
		return FALSE;

	return acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE) > 0;
}

static int acl_mailbox_close(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	acl_object_deinit(&abox->aclobj);
	return abox->module_ctx.super.close(box);
}

static int
acl_get_write_rights(struct mailbox *box,
		     bool *flags_r, bool *flag_seen_r, bool *flag_del_r)
{
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE);
	if (ret < 0)
		return -1;
	*flags_r = ret > 0;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_SEEN);
	if (ret < 0)
		return -1;
	*flag_seen_r = ret > 0;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_DELETED);
	if (ret < 0)
		return -1;
	*flag_del_r = ret > 0;
	return 0;
}

static void acl_transaction_set_failure(struct mailbox_transaction_context *t)
{
	MODULE_CONTEXT_SET(t, acl_storage_module,
			   &acl_transaction_failure);
}

static void
acl_mail_update_flags(struct mail *_mail, enum modify_type modify_type,
		      enum mail_flags flags)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *amail = ACL_MAIL_CONTEXT(mail);
	bool acl_flags, acl_flag_seen, acl_flag_del;

	if (acl_get_write_rights(_mail->box, &acl_flags, &acl_flag_seen,
				 &acl_flag_del) < 0) {
		acl_transaction_set_failure(_mail->transaction);
		return;
	}

	if (modify_type != MODIFY_REPLACE) {
		/* adding/removing flags. just remove the disallowed
		   flags from the mask. */
		if (!acl_flags)
			flags &= MAIL_SEEN | MAIL_DELETED;
		if (!acl_flag_seen)
			flags &= ~MAIL_SEEN;
		if (!acl_flag_del)
			flags &= ~MAIL_DELETED;
	} else if (!acl_flags || !acl_flag_seen || !acl_flag_del) {
		/* we don't have permission to replace all the flags. */
		if (!acl_flags && !acl_flag_seen && !acl_flag_del) {
			/* no flag changes allowed. ignore silently. */
			return;
		}

		/* handle this by first removing the allowed flags and
		   then adding the allowed flags */
		acl_mail_update_flags(_mail, MODIFY_REMOVE, ~flags);
		if (flags != 0)
			acl_mail_update_flags(_mail, MODIFY_ADD, flags);
		return;
	}

	amail->super.update_flags(_mail, modify_type, flags);
}

static void
acl_mail_update_keywords(struct mail *_mail, enum modify_type modify_type,
			 struct mail_keywords *keywords)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *amail = ACL_MAIL_CONTEXT(mail);
	int ret;

	ret = acl_mailbox_right_lookup(_mail->box, ACL_STORAGE_RIGHT_WRITE);
	if (ret <= 0) {
		/* if we don't have permission, just silently return success. */
		if (ret < 0)
			acl_transaction_set_failure(_mail->transaction);
		return;
	}

	amail->super.update_keywords(_mail, modify_type, keywords);
}

static void acl_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *amail = ACL_MAIL_CONTEXT(mail);
	int ret;

	ret = acl_mailbox_right_lookup(_mail->box, ACL_STORAGE_RIGHT_EXPUNGE);
	if (ret <= 0) {
		/* if we don't have permission, silently return success so
		   users won't see annoying error messages in case their
		   clients try automatic expunging. */
		if (ret < 0)
			acl_transaction_set_failure(_mail->transaction);
		return;
	}

	amail->super.expunge(_mail);
}

static struct mail *
acl_mail_alloc(struct mailbox_transaction_context *t,
	       enum mail_fetch_field wanted_fields,
	       struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct acl_mailbox *abox = ACL_CONTEXT(t->box);
	union mail_module_context *amail;
	struct mail *_mail;
	struct mail_private *mail;

	_mail = abox->module_ctx.super.
		mail_alloc(t, wanted_fields, wanted_headers);
	mail = (struct mail_private *)_mail;

	amail = p_new(mail->pool, union mail_module_context, 1);
	amail->super = mail->v;

	mail->v.update_flags = acl_mail_update_flags;
	mail->v.update_keywords = acl_mail_update_keywords;
	mail->v.expunge = acl_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, acl_mail_module, amail);
	return _mail;
}

static int acl_save_get_flags(struct mailbox *box, enum mail_flags *flags,
			      struct mail_keywords **keywords)
{
	bool acl_flags, acl_flag_seen, acl_flag_del;

	if (acl_get_write_rights(box, &acl_flags, &acl_flag_seen,
				 &acl_flag_del) < 0)
		return -1;

	if (!acl_flag_seen)
		*flags &= ~MAIL_SEEN;
	if (!acl_flag_del)
		*flags &= ~MAIL_DELETED;
	if (!acl_flags) {
		*flags &= MAIL_SEEN | MAIL_DELETED;
		*keywords = NULL;
	}
	return 0;
}

static int
acl_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox *box = ctx->transaction->box;
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	enum acl_storage_rights save_right;

	save_right = (box->open_flags & MAILBOX_OPEN_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(box, save_right) <= 0)
		return -1;
	if (acl_save_get_flags(box, &ctx->flags, &ctx->keywords) < 0)
		return -1;

	return abox->module_ctx.super.save_begin(ctx, input);
}

static int
acl_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct acl_mailbox *abox = ACL_CONTEXT(t->box);
	enum acl_storage_rights save_right;

	save_right = (t->box->open_flags & MAILBOX_OPEN_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(t->box, save_right) <= 0)
		return -1;
	if (acl_save_get_flags(t->box, &ctx->flags, &ctx->keywords) < 0)
		return -1;

	return abox->module_ctx.super.copy(ctx, mail);
}

static int
acl_transaction_commit(struct mailbox_transaction_context *ctx,
		       uint32_t *uid_validity_r,
		       uint32_t *first_saved_uid_r, uint32_t *last_saved_uid_r)
{
	struct acl_mailbox *abox = ACL_CONTEXT(ctx->box);
	void *at = ACL_CONTEXT(ctx);

	if (at != NULL) {
		abox->module_ctx.super.transaction_rollback(ctx);
		return -1;
	}

	return abox->module_ctx.super.
		transaction_commit(ctx, uid_validity_r,
				   first_saved_uid_r, last_saved_uid_r);
}

static int
acl_keywords_create(struct mailbox *box, const char *const keywords[],
		    struct mail_keywords **keywords_r, bool skip_invalid)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE);
	if (ret < 0) {
		if (!skip_invalid)
			return -1;
		/* we can't return failure. assume we don't have permissions. */
		ret = 0;
	}

	if (ret == 0) {
		/* no permission to update any flags. just return empty
		   keywords list. */
		const char *null = NULL;

		return abox->module_ctx.super.keywords_create(box, &null,
							      keywords_r,
							      skip_invalid);
	}

	return abox->module_ctx.super.keywords_create(box, keywords,
						      keywords_r, skip_invalid);
}

struct mailbox *acl_mailbox_open_box(struct mailbox *box)
{
	struct acl_mail_storage *astorage = ACL_CONTEXT(box->storage);
	struct acl_mailbox *abox;

	abox = p_new(box->pool, struct acl_mailbox, 1);
	abox->module_ctx.super = box->v;
	abox->aclobj = acl_object_init_from_name(astorage->rights.backend,
						 box->storage,
						 mailbox_get_name(box));

	if ((box->open_flags & MAILBOX_OPEN_IGNORE_ACLS) == 0) {
		box->v.is_readonly = acl_is_readonly;
		box->v.allow_new_keywords = acl_allow_new_keywords;
		box->v.close = acl_mailbox_close;
		box->v.mail_alloc = acl_mail_alloc;
		box->v.save_begin = acl_save_begin;
		box->v.keywords_create = acl_keywords_create;
		box->v.copy = acl_copy;
		box->v.transaction_commit = acl_transaction_commit;
	}
	MODULE_CONTEXT_SET(box, acl_storage_module, abox);
	return box;
}
