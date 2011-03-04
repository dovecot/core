/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

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
	bool skip_acl_checks;
	bool acl_enabled;
};

struct acl_transaction_context {
	union mailbox_transaction_module_context module_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(acl_mail_module, &mail_module_register);
static struct acl_transaction_context acl_transaction_failure;

struct acl_object *acl_mailbox_get_aclobj(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	return abox->aclobj;
}

int acl_mailbox_right_lookup(struct mailbox *box, unsigned int right_idx)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(box->list);
	int ret;

	if (abox->skip_acl_checks)
		return 1;

	ret = acl_object_have_right(abox->aclobj,
			alist->rights.acl_storage_right_idx[right_idx]);
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

	save_right = (box->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
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

static void acl_mailbox_free(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	acl_object_deinit(&abox->aclobj);
	abox->module_ctx.super.free(box);
}

static void acl_mailbox_copy_acls_from_parent(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(box->list);
	struct acl_object *parent_aclobj;
	struct acl_object_list_iter *iter;
	struct acl_rights_update update;

	memset(&update, 0, sizeof(update));
	update.modify_mode = ACL_MODIFY_MODE_REPLACE;
	update.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;

	parent_aclobj = acl_object_init_from_parent(alist->rights.backend,
						    box->name);
	iter = acl_object_list_init(parent_aclobj);
	while (acl_object_list_next(iter, &update.rights) > 0) {
		/* don't copy global ACL rights. */
		if (!update.rights.global)
			(void)acl_object_update(abox->aclobj, &update);
	}
	acl_object_list_deinit(&iter);
	acl_object_deinit(&parent_aclobj);
}

static int
acl_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		   bool directory)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	/* we already checked permissions in list.mailbox_create_dir(). */
	if (abox->module_ctx.super.create(box, update, directory) < 0)
		return -1;

	acl_mailbox_copy_acls_from_parent(box);
	return 0;
}

static int
acl_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_ADMIN);
	if (ret <= 0)
		return -1;
	return abox->module_ctx.super.update(box, update);
}

static void acl_mailbox_fail_not_found(struct mailbox *box)
{
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_LOOKUP);
	if (ret > 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PERM,
				       MAIL_ERRSTR_NO_PERMISSION);
	} else if (ret == 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(box->name));
	}
}

static int
acl_mailbox_delete(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_DELETE);
	if (ret <= 0) {
		if (ret == 0)
			acl_mailbox_fail_not_found(box);
		return -1;
	}

	/* deletion might internally open the mailbox. let it succeed even if
	   we don't have READ permission. */
	abox->skip_acl_checks = TRUE;
	ret = abox->module_ctx.super.delete(box);
	abox->skip_acl_checks = FALSE;
	return ret;
}

static int
acl_mailbox_rename(struct mailbox *src, struct mailbox *dest,
		   bool rename_children)
{
	struct acl_mailbox *abox = ACL_CONTEXT(src);
	int ret;

	/* renaming requires rights to delete the old mailbox */
	ret = acl_mailbox_right_lookup(src, ACL_STORAGE_RIGHT_DELETE);
	if (ret <= 0) {
		if (ret == 0)
			acl_mailbox_fail_not_found(src);
		return -1;
	}

	/* and create the new one under the parent mailbox */
	T_BEGIN {
		ret = acl_mailbox_list_have_right(dest->list, dest->name, TRUE,
						ACL_STORAGE_RIGHT_CREATE, NULL);
	} T_END;

	if (ret <= 0) {
		if (ret == 0) {
			/* Note that if the mailbox didn't have LOOKUP
			   permission, this now reveals to user the mailbox's
			   existence. Can't help it. */
			mail_storage_set_error(src->storage, MAIL_ERROR_PERM,
					       MAIL_ERRSTR_NO_PERMISSION);
		} else {
			mail_storage_set_internal_error(src->storage);
		}
		return -1;
	}

	return abox->module_ctx.super.rename(src, dest, rename_children);
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

void acl_mail_allocated(struct mail *_mail)
{
	struct acl_mailbox *abox = ACL_CONTEXT(_mail->box);
	struct mail_private *mail = (struct mail_private *)_mail;
	struct mail_vfuncs *v = mail->vlast;
	union mail_module_context *amail;

	if (abox == NULL || !abox->acl_enabled)
		return;

	amail = p_new(mail->pool, union mail_module_context, 1);
	amail->super = *v;
	mail->vlast = &amail->super;

	v->update_flags = acl_mail_update_flags;
	v->update_keywords = acl_mail_update_keywords;
	v->expunge = acl_mail_expunge;
	MODULE_CONTEXT_SET_SELF(mail, acl_mail_module, amail);
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

	save_right = (box->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
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

	save_right = (t->box->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(t->box, save_right) <= 0)
		return -1;
	if (acl_save_get_flags(t->box, &ctx->flags, &ctx->keywords) < 0)
		return -1;

	return abox->module_ctx.super.copy(ctx, mail);
}

static int
acl_transaction_commit(struct mailbox_transaction_context *ctx,
		       struct mail_transaction_commit_changes *changes_r)
{
	struct acl_mailbox *abox = ACL_CONTEXT(ctx->box);
	void *at = ACL_CONTEXT(ctx);

	if (at != NULL) {
		abox->module_ctx.super.transaction_rollback(ctx);
		return -1;
	}

	return abox->module_ctx.super.transaction_commit(ctx, changes_r);
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

static int acl_mailbox_open_check_acl(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(box->list);
	const unsigned int *idx_arr = alist->rights.acl_storage_right_idx;
	enum acl_storage_rights open_right;
	int ret;

	/* mailbox can be opened either for reading or appending new messages */
	if ((box->flags & MAILBOX_FLAG_IGNORE_ACLS) != 0 ||
	    (box->list->ns->flags & NAMESPACE_FLAG_NOACL) != 0 ||
	    abox->skip_acl_checks)
		return 0;

	if ((box->flags & MAILBOX_FLAG_SAVEONLY) != 0) {
		open_right = (box->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
			ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	} else {
		open_right = ACL_STORAGE_RIGHT_READ;
	}

	ret = acl_object_have_right(abox->aclobj, idx_arr[open_right]);
	if (ret <= 0) {
		if (ret == 0) {
			/* no access. */
			acl_mailbox_fail_not_found(box);
		}
		return -1;
	}
	return 0;
}

static int acl_mailbox_open(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	if (acl_mailbox_open_check_acl(box) < 0)
		return -1;

	return abox->module_ctx.super.open(box);
}

void acl_mailbox_allocated(struct mailbox *box)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(box->list);
	struct mailbox_vfuncs *v = box->vlast;
	struct acl_mailbox *abox;

	if (alist == NULL) {
		/* ACLs disabled */
		return;
	}

	abox = p_new(box->pool, struct acl_mailbox, 1);
	abox->module_ctx.super = *v;
	box->vlast = &abox->module_ctx.super;
	/* aclobj can be used for setting ACLs, even when mailbox is opened
	   with IGNORE_ACLS flag */
	abox->aclobj = acl_object_init_from_name(alist->rights.backend,
						 mailbox_get_name(box));

	v->free = acl_mailbox_free;
	if ((box->flags & MAILBOX_FLAG_IGNORE_ACLS) == 0) {
		abox->acl_enabled = TRUE;
		v->is_readonly = acl_is_readonly;
		v->allow_new_keywords = acl_allow_new_keywords;
		v->open = acl_mailbox_open;
		v->create = acl_mailbox_create;
		v->update = acl_mailbox_update;
		v->delete = acl_mailbox_delete;
		v->rename = acl_mailbox_rename;
		v->save_begin = acl_save_begin;
		v->keywords_create = acl_keywords_create;
		v->copy = acl_copy;
		v->transaction_commit = acl_transaction_commit;
	}
	MODULE_CONTEXT_SET(box, acl_storage_module, abox);
}
