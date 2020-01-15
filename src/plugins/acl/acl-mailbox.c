/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

/* FIXME: If we don't have permission to change flags/keywords, the changes
   should still be stored temporarily for this session. However most clients
   don't care and it's a huge job, so I currently this isn't done. The same
   problem actually exists when opening read-only mailboxes. */
#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "istream.h"
#include "mailbox-list-private.h"
#include "acl-api-private.h"
#include "acl-plugin.h"

#include <sys/stat.h>

#define ACL_MAIL_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, acl_mail_module)

struct acl_transaction_context {
	union mailbox_transaction_module_context module_ctx;
};

static MODULE_CONTEXT_DEFINE_INIT(acl_mail_module, &mail_module_register);
static struct acl_transaction_context acl_transaction_failure;

struct acl_object *acl_mailbox_get_aclobj(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);

	return abox->aclobj;
}

int acl_mailbox_right_lookup(struct mailbox *box, unsigned int right_idx)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	int ret;

	if (abox->skip_acl_checks)
		return 1;

	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(box->list);

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
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	enum acl_storage_rights save_right;

	if (abox->module_ctx.super.is_readonly(box))
		return TRUE;

	save_right = (box->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(box, save_right) > 0)
		return FALSE;
	if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_EXPUNGE) > 0)
		return FALSE;

	if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE) > 0)
		return FALSE;
	if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_DELETED) > 0)
		return FALSE;
	if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_SEEN) > 0)
		return FALSE;

	return TRUE;
}

static void acl_mailbox_free(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);

	acl_object_deinit(&abox->aclobj);
	abox->module_ctx.super.free(box);
}

static void acl_mailbox_copy_acls_from_parent(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(box->list);
	struct acl_object *parent_aclobj;
	struct acl_object_list_iter *iter;
	struct acl_rights_update update;

	i_zero(&update);
	update.modify_mode = ACL_MODIFY_MODE_REPLACE;
	update.neg_modify_mode = ACL_MODIFY_MODE_REPLACE;

	parent_aclobj = acl_object_init_from_parent(alist->rights.backend,
						    box->name);
	iter = acl_object_list_init(parent_aclobj);
	while (acl_object_list_next(iter, &update.rights)) {
		/* don't copy global ACL rights. */
		if (!update.rights.global)
			(void)acl_object_update(abox->aclobj, &update);
	}
	/* FIXME: Add error handling */
	acl_object_list_deinit(&iter);
	acl_object_deinit(&parent_aclobj);
}

static int
acl_mailbox_create(struct mailbox *box, const struct mailbox_update *update,
		   bool directory)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	int ret;

	if (!mailbox_is_autocreated(box)) {
		/* we're looking up CREATE permission from our parent's rights */
		ret = acl_mailbox_list_have_right(box->list, box->name, TRUE,
						  ACL_STORAGE_RIGHT_CREATE, NULL);
	} else {
		/* mailbox is autocreated, so we need to treat it as if it
		   already exists. ignore the "create" ACL here. */
		ret = 1;
	}
	if (ret <= 0) {
		if (ret < 0) {
			mail_storage_set_internal_error(box->storage);
			return -1;
		}
		/* Note that if user didn't have LOOKUP permission to parent
		   mailbox, this may reveal the mailbox's existence to user.
		   Can't help it. */
		mail_storage_set_error(box->storage, MAIL_ERROR_PERM,
				       MAIL_ERRSTR_NO_PERMISSION);
		return -1;
	}

	/* ignore ACLs in this mailbox until creation is complete, because
	   super.create() may call e.g. mailbox_open() which will fail since
	   we haven't yet copied ACLs to this mailbox. */
	abox->skip_acl_checks = TRUE;
	ret = abox->module_ctx.super.create_box(box, update, directory);
	abox->skip_acl_checks = FALSE;
	if (ret == 0)
		acl_mailbox_copy_acls_from_parent(box);
	return ret;
}

static int
acl_mailbox_update(struct mailbox *box, const struct mailbox_update *update)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_ADMIN);
	if (ret <= 0)
		return -1;
	return abox->module_ctx.super.update_box(box, update);
}

static void acl_mailbox_fail_not_found(struct mailbox *box)
{
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_LOOKUP);
	if (ret > 0) {
		mail_storage_set_error(box->storage, MAIL_ERROR_PERM,
				       MAIL_ERRSTR_NO_PERMISSION);
	} else if (ret == 0) {
		box->acl_no_lookup_right = TRUE;
		mail_storage_set_error(box->storage, MAIL_ERROR_NOTFOUND,
				T_MAIL_ERR_MAILBOX_NOT_FOUND(box->vname));
	}
}

static int
acl_mailbox_delete(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	int ret;

	ret = acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_DELETE);
	if (ret <= 0) {
		if (ret == 0)
			acl_mailbox_fail_not_found(box);
		return -1;
	}

	return abox->module_ctx.super.delete_box(box);
}

static int
acl_mailbox_rename(struct mailbox *src, struct mailbox *dest)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(src);
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

	return abox->module_ctx.super.rename_box(src, dest);
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

static int
acl_save_get_flags(struct mailbox *box, enum mail_flags *flags,
		   enum mail_flags *pvt_flags, struct mail_keywords **keywords)
{
	bool acl_flags, acl_flag_seen, acl_flag_del;

	if (acl_get_write_rights(box, &acl_flags, &acl_flag_seen,
				 &acl_flag_del) < 0)
		return -1;

	if (!acl_flag_seen) {
		*flags &= ~MAIL_SEEN;
		*pvt_flags &= ~MAIL_SEEN;
	}
	if (!acl_flag_del) {
		*flags &= ~MAIL_DELETED;
		*pvt_flags &= ~MAIL_DELETED;
	}
	if (!acl_flags) {
		*flags &= MAIL_SEEN | MAIL_DELETED;
		*pvt_flags &= MAIL_SEEN | MAIL_DELETED;
		*keywords = NULL;
	}
	return 0;
}

static int
acl_save_begin(struct mail_save_context *ctx, struct istream *input)
{
	struct mailbox *box = ctx->transaction->box;
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	enum acl_storage_rights save_right;

	save_right = (box->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(box, save_right) <= 0)
		return -1;
	if (acl_save_get_flags(box, &ctx->data.flags,
			       &ctx->data.pvt_flags, &ctx->data.keywords) < 0)
		return -1;

	return abox->module_ctx.super.save_begin(ctx, input);
}

static bool
acl_copy_has_rights(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox *destbox = ctx->transaction->box;
	enum acl_storage_rights save_right;

	if (ctx->moving) {
		if (acl_mailbox_right_lookup(mail->box,
					     ACL_STORAGE_RIGHT_EXPUNGE) <= 0)
			return FALSE;
	}

	save_right = (destbox->flags & MAILBOX_FLAG_POST_SESSION) != 0 ?
		ACL_STORAGE_RIGHT_POST : ACL_STORAGE_RIGHT_INSERT;
	if (acl_mailbox_right_lookup(destbox, save_right) <= 0)
		return FALSE;
	if (acl_save_get_flags(destbox, &ctx->data.flags,
			       &ctx->data.pvt_flags, &ctx->data.keywords) < 0)
		return FALSE;
	return TRUE;
}

static int
acl_copy(struct mail_save_context *ctx, struct mail *mail)
{
	struct mailbox_transaction_context *t = ctx->transaction;
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(t->box);

	if (!acl_copy_has_rights(ctx, mail)) {
		mailbox_save_cancel(&ctx);
		return -1;
	}

	return abox->module_ctx.super.copy(ctx, mail);
}

static int
acl_transaction_commit(struct mailbox_transaction_context *ctx,
		       struct mail_transaction_commit_changes *changes_r)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(ctx->box);
	void *at = ACL_CONTEXT(ctx);
	int ret;

	if (at != NULL) {
		abox->module_ctx.super.transaction_rollback(ctx);
		return -1;
	}

	ret = abox->module_ctx.super.transaction_commit(ctx, changes_r);
	if (abox->no_read_right) {
		/* don't allow IMAP client to see what UIDs the messages got */
		changes_r->no_read_perm = TRUE;
	}
	return ret;
}

static int acl_mailbox_exists(struct mailbox *box, bool auto_boxes,
			      enum mailbox_existence *existence_r)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	const char *const *rights;
	unsigned int i;

	if (acl_object_get_my_rights(abox->aclobj, pool_datastack_create(),
				     &rights) < 0)
		return -1;

	/* for now this is used only by IMAP SUBSCRIBE. we'll intentionally
	   violate RFC 4314 here, because it says SUBSCRIBE should succeed only
	   when mailbox has 'l' right. But there's no point in not allowing
	   a subscribe for a mailbox that can be selected anyway. Just the
	   opposite: subscribing to such mailboxes is a very useful feature. */
	for (i = 0; rights[i] != NULL; i++) {
		if (strcmp(rights[i], MAIL_ACL_LOOKUP) == 0 ||
		    strcmp(rights[i], MAIL_ACL_READ) == 0 ||
		    strcmp(rights[i], MAIL_ACL_INSERT) == 0)
			return abox->module_ctx.super.exists(box, auto_boxes,
							     existence_r);
	}
	*existence_r = MAILBOX_EXISTENCE_NONE;
	return 0;
}

bool acl_mailbox_have_extra_attribute_rights(struct mailbox *box)
{
	/* RFC 5464:

	   When the ACL extension [RFC4314] is present, users can only set and
	   retrieve private or shared mailbox annotations on a mailbox on which
	   they have the "l" right and any one of the "r", "s", "w", "i", or "p"
	   rights.
	*/
	const enum acl_storage_rights check_rights[] = {
		ACL_STORAGE_RIGHT_READ,
		ACL_STORAGE_RIGHT_WRITE_SEEN,
		ACL_STORAGE_RIGHT_WRITE,
		ACL_STORAGE_RIGHT_INSERT,
		ACL_STORAGE_RIGHT_POST,
	};
	for (unsigned int i = 0; i < N_ELEMENTS(check_rights); i++) {
		int ret = acl_mailbox_right_lookup(box, check_rights[i]);
		if (ret > 0)
			return TRUE;
		if (ret < 0) {
			/* unexpected error - stop checking further */
			return FALSE;
		}
	}
	return FALSE;
}

static int acl_mailbox_open_check_acl(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT_REQUIRE(box->list);
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
	} else if (box->deleting) {
		open_right = ACL_STORAGE_RIGHT_DELETE;
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
	if (open_right != ACL_STORAGE_RIGHT_READ) {
		ret = acl_object_have_right(abox->aclobj,
					    idx_arr[ACL_STORAGE_RIGHT_READ]);
		if (ret < 0)
			return -1;
		if (ret == 0)
			abox->no_read_right = TRUE;
	}
	return 0;
}

static int acl_mailbox_open(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);

	if (acl_mailbox_open_check_acl(box) < 0)
		return -1;

	return abox->module_ctx.super.open(box);
}

static int acl_mailbox_get_status(struct mailbox *box,
				  enum mailbox_status_items items,
				  struct mailbox_status *status_r)
{
	struct acl_mailbox *abox = ACL_CONTEXT_REQUIRE(box);

	if (abox->module_ctx.super.get_status(box, items, status_r) < 0)
		return -1;

	if ((items & STATUS_PERMANENT_FLAGS) != 0) {
		if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE) <= 0) {
			status_r->permanent_flags &= MAIL_DELETED|MAIL_SEEN;
			status_r->permanent_keywords = FALSE;
			status_r->allow_new_keywords = FALSE;
		}
		if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_DELETED) <= 0)
			status_r->permanent_flags &= ~MAIL_DELETED;
		if (acl_mailbox_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_SEEN) <= 0)
			status_r->permanent_flags &= ~MAIL_SEEN;
	}
	return 0;
}

void acl_mailbox_allocated(struct mailbox *box)
{
	struct acl_mailbox_list *alist = ACL_LIST_CONTEXT(box->list);
	struct mailbox_vfuncs *v = box->vlast;
	struct acl_mailbox *abox;
	bool ignore_acls = (box->flags & MAILBOX_FLAG_IGNORE_ACLS) != 0;

	if (alist == NULL) {
		/* ACLs disabled */
		return;
	}

	if (mail_namespace_is_shared_user_root(box->list->ns)) {
		/* this is the root shared namespace, which itself doesn't
		   have any existing mailboxes. */
		ignore_acls = TRUE;
	}

	abox = p_new(box->pool, struct acl_mailbox, 1);
	abox->module_ctx.super = *v;
	box->vlast = &abox->module_ctx.super;
	/* aclobj can be used for setting ACLs, even when mailbox is opened
	   with IGNORE_ACLS flag */
	abox->aclobj = acl_object_init_from_name(alist->rights.backend,
						 mailbox_get_name(box));

	v->free = acl_mailbox_free;
	if (!ignore_acls) {
		abox->acl_enabled = TRUE;
		v->is_readonly = acl_is_readonly;
		v->exists = acl_mailbox_exists;
		v->open = acl_mailbox_open;
		v->get_status = acl_mailbox_get_status;
		v->create_box = acl_mailbox_create;
		v->update_box = acl_mailbox_update;
		v->delete_box = acl_mailbox_delete;
		v->rename_box = acl_mailbox_rename;
		v->save_begin = acl_save_begin;
		v->copy = acl_copy;
		v->transaction_commit = acl_transaction_commit;
		v->attribute_set = acl_attribute_set;
		v->attribute_get = acl_attribute_get;
		v->attribute_iter_init = acl_attribute_iter_init;
		v->attribute_iter_next = acl_attribute_iter_next;
		v->attribute_iter_deinit = acl_attribute_iter_deinit;
	}
	MODULE_CONTEXT_SET(box, acl_storage_module, abox);
}

static bool
acl_mailbox_update_removed_id(struct acl_object *aclobj,
			      const struct acl_rights_update *update)
{
	struct acl_object_list_iter *iter;
	struct acl_rights rights;

	if (update->modify_mode != ACL_MODIFY_MODE_CLEAR &&
	    update->neg_modify_mode != ACL_MODIFY_MODE_CLEAR)
		return FALSE;
	if (update->modify_mode == ACL_MODIFY_MODE_CLEAR &&
	    update->neg_modify_mode == ACL_MODIFY_MODE_CLEAR)
		return TRUE;

	/* mixed clear/non-clear. see if the identifier exists anymore */
	iter = acl_object_list_init(aclobj);
	while (acl_object_list_next(iter, &rights)) {
		if (rights.id_type == update->rights.id_type &&
		    null_strcmp(rights.identifier, update->rights.identifier) == 0)
			break;
	}
	return acl_object_list_deinit(&iter) >= 0;
}

int acl_mailbox_update_acl(struct mailbox_transaction_context *t,
			   const struct acl_rights_update *update)
{
	struct acl_object *aclobj;
	const char *key;
	time_t ts = update->last_change != 0 ?
		update->last_change : ioloop_time;

	key = t_strdup_printf(MAILBOX_ATTRIBUTE_PREFIX_ACL"%s",
			      acl_rights_get_id(&update->rights));
	aclobj = acl_mailbox_get_aclobj(t->box);
	if (acl_object_update(aclobj, update) < 0) {
		mailbox_set_critical(t->box, "Failed to set ACL");
		return -1;
	}

	/* FIXME: figure out some value lengths, so maybe some day
	   quota could apply to ACLs as well. */
	if (acl_mailbox_update_removed_id(aclobj, update))
		mail_index_attribute_unset(t->itrans, FALSE, key, ts);
	else
		mail_index_attribute_set(t->itrans, FALSE, key, ts, 0);
	return 0;
}
