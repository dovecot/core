/* Copyright (C) 2006 Timo Sirainen */

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

static MODULE_CONTEXT_DEFINE_INIT(acl_mail_module, &mail_module_register);

static int mailbox_acl_right_lookup(struct mailbox *box, unsigned int right_idx)
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

	if (abox->module_ctx.super.is_readonly(box))
		return TRUE;

	if (mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_INSERT) > 0)
		return FALSE;
	if (mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_EXPUNGE) > 0)
		return FALSE;

	/* Next up is the "shared flag rights" */
	if (mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_WRITE) > 0)
		return FALSE;
	if ((box->private_flags_mask & MAIL_DELETED) == 0 &&
	    mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_DELETED) > 0)
		return FALSE;
	if ((box->private_flags_mask & MAIL_SEEN) == 0 &&
	    mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_SEEN) > 0)
		return FALSE;

	return TRUE;
}

static bool acl_allow_new_keywords(struct mailbox *box)
{
	struct acl_mailbox *abox = ACL_CONTEXT(box);

	if (!abox->module_ctx.super.allow_new_keywords(box))
		return FALSE;

	return mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_WRITE) > 0;
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

	ret = mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_WRITE);
	if (ret < 0)
		return -1;
	*flags_r = ret > 0;

	ret = mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_SEEN);
	if (ret < 0)
		return -1;
	*flag_seen_r = ret > 0;

	ret = mailbox_acl_right_lookup(box, ACL_STORAGE_RIGHT_WRITE_DELETED);
	if (ret < 0)
		return -1;
	*flag_del_r = ret > 0;
	return 0;
}

static int
acl_mail_update_flags(struct mail *_mail, enum modify_type modify_type,
		      enum mail_flags flags)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *amail = ACL_MAIL_CONTEXT(mail);
	bool acl_flags, acl_flag_seen, acl_flag_del;

	if (acl_get_write_rights(_mail->box, &acl_flags, &acl_flag_seen,
				 &acl_flag_del) < 0)
		return -1;

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
			return 0;
		}

		/* handle this by first removing the allowed flags and
		   then adding the allowed flags */
		if (acl_mail_update_flags(_mail, MODIFY_REMOVE,
					  ~flags) < 0)
			return -1;
		return acl_mail_update_flags(_mail, MODIFY_ADD, flags);
	}

	return amail->super.update_flags(_mail, modify_type, flags);
}

static int
acl_mail_update_keywords(struct mail *_mail, enum modify_type modify_type,
			 struct mail_keywords *keywords)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *amail = ACL_MAIL_CONTEXT(mail);
	int ret;

	ret = mailbox_acl_right_lookup(_mail->box, ACL_STORAGE_RIGHT_WRITE);
	if (ret <= 0) {
		/* if we don't have permission, just silently return success. */
		return ret;
	}

	return amail->super.update_keywords(_mail, modify_type, keywords);
}

static int acl_mail_expunge(struct mail *_mail)
{
	struct mail_private *mail = (struct mail_private *)_mail;
	union mail_module_context *amail = ACL_MAIL_CONTEXT(mail);
	int ret;

	ret = mailbox_acl_right_lookup(_mail->box, ACL_STORAGE_RIGHT_EXPUNGE);
	if (ret <= 0) {
		/* if we don't have permission, silently return success so
		   users won't see annoying error messages in case their
		   clients try automatic expunging. */
		return ret;
	}

	return amail->super.expunge(_mail);
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
acl_save_init(struct mailbox_transaction_context *t,
	      enum mail_flags flags, struct mail_keywords *keywords,
	      time_t received_date, int timezone_offset,
	      const char *from_envelope, struct istream *input,
	      struct mail *dest_mail, struct mail_save_context **ctx_r)
{
	struct acl_mailbox *abox = ACL_CONTEXT(t->box);

	if (mailbox_acl_right_lookup(t->box, ACL_STORAGE_RIGHT_INSERT) <= 0)
		return -1;
	if (acl_save_get_flags(t->box, &flags, &keywords) < 0)
		return -1;

	return abox->module_ctx.super.
		save_init(t, flags, keywords, received_date,
			  timezone_offset, from_envelope,
			  input, dest_mail, ctx_r);
}

static int
acl_copy(struct mailbox_transaction_context *t, struct mail *mail,
	 enum mail_flags flags, struct mail_keywords *keywords,
	 struct mail *dest_mail)
{
	struct acl_mailbox *abox = ACL_CONTEXT(t->box);

	if (mailbox_acl_right_lookup(t->box, ACL_STORAGE_RIGHT_INSERT) <= 0)
		return -1;
	if (acl_save_get_flags(t->box, &flags, &keywords) < 0)
		return -1;

	return abox->module_ctx.super.copy(t, mail, flags, keywords, dest_mail);
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
	
	box->v.is_readonly = acl_is_readonly;
	box->v.allow_new_keywords = acl_allow_new_keywords;
	box->v.close = acl_mailbox_close;
	box->v.mail_alloc = acl_mail_alloc;
	box->v.save_init = acl_save_init;
	box->v.copy = acl_copy;
	MODULE_CONTEXT_SET(box, acl_storage_module, abox);
	return box;
}
