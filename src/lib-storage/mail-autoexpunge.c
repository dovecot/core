/* Copyright (c) 2015-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "mail-user.h"
#include "mail-autoexpunge.h"

static int mailbox_autoexpunge(struct mailbox *box, time_t expire_time)
{
	struct mailbox_transaction_context *t;
	struct mail *mail;
	struct mailbox_metadata metadata;
	const struct mail_index_header *hdr;
	uint32_t seq;
	time_t timestamp;
	int ret = 0;

	/* first try to check quickly from mailbox list index if we should
	   bother opening this mailbox. */
	if (mailbox_get_metadata(box, MAILBOX_METADATA_FIRST_SAVE_DATE,
				 &metadata) == 0) {
		if (metadata.first_save_date == (time_t)-1 ||
		    metadata.first_save_date > expire_time)
			return 0;
	}

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0) {
		if (mailbox_get_last_mail_error(box) == MAIL_ERROR_NOTFOUND) {
			/* autocreated mailbox doesn't exist yet */
			return 0;
		}
		return -1;
	}

	t = mailbox_transaction_begin(box, 0);
	mail = mail_alloc(t, 0, NULL);

	hdr = mail_index_get_header(box->view);
	for (seq = 1; seq <= hdr->messages_count; seq++) {
		mail_set_seq(mail, seq);
		if (mail_get_save_date(mail, &timestamp) == 0) {
			if (timestamp > expire_time)
				break;
			mail_expunge(mail);
		} else if (mailbox_get_last_mail_error(box) == MAIL_ERROR_EXPUNGED) {
			/* already expunged */
		} else {
			/* failed */
			ret = -1;
			break;
		}
	}
	mail_free(&mail);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	return ret;
}

static void mail_namespace_autoexpunge(struct mail_namespace *ns)
{
	struct mailbox_settings *const *box_set;
	struct mailbox *box;
	time_t expire_time;
	const char *vname;

	if (!array_is_created(&ns->set->mailboxes))
		return;

	array_foreach(&ns->set->mailboxes, box_set) {
		if ((*box_set)->autoexpunge == 0 ||
		    (unsigned int)ioloop_time < (*box_set)->autoexpunge)
			continue;

		if ((*box_set)->name[0] == '\0' && ns->prefix_len > 0 &&
		    ns->prefix[ns->prefix_len-1] == mail_namespace_get_sep(ns))
			vname = t_strndup(ns->prefix, ns->prefix_len - 1);
		else
			vname = t_strconcat(ns->prefix, (*box_set)->name, NULL);
		expire_time = ioloop_time - (*box_set)->autoexpunge;
		/* autoexpunge is configured by admin, so we can safely ignore
		   any ACLs the user might normally have against expunging in
		   the mailbox. */
		box = mailbox_alloc(ns->list, vname, MAILBOX_FLAG_IGNORE_ACLS);
		if (mailbox_autoexpunge(box, expire_time) < 0) {
			i_error("Failed to autoexpunge mailbox '%s': %s",
				mailbox_get_vname(box),
				mailbox_get_last_error(box, NULL));
		}
		mailbox_free(&box);
	}
}

void mail_user_autoexpunge(struct mail_user *user)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->alias_for == NULL)
			mail_namespace_autoexpunge(ns);
	}
}
