/* Copyright (c) 2015-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "mailbox-list-iter.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "mail-user.h"
#include "mail-autoexpunge.h"

#define AUTOEXPUNGE_LOCK_FNAME "dovecot.autoexpunge.lock"
#define AUTOEXPUNGE_BATCH_SIZE 1000

static bool
mailbox_autoexpunge_lock(struct mail_user *user, struct file_lock **lock)
{
	const char *error;
	int ret;

	if (*lock != NULL)
		return TRUE;

	/* Try to lock the autoexpunging. If the lock already exists, another
	   process is already busy with expunging, so we don't have to do it.
	   The easiest place where to store the lock file to is the home
	   directory, but allow autoexpunging to work even if we can't get
	   it. The lock isn't really required; it 1) improves performance
	   so that multiple processes won't do the same work unnecessarily,
	   and 2) it helps to avoid duplicate mails being added with
	   lazy_expunge. */
	ret = mail_user_lock_file_create(user, AUTOEXPUNGE_LOCK_FNAME,
					 0, lock, &error);
	if (ret < 0) {
		i_error("autoexpunge: Couldn't create %s lock: %s",
			AUTOEXPUNGE_LOCK_FNAME, error);
		/* do autoexpunging anyway */
		return TRUE;
	} else if (ret == 0) {
		/* another process is autoexpunging, so we don't need to. */
		return FALSE;
	} else {
		return TRUE;
	}
}

/* returns -1 on error, 0 when done, and 1 when there is more to do */
static int
mailbox_autoexpunge_batch(struct mailbox *box,
			  const unsigned int interval_time,
			  const unsigned int max_mails,
			  const time_t expire_time,
			  unsigned int *expunged_count)
{
	struct mailbox_transaction_context *t;
	struct mail *mail;
	const struct mail_index_header *hdr;
	uint32_t seq;
	time_t timestamp, last_rename_stamp = 0;
	const void *data;
	size_t size;
	unsigned int count = 0;
	bool done = FALSE;
	int ret = 0;

	mail_index_get_header_ext(box->view, box->box_last_rename_stamp_ext_id,
				  &data, &size);

	if (size >= sizeof(uint32_t))
		last_rename_stamp = *(const uint32_t*)data;

	t = mailbox_transaction_begin(box, 0, "autoexpunge");
	mail = mail_alloc(t, 0, NULL);

	hdr = mail_index_get_header(box->view);
	done = hdr->messages_count == 0;

	for (seq = 1; seq <= I_MIN(hdr->messages_count, AUTOEXPUNGE_BATCH_SIZE); seq++) {
		mail_set_seq(mail, seq);
		if (max_mails > 0 && hdr->messages_count - seq + 1 > max_mails) {
			/* max_mails is still being reached -> expunge.
			   don't even check saved-dates before we're
			   below max_mails. */
			mail_autoexpunge(mail);
			count++;
		} else if (interval_time == 0) {
			/* only max_mails is used. nothing further to do. */
			done = TRUE;
			break;
		} else if (mail_get_save_date(mail, &timestamp) >= 0) {
			if (I_MAX(last_rename_stamp, timestamp) > expire_time) {
				done = TRUE;
				break;
			}
			mail_autoexpunge(mail);
			count++;
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
	else if (count > 0) {
		if (mailbox_sync(box, 0) < 0)
			ret = -1;
		*expunged_count += count;
	}

	if (ret < 0)
		return -1;
	return done ? 0 : 1;
}

static int
mailbox_autoexpunge(struct mailbox *box, unsigned int interval_time,
		    unsigned int max_mails, unsigned int *expunged_count)
{
	struct mailbox_metadata metadata;
	struct mailbox_status status;
	time_t expire_time;
	int ret;

	if ((unsigned int)ioloop_time < interval_time)
		expire_time = 0;
	else
		expire_time = ioloop_time - interval_time;

	/* first try to check quickly from mailbox list index if we should
	   bother opening this mailbox. */
	if (mailbox_get_status(box, STATUS_MESSAGES, &status) < 0) {
		if (mailbox_get_last_mail_error(box) == MAIL_ERROR_NOTFOUND) {
			/* autocreated mailbox doesn't exist yet */
			return 0;
		}
		return -1;
	}
	if (interval_time == 0 && status.messages <= max_mails)
		return 0;

	if (max_mails == 0 || status.messages <= max_mails) {
		if (mailbox_get_metadata(box, MAILBOX_METADATA_FIRST_SAVE_DATE,
					 &metadata) < 0)
			return -1;
		if (metadata.first_save_date == (time_t)-1 ||
		    metadata.first_save_date > expire_time)
			return 0;
	}

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0)
		return -1;

	do {
		ret = mailbox_autoexpunge_batch(box, interval_time, max_mails,
						expire_time, expunged_count);
	} while (ret > 0);

	return ret;
}

static void
mailbox_autoexpunge_set(struct mail_namespace *ns, const char *vname,
			unsigned int autoexpunge,
			unsigned int autoexpunge_max_mails,
			unsigned int *expunged_count)
{
	struct mailbox *box;

	/* autoexpunge is configured by admin, so we can safely ignore
	   any ACLs the user might normally have against expunging in
	   the mailbox. */
	box = mailbox_alloc(ns->list, vname, MAILBOX_FLAG_IGNORE_ACLS);
	mailbox_set_reason(box, "autoexpunge");
	if (mailbox_autoexpunge(box, autoexpunge, autoexpunge_max_mails,
				expunged_count) < 0) {
		i_error("Failed to autoexpunge mailbox '%s': %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
	}
	mailbox_free(&box);
}

static void
mailbox_autoexpunge_wildcards(struct mail_namespace *ns,
			      const struct mailbox_settings *set,
			      unsigned int *expunged_count)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	const char *iter_name;

	iter_name = t_strconcat(ns->prefix, set->name, NULL);
	iter = mailbox_list_iter_init(ns->list, iter_name,
				      MAILBOX_LIST_ITER_NO_AUTO_BOXES |
				      MAILBOX_LIST_ITER_SKIP_ALIASES |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while ((info = mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		mailbox_autoexpunge_set(ns, info->vname, set->autoexpunge,
					set->autoexpunge_max_mails,
					expunged_count);
	} T_END;
	if (mailbox_list_iter_deinit(&iter) < 0) {
		i_error("Failed to iterate autoexpunge mailboxes '%s': %s",
			iter_name, mailbox_list_get_last_internal_error(ns->list, NULL));
	}
}

static bool
mail_namespace_autoexpunge(struct mail_namespace *ns, struct file_lock **lock,
			   unsigned int *expunged_count)
{
	struct mailbox_settings *const *box_set;
	const char *vname;

	if (!array_is_created(&ns->set->mailboxes))
		return TRUE;

	array_foreach(&ns->set->mailboxes, box_set) {
		if ((*box_set)->autoexpunge == 0 &&
		    (*box_set)->autoexpunge_max_mails == 0)
			continue;

		if (!mailbox_autoexpunge_lock(ns->user, lock))
			return FALSE;

		if (strpbrk((*box_set)->name, "*?") != NULL)
			mailbox_autoexpunge_wildcards(ns, *box_set, expunged_count);
		else {
			if ((*box_set)->name[0] == '\0' && ns->prefix_len > 0 &&
			    ns->prefix[ns->prefix_len-1] == mail_namespace_get_sep(ns))
				vname = t_strndup(ns->prefix, ns->prefix_len - 1);
			else
				vname = t_strconcat(ns->prefix, (*box_set)->name, NULL);
			mailbox_autoexpunge_set(ns, vname, (*box_set)->autoexpunge,
						(*box_set)->autoexpunge_max_mails,
						expunged_count);
		}
	}
	return TRUE;
}

unsigned int mail_user_autoexpunge(struct mail_user *user)
{
	struct file_lock *lock = NULL;
	struct mail_namespace *ns;
	unsigned int expunged_count = 0;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->alias_for == NULL) {
			if (!mail_namespace_autoexpunge(ns, &lock, &expunged_count))
				break;
		}
	}
	file_lock_free(&lock);
	return expunged_count;
}
