/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "settings.h"
#include "mailbox-list-iter.h"
#include "mail-storage-private.h"
#include "mail-namespace.h"
#include "mail-user.h"
#include "mail-autoexpunge.h"

#define AUTOEXPUNGE_LOCK_FNAME "dovecot.autoexpunge.lock"

struct mail_autoexpunge_context {
	struct mail_user *user;
	struct file_lock *lock;
	/* Earliest time when a mail in the checked mailboxes is known to
	   expire, or 0 if none. */
	time_t next_expire;
	/* Smallest autoexpunge interval in the settings, or 0 if none. */
	unsigned int min_interval;
	unsigned int expunged_count;

	/* Locking was already attempted */
	bool lock_tried:1;
	/* Another process is already autoexpunging */
	bool lock_busy:1;
};

static bool mailbox_autoexpunge_lock(struct mail_autoexpunge_context *ctx)
{
	const char *error;
	int ret;

	if (ctx->lock_tried)
		return !ctx->lock_busy;
	ctx->lock_tried = TRUE;

	/* Try to lock the autoexpunging. If the lock already exists, another
	   process is already busy with expunging, so we don't have to do it.
	   The easiest place where to store the lock file to is the home
	   directory, but allow autoexpunging to work even if we can't get
	   it. The lock isn't really required; it 1) improves performance
	   so that multiple processes won't do the same work unnecessarily,
	   and 2) it helps to avoid duplicate mails being added with
	   lazy_expunge. */
	ret = mail_user_lock_file_create(ctx->user, AUTOEXPUNGE_LOCK_FNAME,
					 0, &ctx->lock, &error);
	if (ret < 0) {
		e_error(ctx->user->event, "autoexpunge: Couldn't create %s lock: %s",
			AUTOEXPUNGE_LOCK_FNAME, error);
		/* do autoexpunging anyway */
		return TRUE;
	} else if (ret == 0) {
		/* another process is autoexpunging, so we don't need to. */
		ctx->lock_busy = TRUE;
		return FALSE;
	} else {
		return TRUE;
	}
}

static void
mail_autoexpunge_update_next_expire(struct mail_autoexpunge_context *ctx,
				    time_t expire)
{
	if (ctx->next_expire == 0 || expire < ctx->next_expire)
		ctx->next_expire = expire;
}

/* returns -1 on error, 0 when done, and 1 when there is more to do */
static int
mailbox_autoexpunge_batch(struct mail_autoexpunge_context *ctx,
			  struct mailbox *box,
			  const unsigned int interval_time,
			  const unsigned int max_mails,
			  const time_t expire_time)
{
	struct mailbox_transaction_context *t;
	struct mail *mail;
	const struct mail_index_header *hdr;
	uint32_t seq;
	time_t timestamp, last_rename_stamp = 0;
	const void *data;
	size_t size;
	unsigned int count = 0;
	bool done = FALSE, expunges_found = FALSE;
	int ret = 0;

	mail_index_get_header_ext(box->view, box->box_last_rename_stamp_ext_id,
				  &data, &size);

	if (size >= sizeof(uint32_t)) {
		last_rename_stamp = *(const uint32_t*)data;
		if (last_rename_stamp > ioloop_time+60) {
			/* Seems to be corrupted, or way too far into the
			   future. Don't trust it. */
			last_rename_stamp = 0;
		}
	}

	t = mailbox_transaction_begin(box, 0, "autoexpunge");
	mail = mail_alloc(t, 0, NULL);

	hdr = mail_index_get_header(box->view);

	for (seq = 1; seq <= I_MIN(hdr->messages_count, MAIL_EXPUNGE_BATCH_SIZE); seq++) {
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
			timestamp = I_MAX(last_rename_stamp, timestamp);
			if (timestamp > expire_time) {
				/* this is the next mail to expire */
				mail_autoexpunge_update_next_expire(ctx,
					timestamp + interval_time);
				done = TRUE;
				break;
			}
			mail_autoexpunge(mail);
			count++;
		} else if (mailbox_get_last_mail_error(box) == MAIL_ERROR_EXPUNGED) {
			/* already expunged */
			expunges_found = TRUE;
		} else {
			/* failed */
			ret = -1;
			break;
		}
	}
	mail_free(&mail);
	if (mailbox_transaction_commit(&t) < 0)
		ret = -1;
	else if (count > 0 || expunges_found) {
		if (mailbox_sync(box, 0) < 0)
			ret = -1;
		ctx->expunged_count += count;
	}

	if (ret < 0)
		return -1;
	return (done || count == 0) ? 0 : 1;
}

/* Check quickly from mailbox list index if the mailbox has anything to
   autoexpunge, without opening it. Returns 1 if yes, 0 if not, -1 on error.
   first_save_date_r is set if it was looked up, otherwise it's -1. */
static int
mailbox_autoexpunge_needed(struct mailbox *box, unsigned int interval_time,
			   unsigned int max_mails, time_t expire_time,
			   time_t *first_save_date_r)
{
	struct mailbox_metadata metadata;
	struct mailbox_status status;

	*first_save_date_r = (time_t)-1;

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
		*first_save_date_r = metadata.first_save_date;
		if (metadata.first_save_date == (time_t)-1 ||
		    metadata.first_save_date > expire_time)
			return 0;
	}
	return 1;
}

static int
mailbox_autoexpunge(struct mail_autoexpunge_context *ctx, struct mailbox *box,
		    unsigned int interval_time, unsigned int max_mails)
{
	time_t expire_time, first_save_date;
	int ret;

	if (ioloop_time32 < interval_time)
		expire_time = 0;
	else
		expire_time = ioloop_time - interval_time;

	ret = mailbox_autoexpunge_needed(box, interval_time, max_mails,
					 expire_time, &first_save_date);
	if (ret == 0 && interval_time > 0 && first_save_date != (time_t)-1) {
		/* The first mail is the next one to expire. An empty
		   mailbox doesn't need to be checked until mails are saved
		   to it. That is covered by the maximum check interval. */
		mail_autoexpunge_update_next_expire(ctx,
			first_save_date + interval_time);
	}
	if (ret <= 0)
		return ret;
	/* Lock only once something actually needs to be expunged. This
	   avoids creating the lock file at every logout and delivery. */
	if (!mailbox_autoexpunge_lock(ctx))
		return 0;

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FAST) < 0)
		return -1;

	do {
		ret = mailbox_autoexpunge_batch(ctx, box, interval_time,
						max_mails, expire_time);
	} while (ret > 0);

	return ret;
}

static void
mailbox_autoexpunge_set(struct mail_autoexpunge_context *ctx,
			struct mail_namespace *ns, const char *vname,
			unsigned int autoexpunge,
			unsigned int autoexpunge_max_mails)
{
	struct mailbox *box;

	/* autoexpunge is configured by admin, so we can safely ignore
	   any ACLs the user might normally have against expunging in
	   the mailbox. */
	box = mailbox_alloc(ns->list, vname, MAILBOX_FLAG_IGNORE_ACLS);
	if (mailbox_autoexpunge(ctx, box, autoexpunge,
				autoexpunge_max_mails) < 0) {
		e_error(box->event, "Failed to autoexpunge: %s",
			mailbox_get_last_internal_error(box, NULL));
	}
	mailbox_free(&box);
}

static void
mailbox_autoexpunge_wildcards(struct mail_autoexpunge_context *ctx,
			      struct mail_namespace *ns,
			      const struct mailbox_settings *set)
{
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	const char *iter_name;

	iter_name = t_strconcat(ns->prefix, set->name, NULL);
	iter = mailbox_list_iter_init(ns->list, iter_name,
				      MAILBOX_LIST_ITER_NO_AUTO_BOXES |
				      MAILBOX_LIST_ITER_SKIP_ALIASES |
				      MAILBOX_LIST_ITER_RETURN_NO_FLAGS);
	while (!ctx->lock_busy &&
	       (info = mailbox_list_iter_next(iter)) != NULL) T_BEGIN {
		mailbox_autoexpunge_set(ctx, ns, info->vname,
					set->autoexpunge,
					set->autoexpunge_max_mails);
	} T_END;
	if (mailbox_list_iter_deinit(&iter) < 0) {
		e_error(mailbox_list_get_event(ns->list),
			"Failed to iterate autoexpunge mailboxes '%s': %s",
			iter_name, mailbox_list_get_last_internal_error(ns->list, NULL));
	}
}

static void
mailbox_autoexpunge_name(struct mail_autoexpunge_context *ctx,
			 struct mail_namespace *ns,
			 const struct mailbox_settings *box_set)
{
	const char *vname;

	if (strpbrk(box_set->name, "*?") != NULL)
		mailbox_autoexpunge_wildcards(ctx, ns, box_set);
	else {
		if (box_set->name[0] == '\0' && ns->prefix_len > 0 &&
		    ns->prefix[ns->prefix_len-1] == mail_namespace_get_sep(ns))
			vname = t_strndup(ns->prefix, ns->prefix_len - 1);
		else
			vname = t_strconcat(ns->prefix, box_set->name, NULL);
		mailbox_autoexpunge_set(ctx, ns, vname, box_set->autoexpunge,
					box_set->autoexpunge_max_mails);
	}
}

static bool
mail_namespace_autoexpunge(struct mail_autoexpunge_context *ctx,
			   struct mail_namespace *ns)
{
	const struct mailbox_settings *box_set;

	if (!array_is_created(&ns->set->parsed_mailboxes))
		return TRUE;

	array_foreach_elem(&ns->set->parsed_mailboxes, box_set) {
		if (box_set->autoexpunge == 0 &&
		    box_set->autoexpunge_max_mails == 0) {
			/* no autoexpunging needed */
			continue;
		}
		if (box_set->autoexpunge > 0 &&
		    (ctx->min_interval == 0 ||
		     box_set->autoexpunge < ctx->min_interval))
			ctx->min_interval = box_set->autoexpunge;
		T_BEGIN {
			mailbox_autoexpunge_name(ctx, ns, box_set);
		} T_END;
		if (ctx->lock_busy) {
			/* another process is already autoexpunging */
			return FALSE;
		}
	}
	return TRUE;
}

static time_t
mail_autoexpunge_get_next_check(const struct mail_autoexpunge_context *ctx)
{
	unsigned int interval = MAIL_AUTOEXPUNGE_CHECK_MAX_INTERVAL_SECS;
	time_t next_check;

	if (ctx->lock_busy) {
		/* not all mailboxes were checked */
		return 0;
	}
	/* Mails saved later on and mailboxes that failed are checked at
	   least within the smallest autoexpunge interval. */
	if (ctx->min_interval > 0 && ctx->min_interval < interval)
		interval = ctx->min_interval;
	next_check = ioloop_time + interval;
	if (ctx->next_expire != 0 && ctx->next_expire < next_check)
		next_check = ctx->next_expire;
	return next_check;
}

unsigned int mail_user_autoexpunge(struct mail_user *user,
				   time_t *next_check_r)
{
	struct mail_autoexpunge_context ctx = {
		.user = user,
	};
	struct mail_namespace *ns;
	struct event_reason *reason =
		event_reason_begin("storage:autoexpunge");

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->alias_for == NULL) {
			if (!mail_namespace_autoexpunge(&ctx, ns))
				break;
		}
	}
	event_reason_end(&reason);
	file_lock_free(&ctx.lock);

	if (next_check_r != NULL)
		*next_check_r = mail_autoexpunge_get_next_check(&ctx);
	return ctx.expunged_count;
}
