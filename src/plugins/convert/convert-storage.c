/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "file-dotlock.h"
#include "index-storage.h"
#include "mail-search.h"
#include "convert-storage.h"

#include <stdio.h>

#define CONVERT_LOCK_FILENAME ".dovecot.convert"

const struct dotlock_settings dotlock_settings = {
	MEMBER(temp_prefix) NULL,
	MEMBER(lock_suffix) NULL,

	MEMBER(timeout) 60*5,
	MEMBER(stale_timeout) 60*5,

	MEMBER(callback) NULL,
	MEMBER(context) NULL,

	MEMBER(use_excl_lock) FALSE
};

static int sync_mailbox(struct mailbox *box)
{
	struct mailbox_sync_context *ctx;
        struct mailbox_sync_rec sync_rec;
	struct mailbox_status status;

	ctx = mailbox_sync_init(box, MAILBOX_SYNC_FLAG_FULL_READ);
	while (mailbox_sync_next(ctx, &sync_rec) > 0)
		;
	return mailbox_sync_deinit(&ctx, &status);
}

static int mailbox_copy_mails(struct mailbox *srcbox, struct mailbox *destbox,
			      struct dotlock *dotlock)
{
	struct mail_search_context *ctx;
	struct mailbox_transaction_context *src_trans, *dest_trans;
	struct mail *mail;
	struct mail_search_arg search_arg;
	int ret = 0;

	if (sync_mailbox(srcbox) < 0)
		return -1;

	memset(&search_arg, 0, sizeof(search_arg));
	search_arg.type = SEARCH_ALL;

	src_trans = mailbox_transaction_begin(srcbox, 0);
	dest_trans = mailbox_transaction_begin(destbox,
					MAILBOX_TRANSACTION_FLAG_EXTERNAL);

	ctx = mailbox_search_init(src_trans, NULL, &search_arg, NULL);
	mail = mail_alloc(src_trans,
			  MAIL_FETCH_FLAGS | MAIL_FETCH_RECEIVED_DATE |
			  MAIL_FETCH_STREAM_HEADER | MAIL_FETCH_STREAM_BODY |
			  MAIL_FETCH_FROM_ENVELOPE, NULL);
	while (mailbox_search_next(ctx, mail) > 0) {
		struct mail_keywords *keywords;
		const char *const *keywords_list;

		if ((mail->seq % 100) == 0) {
			/* touch the lock file so that if there are tons of
			   mails another process won't override our lock. */
			(void)file_dotlock_touch(dotlock);
		}

		keywords_list = mail_get_keywords(mail);
		keywords = strarray_length(keywords_list) == 0 ? NULL :
			mailbox_keywords_create(dest_trans, keywords_list);

		ret = mailbox_copy(dest_trans, mail, mail_get_flags(mail),
				   keywords, NULL);
		mailbox_keywords_free(dest_trans, &keywords);
		if (ret < 0)
			break;
	}

	mail_free(&mail);
	if (mailbox_search_deinit(&ctx) < 0)
		ret = -1;

	if (ret < 0)
		mailbox_transaction_rollback(&dest_trans);
	else
		ret = mailbox_transaction_commit(&dest_trans, 0);

	/* source transaction committing isn't all that important.
	   ignore if it fails. */
	if (ret < 0)
		mailbox_transaction_rollback(&src_trans);
	else
		(void)mailbox_transaction_commit(&src_trans, 0);
	return ret;
}

static int mailbox_convert_list_item(struct mail_storage *source_storage,
				     struct mail_storage *dest_storage,
				     struct mailbox_list *list,
				     struct dotlock *dotlock)
{
	const char *name;
	struct mailbox *srcbox, *destbox;
	int ret = 0;

	if ((list->flags & (MAILBOX_NONEXISTENT|MAILBOX_PLACEHOLDER)) != 0)
		return 0;

	name = strcasecmp(list->name, "INBOX") == 0 ? "INBOX" : list->name;
	if ((list->flags & MAILBOX_NOSELECT) != 0) {
		if (mail_storage_mailbox_create(dest_storage, name, TRUE) < 0) {
			i_error("Mailbox conversion: Couldn't create mailbox "
				"directory %s", name);
			return -1;
		}
		return 0;
	}

	/* It's a real mailbox. First create the destination mailbox. */
	if (mail_storage_mailbox_create(dest_storage, name, FALSE) < 0) {
		i_error("Mailbox conversion: Couldn't create mailbox %s", name);
		return -1;
	}

	/* Open both the mailboxes.. */
	srcbox = mailbox_open(source_storage, name, NULL,
			   MAILBOX_OPEN_READONLY | MAILBOX_OPEN_KEEP_RECENT);
	if (srcbox == NULL) {
		i_error("Mailbox conversion: Couldn't open source mailbox %s",
			name);
		return -1;
	}

	destbox = mailbox_open(dest_storage, name, NULL,
			       MAILBOX_OPEN_KEEP_RECENT);
	if (destbox == NULL) {
		i_error("Mailbox conversion: Couldn't open dest mailbox %s",
			name);
		mailbox_close(&srcbox);
		return -1;
	}

	if (mailbox_copy_mails(srcbox, destbox, dotlock) < 0) {
		i_error("Mailbox conversion: Couldn't copy mailbox %s",
			mailbox_get_name(srcbox));
	}

	mailbox_close(&srcbox);
	mailbox_close(&destbox);
	return ret;
}

static int mailbox_list_copy(struct mail_storage *source_storage,
			     struct mail_storage *dest_storage,
			     struct dotlock *dotlock)
{
	struct mailbox_list_context *iter;
	struct mailbox_list *list;
	int ret = 0;

	iter = mail_storage_mailbox_list_init(source_storage, "", "*",
                                              MAILBOX_LIST_FAST_FLAGS);
	while ((list = mail_storage_mailbox_list_next(iter)) != NULL) {
		if (mailbox_convert_list_item(source_storage, dest_storage,
					      list, dotlock) < 0) {
			ret = -1;
			break;
		}

		/* In case there are lots of mailboxes. Also the other touch
		   is done only after 100 mails. */
		(void)file_dotlock_touch(dotlock);
	}
	if (mail_storage_mailbox_list_deinit(&iter) < 0)
		ret = -1;
	return ret;
}

int convert_storage(const char *user, const char *home_dir,
		    const char *source_data, const char *dest_data)
{
	struct mail_storage *source_storage, *dest_storage;
	struct dotlock *dotlock;
        enum mail_storage_flags flags;
        enum mail_storage_lock_method lock_method;
	const char *path;
	int ret;

	mail_storage_parse_env(&flags, &lock_method);
	source_storage = mail_storage_create_with_data(source_data, user,
						       flags, lock_method);
	if (source_storage == NULL) {
		/* No need for conversion. */
		return 0;
	}

        path = t_strconcat(home_dir, "/"CONVERT_LOCK_FILENAME, NULL);
	ret = file_dotlock_create(&dotlock_settings, path, 0, &dotlock);
	if (ret <= 0) {
		if (ret == 0)
			i_error("Mailbox conversion: Lock creation timeouted");
		return -1;
	}

	/* just in case if another process just had converted the mailbox,
	   reopen the source storage */
	mail_storage_destroy(&source_storage);
	source_storage = mail_storage_create_with_data(source_data, user,
						       flags, lock_method);
	if (source_storage == NULL) {
		/* No need for conversion anymore. */
		file_dotlock_delete(&dotlock);
		return 0;
	}

	dest_storage = mail_storage_create_with_data(dest_data, user,
						     flags, lock_method);
	if (dest_storage == NULL) {
		i_error("Mailbox conversion: Failed to create destination "
			"storage with data: %s", dest_data);
		ret = -1;
	} else {
		ret = mailbox_list_copy(source_storage, dest_storage, dotlock);
	}

	if (ret == 0) {
		/* all finished. rename the source directory to mark the
		   move as finished. */
		const char *src, *dest;
		bool is_file;

		src = mail_storage_get_mailbox_path(source_storage, "",
						    &is_file);
		if (src != NULL) {
			dest = t_strconcat(src, "-converted", NULL);
			if (rename(src, dest) < 0) {
				i_error("Mailbox conversion: "
					"rename(%s, %s) failed: %m", src, dest);
				/* return success anyway */
			}
		}
		ret = 1;
	}

	file_dotlock_delete(&dotlock);
	if (dest_storage != NULL)
		mail_storage_destroy(&dest_storage);
	mail_storage_destroy(&source_storage);
	return ret;
}
