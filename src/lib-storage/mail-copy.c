/* Copyright (c) 2004-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "mail-storage-private.h"
#include "mail-copy.h"

static void
mail_copy_set_failed(struct mail_save_context *ctx, struct mail *mail,
		     const char *func)
{
	const char *errstr;
	enum mail_error error;

	if (ctx->transaction->box->storage == mail->box->storage)
		return;

	errstr = mail_storage_get_last_error(mail->box->storage, &error);
	mail_storage_set_error(ctx->transaction->box->storage, error,
			       t_strdup_printf("%s (%s)", errstr, func));
}

int mail_save_copy_default_metadata(struct mail_save_context *ctx,
				    struct mail *mail)
{
	const char *from_envelope, *guid;
	time_t received_date;

	if (ctx->data.received_date == (time_t)-1) {
		if (mail_get_received_date(mail, &received_date) < 0) {
			mail_copy_set_failed(ctx, mail, "received-date");
			return -1;
		}
		mailbox_save_set_received_date(ctx, received_date, 0);
	}
	if (ctx->data.from_envelope == NULL) {
		if (mail_get_special(mail, MAIL_FETCH_FROM_ENVELOPE,
				     &from_envelope) < 0) {
			mail_copy_set_failed(ctx, mail, "from-envelope");
			return -1;
		}
		if (*from_envelope != '\0')
			mailbox_save_set_from_envelope(ctx, from_envelope);
	}
	if (ctx->data.guid == NULL) {
		if (mail_get_special(mail, MAIL_FETCH_GUID, &guid) < 0) {
			mail_copy_set_failed(ctx, mail, "guid");
			return -1;
		}
		if (*guid != '\0')
			mailbox_save_set_guid(ctx, guid);
	}
	return 0;
}

static int
mail_storage_try_copy(struct mail_save_context **_ctx, struct mail *mail)
{
	struct mail_save_context *ctx = *_ctx;
	struct mail_private *pmail = (struct mail_private *)mail;
	struct istream *input;

	ctx->copying_via_save = TRUE;

	/* we need to open the file in any case. caching metadata is unlikely
	   to help anything. */
	pmail->v.set_uid_cache_updates(mail, TRUE);

	if (mail_get_stream_because(mail, NULL, NULL, "copying", &input) < 0) {
		mail_copy_set_failed(ctx, mail, "stream");
		return -1;
	}
	if (mail_save_copy_default_metadata(ctx, mail) < 0)
		return -1;

	if (mailbox_save_begin(_ctx, input) < 0)
		return -1;

	ssize_t ret;
	do {
		if (mailbox_save_continue(ctx) < 0)
			break;
		ret = i_stream_read(input);
		i_assert(ret != 0);
	} while (ret != -1);

	if (input->stream_errno != 0) {
		mailbox_set_critical(ctx->transaction->box,
			"copy: i_stream_read(%s) failed: %s",
			i_stream_get_name(input), i_stream_get_error(input));
		return -1;
	}
	return 0;
}

int mail_storage_copy(struct mail_save_context *ctx, struct mail *mail)
{
	i_assert(ctx->copying_or_moving);

	if (mail_storage_try_copy(&ctx, mail) < 0) {
		if (ctx != NULL)
			mailbox_save_cancel(&ctx);
		return -1;
	}
	return mailbox_save_finish(&ctx);
}

bool mail_storage_copy_can_use_hardlink(struct mailbox *src,
					struct mailbox *dest)
{
	const struct mailbox_permissions *src_perm =
		mailbox_get_permissions(src);
	const struct mailbox_permissions *dest_perm =
		mailbox_get_permissions(dest);

	if (src_perm->file_uid != dest_perm->file_uid) {
		/* if we don't have read permissions, we can't hard link
		   (basically we'll catch 0600 files here) */
		if ((src_perm->file_create_mode & 0022) == 0)
			return FALSE;
	}

	return src_perm->file_create_mode == dest_perm->file_create_mode &&
		src_perm->file_create_gid == dest_perm->file_create_gid &&
		!dest->disable_reflink_copy_to;
}
