/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

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

static int
mail_storage_try_copy(struct mail_save_context **_ctx, struct mail *mail)
{
	struct mail_save_context *ctx = *_ctx;
	struct mail_private *pmail = (struct mail_private *)mail;
	struct istream *input;
	const char *from_envelope, *guid;
	time_t received_date;

	ctx->copying = TRUE;

	/* we need to open the file in any case. caching metadata is unlikely
	   to help anything. */
	pmail->v.set_uid_cache_updates(mail, TRUE);

	if (mail_get_stream(mail, NULL, NULL, &input) < 0) {
		mail_copy_set_failed(ctx, mail, "stream");
		return -1;
	}

	if (ctx->received_date == (time_t)-1) {
		if (mail_get_received_date(mail, &received_date) < 0) {
			mail_copy_set_failed(ctx, mail, "received-date");
			return -1;
		}
		mailbox_save_set_received_date(ctx, received_date, 0);
	}
	if (ctx->from_envelope == NULL) {
		if (mail_get_special(mail, MAIL_FETCH_FROM_ENVELOPE,
				     &from_envelope) < 0) {
			mail_copy_set_failed(ctx, mail, "from-envelope");
			return -1;
		}
		if (*from_envelope != '\0')
			mailbox_save_set_from_envelope(ctx, from_envelope);
	}
	if (ctx->guid == NULL) {
		if (mail_get_special(mail, MAIL_FETCH_GUID, &guid) < 0) {
			mail_copy_set_failed(ctx, mail, "guid");
			return -1;
		}
		if (*guid != '\0')
			mailbox_save_set_guid(ctx, guid);
	}

	if (mailbox_save_begin(_ctx, input) < 0)
		return -1;

	do {
		if (mailbox_save_continue(ctx) < 0)
			break;
	} while (i_stream_read(input) != -1);

	if (input->stream_errno != 0) {
		mail_storage_set_critical(ctx->transaction->box->storage,
					  "copy: i_stream_read() failed: %m");
		return -1;
	}
	return 0;
}

int mail_storage_copy(struct mail_save_context *ctx, struct mail *mail)
{
	if (ctx->keywords != NULL) {
		/* keywords gets unreferenced twice: first in
		   mailbox_save_cancel()/_finish() and second time in
		   mailbox_copy(). */
		mailbox_keywords_ref(ctx->transaction->box, ctx->keywords);
	}

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
	return src->file_create_mode == dest->file_create_mode &&
		src->file_create_gid == dest->file_create_gid &&
		!dest->disable_reflink_copy_to;
}
