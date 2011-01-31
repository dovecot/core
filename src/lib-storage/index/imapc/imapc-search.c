/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "write-full.h"
#include "str.h"
#include "imap-arg.h"
#include "imap-date.h"
#include "imap-util.h"
#include "mail-user.h"
#include "mail-search.h"
#include "index-search-private.h"
#include "imapc-mail.h"
#include "imapc-client.h"
#include "imapc-storage.h"

struct imapc_search_context {
	struct index_search_context ictx;

	/* non-NULL during _search_next_nonblock() */
	struct mail *cur_mail;

	/* sequences of messages we're next wanting to fetch. */
	ARRAY_TYPE(seq_range) next_seqs;
	uint32_t next_pending_seq, saved_seq;

	unsigned int fetching:1;
};

static void imapc_search_fetch_callback(const struct imapc_command_reply *reply,
					void *context)
{
	struct imapc_search_context *ctx = context;
	struct imapc_mailbox *mbox =
		(struct imapc_mailbox *)ctx->ictx.mail_ctx.transaction->box;

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(mbox->storage, MAIL_ERROR_PARAMS,
					    reply);
	} else {
		mail_storage_set_critical(&mbox->storage->storage,
			"imapc: Command failed: %s", reply->text_full);
	}
	ctx->fetching = FALSE;
	imapc_client_stop(mbox->storage->client);
}

static bool
imapc_append_wanted_fields(string_t *str, enum mail_fetch_field fields,
			   bool want_headers)
{
	bool ret = FALSE;

	if ((fields & (MAIL_FETCH_STREAM_BODY |
		       MAIL_FETCH_MESSAGE_PARTS |
		       MAIL_FETCH_NUL_STATE |
		       MAIL_FETCH_IMAP_BODY |
		       MAIL_FETCH_IMAP_BODYSTRUCTURE |
		       MAIL_FETCH_PHYSICAL_SIZE |
		       MAIL_FETCH_VIRTUAL_SIZE)) != 0) {
		str_append(str, "BODY.PEEK[] ");
		ret = TRUE;
	} else if (want_headers ||
		   (fields & (MAIL_FETCH_STREAM_HEADER |
			      MAIL_FETCH_IMAP_ENVELOPE |
			      MAIL_FETCH_HEADER_MD5 |
			      MAIL_FETCH_DATE)) != 0) {
		str_append(str, "BODY.PEEK[HEADER] ");
		ret = TRUE;
	}

	if ((fields & MAIL_FETCH_RECEIVED_DATE) != 0) {
		str_append(str, "INTERNALDATE ");
		ret = TRUE;
	}
	return ret;
}

static void
imapc_search_send_fetch(struct imapc_search_context *ctx,
			const ARRAY_TYPE(seq_range) *uids)
{
	struct mail *mail = ctx->cur_mail;
	struct mail_private *pmail = (struct mail_private *)mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)mail->box;
	string_t *str;

	str = t_str_new(64);
	str_append(str, "UID FETCH ");
	imap_write_seq_range(str, uids);
	str_append(str, " (");

	if (!imapc_append_wanted_fields(str, pmail->wanted_fields,
					pmail->wanted_headers != NULL)) {
		/* we don't need to fetch anything */
		return;
	}

	str_truncate(str, str_len(str) - 1);
	str_append_c(str, ')');

	ctx->fetching = TRUE;
	imapc_client_mailbox_cmdf(mbox->client_box, imapc_search_fetch_callback,
				  ctx, "%1s", str_c(str));
}

struct mail_search_context *
imapc_search_init(struct mailbox_transaction_context *t,
		  struct mail_search_args *args,
		  const enum mail_sort_type *sort_program)
{
	struct imapc_search_context *ctx;

	ctx = i_new(struct imapc_search_context, 1);
	index_storage_search_init_context(&ctx->ictx, t, args, sort_program);
	i_array_init(&ctx->next_seqs, 64);
	ctx->ictx.recheck_index_args = TRUE;
	return &ctx->ictx.mail_ctx;
}

int imapc_search_deinit(struct mail_search_context *_ctx)
{
	struct imapc_search_context *ctx = (struct imapc_search_context *)_ctx;
	struct imapc_mailbox *mbox =
		(struct imapc_mailbox *)_ctx->transaction->box;

	while (ctx->fetching)
		imapc_client_run(mbox->storage->client);

	array_free(&ctx->next_seqs);
	return index_storage_search_deinit(_ctx);
}

bool imapc_search_next_nonblock(struct mail_search_context *_ctx,
				struct mail *mail, bool *tryagain_r)
{
	struct imapc_search_context *ctx = (struct imapc_search_context *)_ctx;
	struct imapc_mailbox *mbox =
		(struct imapc_mailbox *)_ctx->transaction->box;
	struct imapc_mail *imail = (struct imapc_mail *)mail;
	bool ret;

	imail->searching = TRUE;
	ctx->cur_mail = mail;
	ret = index_storage_search_next_nonblock(_ctx, mail, tryagain_r);
	ctx->cur_mail = NULL;
	imail->searching = FALSE;
	if (!ret)
		return FALSE;

	if (ctx->fetching) {
		mbox->cur_fetch_mail = mail;
		imapc_client_run(mbox->storage->client);
		mbox->cur_fetch_mail = NULL;
	}
	return TRUE;
}

static void imapc_get_short_uid_range(struct mailbox *box,
				      const ARRAY_TYPE(seq_range) *seqs,
				      ARRAY_TYPE(seq_range) *uids)
{
	const struct seq_range *range;
	unsigned int i, count;
	uint32_t uid1, uid2;

	range = array_get(seqs, &count);
	for (i = 0; i < count; i++) {
		mail_index_lookup_uid(box->view, range[i].seq1, &uid1);
		mail_index_lookup_uid(box->view, range[i].seq2, &uid2);
		seq_range_array_add_range(uids, uid1, uid2);
	}
}

static void imapc_search_update_next_seqs(struct imapc_search_context *ctx)
{
	struct mail_search_context *_ctx = &ctx->ictx.mail_ctx;
	uint32_t prev_seq;

	/* add messages to the next_seqs list as long as the sequences
	   are incrementing */
	if (ctx->next_pending_seq == 0)
		prev_seq = 0;
	else {
		prev_seq = ctx->next_pending_seq;
		seq_range_array_add(&ctx->next_seqs, 0, prev_seq);
	}
	if (ctx->saved_seq != 0)
		_ctx->seq = ctx->saved_seq;
	while (index_storage_search_next_update_seq(_ctx)) {
		mail_search_args_reset(_ctx->args->args, FALSE);
		if (_ctx->seq < prev_seq) {
			ctx->next_pending_seq = _ctx->seq;
			break;
		}
		seq_range_array_add(&ctx->next_seqs, 0, _ctx->seq);
	}
	ctx->saved_seq = _ctx->seq;
	if (array_count(&ctx->next_seqs) > 0) T_BEGIN {
		ARRAY_TYPE(seq_range) uids;

		t_array_init(&uids, array_count(&ctx->next_seqs)*2);
		imapc_get_short_uid_range(_ctx->transaction->box,
					  &ctx->next_seqs, &uids);
		imapc_search_send_fetch(ctx, &uids);
	} T_END;
}

bool imapc_search_next_update_seq(struct mail_search_context *_ctx)
{
	struct imapc_search_context *ctx = (struct imapc_search_context *)_ctx;
	struct seq_range *seqs;
	unsigned int count;

	seqs = array_get_modifiable(&ctx->next_seqs, &count);
	if (count == 0) {
		imapc_search_update_next_seqs(ctx);
		seqs = array_get_modifiable(&ctx->next_seqs, &count);
		if (count == 0)
			return FALSE;
	}

	_ctx->seq = seqs[0].seq1;
	if (seqs[0].seq1 < seqs[0].seq2)
		seqs[0].seq1++;
	else
		array_delete(&ctx->next_seqs, 0, 1);
	return TRUE;
}

static bool imapc_find_lfile_arg(const struct imapc_untagged_reply *reply,
				 const struct imap_arg *arg, int *fd_r)
{
	const struct imap_arg *list;
	unsigned int i, count;

	for (i = 0; i < reply->file_args_count; i++) {
		const struct imapc_arg_file *farg = &reply->file_args[i];

		if (farg->parent_arg == arg->parent &&
		    imap_arg_get_list_full(arg->parent, &list, &count) &&
		    farg->list_idx < count && &list[farg->list_idx] == arg) {
			*fd_r = farg->fd;
			return TRUE;
		}
	}
	return FALSE;
}

static void
imapc_fetch_stream(struct imapc_mail *mail,
		   const struct imapc_untagged_reply *reply,
		   const struct imap_arg *arg, bool body)
{
	struct index_mail *imail = &mail->imail;
	struct mail *_mail = &imail->mail.mail;
	struct istream *input;
	uoff_t size;
	const char *value;
	int fd, ret;

	if (imail->data.stream != NULL)
		return;

	if (arg->type == IMAP_ARG_LITERAL_SIZE) {
		if (!imapc_find_lfile_arg(reply, arg, &fd))
			return;
		if ((fd = dup(fd)) == -1) {
			i_error("dup() failed: %m");
			return;
		}
		imail->data.stream = i_stream_create_fd(fd, 0, TRUE);
	} else {
		if (!imap_arg_get_nstring(arg, &value))
			return;
		if (value == NULL) {
			mail_set_expunged(_mail);
			return;
		}
		if (mail->body == NULL) {
			mail->body = buffer_create_dynamic(default_pool,
							   arg->str_len + 1);
		}
		buffer_set_used_size(mail->body, 0);
		buffer_append(mail->body, value, arg->str_len);
		imail->data.stream = i_stream_create_from_data(mail->body->data,
							       mail->body->used);
	}

	i_stream_set_name(imail->data.stream,
			  t_strdup_printf("imapc mail uid=%u", _mail->uid));
	index_mail_set_read_buffer_size(_mail, imail->data.stream);

	if (imail->mail.v.istream_opened != NULL) {
		if (imail->mail.v.istream_opened(_mail,
						 &imail->data.stream) < 0) {
			i_stream_unref(&imail->data.stream);
			return;
		}
	} else if (body) {
		ret = i_stream_get_size(imail->data.stream, TRUE, &size);
		if (ret < 0) {
			i_stream_unref(&imail->data.stream);
			return;
		}
		i_assert(ret != 0);
		imail->data.physical_size = size;
		/* we'll assume that the remote server is working properly and
		   sending CRLF linefeeds */
		imail->data.virtual_size = size;
	}

	if (index_mail_init_stream(imail, NULL, NULL, &input) < 0)
		i_stream_unref(&imail->data.stream);
}

void imapc_fetch_mail_update(struct mail *mail,
			     const struct imapc_untagged_reply *reply,
			     const struct imap_arg *args)
{
	struct imapc_mail *imapmail = (struct imapc_mail *)mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)mail->box;
	struct imapc_mail *imail = (struct imapc_mail *)mail;
	const char *key, *value;
	unsigned int i;
	time_t t;
	int tz;

	for (i = 0; args[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&args[i], &key) ||
		    args[i+1].type == IMAP_ARG_EOL)
			break;

		if (strcasecmp(key, "BODY[]") == 0)
			imapc_fetch_stream(imail, reply, &args[i+1], TRUE);
		else if (strcasecmp(key, "BODY[HEADER]") == 0)
			imapc_fetch_stream(imail, reply, &args[i+1], FALSE);
		else if (strcasecmp(key, "INTERNALDATE") == 0) {
			if (imap_arg_get_astring(&args[i+1], &value) &&
			    imap_parse_datetime(value, &t, &tz))
				imail->imail.data.received_date = t;
		}
	}
	if (!imapmail->fetch_one)
		imapc_client_stop_now(mbox->storage->client);
	else
		imapc_client_stop(mbox->storage->client);
}

int imapc_mail_fetch(struct mail *mail, enum mail_fetch_field fields)
{
	struct imapc_mail *imail = (struct imapc_mail *)mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)mail->box;
	struct imapc_simple_context sctx;
	string_t *str;

	str = t_str_new(64);
	str_printfa(str, "UID FETCH %u (", mail->uid);

	if (!imapc_append_wanted_fields(str, fields, FALSE))
		return 0;

	str_truncate(str, str_len(str) - 1);
	str_append_c(str, ')');

	sctx.storage = mbox->storage;
	imapc_client_mailbox_cmdf(mbox->client_box, imapc_async_stop_callback,
				  mbox->storage, "%1s", str_c(str));

	imail->fetch_one = TRUE;
	mbox->cur_fetch_mail = mail;
	imapc_client_run(mbox->storage->client);
	mbox->cur_fetch_mail = NULL;
	imail->fetch_one = FALSE;
	return sctx.ret;
}
