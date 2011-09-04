/* Copyright (c) 2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "istream.h"
#include "imap-arg.h"
#include "imap-date.h"
#include "imapc-client.h"
#include "imapc-mail.h"
#include "imapc-storage.h"

static void
imapc_mail_prefetch_callback(const struct imapc_command_reply *reply,
			     void *context)
{
	struct imapc_mail *mail = context;
	struct imapc_mailbox *mbox =
		(struct imapc_mailbox *)mail->imail.mail.mail.box;

	i_assert(mail->fetch_count > 0);

	if (--mail->fetch_count == 0) {
		struct imapc_mail *const *fetch_mails;
		unsigned int i, count;

		fetch_mails = array_get(&mbox->fetch_mails, &count);
		for (i = 0; i < count; i++) {
			if (fetch_mails[i] == mail) {
				array_delete(&mbox->fetch_mails, i, 1);
				break;
			}
		}
		i_assert(i != count);
		mail->fetching_fields = 0;
	}

	if (reply->state == IMAPC_COMMAND_STATE_OK)
		;
	else if (reply->state == IMAPC_COMMAND_STATE_NO) {
		imapc_copy_error_from_reply(mbox->storage, MAIL_ERROR_PARAMS,
					    reply);
	} else {
		mail_storage_set_critical(&mbox->storage->storage,
			"imapc: Mail prefetch failed: %s", reply->text_full);
	}
	imapc_client_stop(mbox->storage->client);
}

static int
imapc_mail_send_fetch(struct mail *_mail, enum mail_fetch_field fields)
{
	struct imapc_mail *mail = (struct imapc_mail *)_mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;
	struct mail_index_view *view;
	string_t *str;
	uint32_t seq;

	if (_mail->lookup_abort != MAIL_LOOKUP_ABORT_NEVER)
		return -1;

	/* drop any fields that we may already be fetching currently */
	fields &= ~mail->fetching_fields;
	if (fields == 0)
		return 0;

	/* if we already know that the mail is expunged,
	   don't try to FETCH it */
	view = mbox->delayed_sync_view != NULL ?
		mbox->delayed_sync_view : mbox->box.view;
	if (!mail_index_lookup_seq(view, _mail->uid, &seq) ||
	    mail_index_is_expunged(view, seq)) {
		mail_set_expunged(_mail);
		return -1;
	}

	if ((fields & MAIL_FETCH_STREAM_BODY) != 0)
		fields |= MAIL_FETCH_STREAM_HEADER;

	str = t_str_new(64);
	str_printfa(str, "UID FETCH %u (", _mail->uid);
	if ((fields & MAIL_FETCH_RECEIVED_DATE) != 0)
		str_append(str, "INTERNALDATE ");
	if ((fields & MAIL_FETCH_STREAM_BODY) != 0)
		str_append(str, "BODY.PEEK[] ");
	else if ((fields & MAIL_FETCH_STREAM_HEADER) != 0)
		str_append(str, "BODY.PEEK[HEADER] ");
	str_truncate(str, str_len(str)-1);
	str_append_c(str, ')');

	pool_ref(mail->imail.mail.pool);
	mail->fetching_fields |= fields;
	if (mail->fetch_count++ == 0)
		array_append(&mbox->fetch_mails, &mail, 1);

	imapc_client_mailbox_cmdf(mbox->client_box,
				  imapc_mail_prefetch_callback,
				  mail, "%1s", str_c(str));
	mail->imail.data.prefetch_sent = TRUE;
	return 0;
}

bool imapc_mail_prefetch(struct mail *_mail)
{
	struct imapc_mail *mail = (struct imapc_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fields = 0;

	if ((mail->imail.wanted_fields & MAIL_FETCH_RECEIVED_DATE) != 0 &&
	    data->received_date == (time_t)-1)
		fields |= MAIL_FETCH_RECEIVED_DATE;

	if (data->stream == NULL && data->access_part != 0) {
		if ((data->access_part & (READ_BODY | PARSE_BODY)) != 0)
			fields |= MAIL_FETCH_STREAM_BODY;
		else
			fields |= MAIL_FETCH_STREAM_HEADER;
	}
	if (fields != 0) T_BEGIN {
		(void)imapc_mail_send_fetch(_mail, fields);
	} T_END;
	return !mail->imail.data.prefetch_sent;
}

static bool
imapc_mail_have_fields(struct imapc_mail *imail, enum mail_fetch_field fields)
{
	if ((fields & MAIL_FETCH_RECEIVED_DATE) != 0) {
		if (imail->imail.data.received_date == (time_t)-1)
			return FALSE;
		fields &= ~MAIL_FETCH_RECEIVED_DATE;
	}
	if ((fields & (MAIL_FETCH_STREAM_HEADER |
		       MAIL_FETCH_STREAM_BODY)) != 0) {
		if (imail->imail.data.stream == NULL)
			return FALSE;
		fields &= ~(MAIL_FETCH_STREAM_HEADER | MAIL_FETCH_STREAM_BODY);
	}
	i_assert(fields == 0);
	return TRUE;
}

int imapc_mail_fetch(struct mail *_mail, enum mail_fetch_field fields)
{
	struct imapc_mail *imail = (struct imapc_mail *)_mail;
	struct imapc_storage *storage =
		(struct imapc_storage *)_mail->box->storage;
	int ret;

	T_BEGIN {
		ret = imapc_mail_send_fetch(_mail, fields);
	} T_END;
	if (ret < 0)
		return -1;

	/* we'll continue waiting until we've got all the fields we wanted,
	   or until all FETCH replies have been received (i.e. some FETCHes
	   failed) */
	while (!imapc_mail_have_fields(imail, fields) && imail->fetch_count > 0)
		imapc_storage_run(storage);
	return 0;
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

	if (imail->data.stream != NULL) {
		if (!body)
			return;
		/* maybe the existing stream has no body. replace it. */
		i_stream_unref(&imail->data.stream);
	}

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

void imapc_mail_fetch_update(struct imapc_mail *mail,
			     const struct imapc_untagged_reply *reply,
			     const struct imap_arg *args)
{
	struct imapc_mailbox *mbox =
		(struct imapc_mailbox *)mail->imail.mail.mail.box;
	const char *key, *value;
	unsigned int i;
	time_t t;
	int tz;
	bool match = FALSE;

	for (i = 0; args[i].type != IMAP_ARG_EOL; i += 2) {
		if (!imap_arg_get_atom(&args[i], &key) ||
		    args[i+1].type == IMAP_ARG_EOL)
			break;

		if (strcasecmp(key, "BODY[]") == 0) {
			imapc_fetch_stream(mail, reply, &args[i+1], TRUE);
			match = TRUE;
		} else if (strcasecmp(key, "BODY[HEADER]") == 0) {
			imapc_fetch_stream(mail, reply, &args[i+1], FALSE);
			match = TRUE;
		} else if (strcasecmp(key, "INTERNALDATE") == 0) {
			if (imap_arg_get_astring(&args[i+1], &value) &&
			    imap_parse_datetime(value, &t, &tz))
				mail->imail.data.received_date = t;
			match = TRUE;
		}
	}
	if (!match) {
		/* this is only a FETCH FLAGS update for the wanted mail */
	} else {
		imapc_client_stop(mbox->storage->client);
	}
}
