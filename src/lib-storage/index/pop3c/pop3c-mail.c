/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "index-mail.h"
#include "pop3c-client.h"
#include "pop3c-sync.h"
#include "pop3c-storage.h"

struct mail *
pop3c_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct pop3c_mail *mail;
	pool_t pool;

	pool = pool_alloconly_create("mail", 2048);
	mail = p_new(pool, struct pop3c_mail, 1);
	mail->imail.mail.pool = pool;

	index_mail_init(&mail->imail, t, wanted_fields, wanted_headers);
	return &mail->imail.mail.mail;
}

static void pop3c_mail_close(struct mail *_mail)
{
	struct pop3c_mail *pmail = POP3C_MAIL(_mail);
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(_mail->box);

	/* wait for any prefetch to finish before closing the mail */
	while (pmail->prefetching)
		pop3c_client_wait_one(mbox->client);
	i_stream_unref(&pmail->prefetch_stream);
	index_mail_close(_mail);
}

static int pop3c_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(_mail->box);
	int tz;

	if (mbox->storage->set->pop3c_quick_received_date) {
		/* we don't care about the date, just return the current date */
		*date_r = ioloop_time;
		return 0;
	}

	/* FIXME: we could also parse the first Received: header and get
	   the date from there, but since this code is unlikely to be called
	   except during migration, I don't think it really matters. */
	return index_mail_get_date(_mail, date_r, &tz);
}

static int pop3c_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;

	if (data->save_date == (time_t)-1) {
		/* FIXME: we could use a value stored in cache */
		if (pop3c_mail_get_received_date(_mail, date_r) < 0)
			return -1;
		return 0;
	}
	*date_r = data->save_date;
	return 0;
}

static int pop3c_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(_mail->box);
	struct message_size hdr_size, body_size;
	struct istream *input;

	if (mail->data.virtual_size != (uoff_t)-1) {
		/* virtual size is already known. it's the same as our
		   (correct) physical size */
		*size_r = mail->data.virtual_size;
		return 0;
	}
	if (index_mail_get_physical_size(_mail, size_r) == 0) {
		*size_r = mail->data.physical_size;
		return 0;
	}

	if (_mail->lookup_abort == MAIL_LOOKUP_ABORT_READ_MAIL &&
	    (_mail->box->flags & MAILBOX_FLAG_POP3_SESSION) != 0) {
		/* kludge: we want output for POP3 LIST with
		   pop3_fast_size_lookups=yes. use the remote's LIST values
		   regardless of their correctness */
		if (mbox->msg_sizes == NULL) {
			if (pop3c_sync_get_sizes(mbox) < 0)
				return -1;
		}
		i_assert(_mail->seq <= mbox->msg_count);
		*size_r = mbox->msg_sizes[_mail->seq-1];
		return 0;
	}

	/* slow way: get the whole message body */
	if (mail_get_stream(_mail, &hdr_size, &body_size, &input) < 0)
		return -1;

	i_assert(mail->data.physical_size != (uoff_t)-1);
	*size_r = mail->data.physical_size;
	return 0;
}

static void pop3c_mail_cache_size(struct index_mail *mail)
{
	uoff_t size;

	if (i_stream_get_size(mail->data.stream, TRUE, &size) <= 0)
		return;
	mail->data.virtual_size = size;
	/* it'll be actually added to index when closing the mail in
	   index_mail_cache_sizes() */
}

static void
pop3c_mail_prefetch_done(enum pop3c_command_state state,
			 const char *reply ATTR_UNUSED, void *context)
{
	struct pop3c_mail *pmail = context;

	switch (state) {
	case POP3C_COMMAND_STATE_OK:
		break;
	case POP3C_COMMAND_STATE_ERR:
	case POP3C_COMMAND_STATE_DISCONNECTED:
		i_stream_unref(&pmail->prefetch_stream);
		/* let pop3c_mail_get_stream() figure out the error handling.
		   in case of a -ERR a retry might even work. */
		break;
	}
	pmail->prefetching = FALSE;
}

static bool pop3c_mail_prefetch(struct mail *_mail)
{
	struct pop3c_mail *pmail = POP3C_MAIL(_mail);
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(_mail->box);
	enum pop3c_capability capa;
	const char *cmd;

	if (pmail->imail.data.access_part != 0 &&
	    pmail->imail.data.stream == NULL) {
		capa = pop3c_client_get_capabilities(mbox->client);
		pmail->prefetching_body = (capa & POP3C_CAPABILITY_TOP) == 0 ||
			(pmail->imail.data.access_part & (READ_BODY | PARSE_BODY)) != 0;
		if (pmail->prefetching_body)
			cmd = t_strdup_printf("RETR %u\r\n", _mail->seq);
		else
			cmd = t_strdup_printf("TOP %u 0\r\n", _mail->seq);

		pmail->prefetching = TRUE;
		pmail->prefetch_stream =
			pop3c_client_cmd_stream_async(mbox->client, cmd,
				pop3c_mail_prefetch_done, pmail);
		i_stream_set_name(pmail->prefetch_stream, t_strcut(cmd, '\r'));
		return !pmail->prefetching;
	}
	return index_mail_prefetch(_mail);
}

static int
pop3c_mail_get_stream(struct mail *_mail, bool get_body,
		      struct message_size *hdr_size,
		      struct message_size *body_size, struct istream **stream_r)
{
	struct pop3c_mail *pmail = POP3C_MAIL(_mail);
	struct index_mail *mail = &pmail->imail;
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(_mail->box);
	enum pop3c_capability capa;
	const char *name, *cmd, *error;
	struct istream *input;
	bool new_stream = FALSE;

	if ((mail->data.access_part & (READ_BODY | PARSE_BODY)) != 0)
		get_body = TRUE;

	while (pmail->prefetching) {
		/* wait for prefetch to finish */
		pop3c_client_wait_one(mbox->client);
	}

	if (pmail->prefetch_stream != NULL && mail->data.stream == NULL) {
		mail->data.stream = pmail->prefetch_stream;
		pmail->prefetch_stream = NULL;
		new_stream = TRUE;
	}

	if (get_body && mail->data.stream != NULL) {
		name = i_stream_get_name(mail->data.stream);
		if (str_begins(name, "RETR")) {
			/* we've fetched the body */
		} else if (str_begins(name, "TOP")) {
			/* we've fetched the header, but we need the body
			   now too */
			index_mail_close_streams(mail);
		} else {
			i_panic("Unexpected POP3 stream name: %s", name);
		}
	}

	if (mail->data.stream == NULL) {
		capa = pop3c_client_get_capabilities(mbox->client);
		if (get_body || (capa & POP3C_CAPABILITY_TOP) == 0) {
			cmd = t_strdup_printf("RETR %u\r\n", _mail->seq);
			get_body = TRUE;
		} else {
			cmd = t_strdup_printf("TOP %u 0\r\n", _mail->seq);
		}
		if (pop3c_client_cmd_stream(mbox->client, cmd,
					    &input, &error) < 0) {
			mail_storage_set_error(mbox->box.storage,
				!pop3c_client_is_connected(mbox->client) ?
				MAIL_ERROR_TEMP : MAIL_ERROR_EXPUNGED, error);
			return -1;
		}
		mail->data.stream = input;
		i_stream_set_name(mail->data.stream, t_strcut(cmd, '\r'));
		new_stream = TRUE;
	}
	if (new_stream) {
		if (mail->mail.v.istream_opened != NULL) {
			if (mail->mail.v.istream_opened(_mail,
							&mail->data.stream) < 0) {
				index_mail_close_streams(mail);
				return -1;
			}
		}
		if (get_body)
			pop3c_mail_cache_size(mail);
	}
	/* if this stream is used by some filter stream, make the
	   filter stream blocking */
	mail->data.stream->blocking = TRUE;
	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

static int
pop3c_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		       const char **value_r)
{
	struct pop3c_mailbox *mbox = POP3C_MAILBOX(_mail->box);

	switch (field) {
	case MAIL_FETCH_UIDL_BACKEND:
	case MAIL_FETCH_GUID:
		if (mbox->msg_uidls == NULL) {
			if (pop3c_sync_get_uidls(mbox) < 0)
				return -1;
		}
		i_assert(_mail->seq <= mbox->msg_count);
		*value_r = mbox->msg_uidls[_mail->seq-1];
		return 0;
	default:
		return index_mail_get_special(_mail, field, value_r);
	}
}

struct mail_vfuncs pop3c_mail_vfuncs = {
	pop3c_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,
	pop3c_mail_prefetch,
	index_mail_precache,
	index_mail_add_temp_wanted_fields,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_pvt_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	pop3c_mail_get_received_date,
	pop3c_mail_get_save_date,
	index_mail_get_virtual_size,
	pop3c_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	pop3c_mail_get_stream,
	index_mail_get_binary_stream,
	pop3c_mail_get_special,
	index_mail_get_backend_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	index_mail_update_pvt_modseq,
	NULL,
	index_mail_expunge,
	index_mail_set_cache_corrupted,
	index_mail_opened,
};
