/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "index-mail.h"
#include "pop3c-client.h"
#include "pop3c-sync.h"
#include "pop3c-storage.h"

static int pop3c_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	int tz;

	/* FIXME: we could also parse the first Received: header and get
	   the date from there, but since this code is unlikely to be called
	   except during migration, I don't think it really matters. */
	return index_mail_get_date(_mail, date_r, &tz);
}

static int pop3c_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->save_date == (time_t)-1) {
		/* FIXME: we could use a value stored in cache */
		return pop3c_mail_get_received_date(_mail, date_r);
	}
	*date_r = data->save_date;
	return 0;
}

static int pop3c_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct pop3c_mailbox *mbox = (struct pop3c_mailbox *)_mail->box;
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
	struct mail *_mail = &mail->mail.mail;
	uoff_t size;
	unsigned int cache_idx;

	if (i_stream_get_size(mail->data.stream, TRUE, &size) <= 0)
		return;
	mail->data.virtual_size = size;

	cache_idx = mail->ibox->cache_fields[MAIL_CACHE_VIRTUAL_FULL_SIZE].idx;
	if (mail_cache_field_exists(_mail->transaction->cache_view,
				    _mail->seq, cache_idx) == 0) {
		index_mail_cache_add_idx(mail, cache_idx, &size, sizeof(size));
		/* make sure it's not cached twice */
		mail->data.dont_cache_fetch_fields |=
			MAIL_CACHE_VIRTUAL_FULL_SIZE;
	}
}

static int
pop3c_mail_get_stream(struct mail *_mail, bool get_body,
		      struct message_size *hdr_size,
		      struct message_size *body_size, struct istream **stream_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct pop3c_mailbox *mbox = (struct pop3c_mailbox *)_mail->box;
	enum pop3c_capability capa;
	const char *name, *cmd, *error;
	struct istream *input;

	if (get_body && mail->data.stream != NULL) {
		name = i_stream_get_name(mail->data.stream);
		if (strncmp(name, "RETR", 4) == 0) {
			/* we've fetched the body */
		} else if (strncmp(name, "TOP", 3) == 0) {
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
		if (mail->mail.v.istream_opened != NULL) {
			if (mail->mail.v.istream_opened(_mail,
							&mail->data.stream) < 0) {
				index_mail_close_streams(mail);
				return -1;
			}
		}
		i_stream_set_name(mail->data.stream, t_strcut(cmd, '\r'));
		if (get_body)
			pop3c_mail_cache_size(mail);
	}
	return index_mail_init_stream(mail, hdr_size, body_size, stream_r);
}

static int
pop3c_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		       const char **value_r)
{
	struct pop3c_mailbox *mbox = (struct pop3c_mailbox *)_mail->box;

	switch (field) {
	case MAIL_FETCH_UIDL_BACKEND:
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
	index_mail_close,
	index_mail_free,
	index_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,
	index_mail_prefetch,
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
	index_mail_get_real_mail,
	index_mail_update_flags,
	index_mail_update_keywords,
	index_mail_update_modseq,
	index_mail_update_pvt_modseq,
	NULL,
	index_mail_expunge,
	index_mail_set_cache_corrupted,
	index_mail_opened
};
