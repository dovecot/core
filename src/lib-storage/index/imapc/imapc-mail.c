/* Copyright (c) 2011-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "sha1.h"
#include "istream.h"
#include "imap-envelope.h"
#include "imapc-msgmap.h"
#include "imapc-mail.h"
#include "imapc-client.h"
#include "imapc-storage.h"

struct mail *
imapc_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct imapc_mail *mail;
	pool_t pool;

	pool = pool_alloconly_create("mail", 2048);
	mail = p_new(pool, struct imapc_mail, 1);
	mail->imail.mail.pool = pool;
	mail->fd = -1;

	index_mail_init(&mail->imail, t, wanted_fields, wanted_headers);
	return &mail->imail.mail.mail;
}

static bool imapc_mail_is_expunged(struct mail *_mail)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;
	struct imapc_msgmap *msgmap;
	uint32_t lseq, rseq;

	if (mbox->sync_view != NULL) {
		/* check if another session has already expunged it */
		if (!mail_index_lookup_seq(mbox->sync_view, _mail->uid, &lseq))
			return TRUE;
	}

	/* check if we've received EXPUNGE for it */
	msgmap = imapc_client_mailbox_get_msgmap(mbox->client_box);
	if (!imapc_msgmap_uid_to_rseq(msgmap, _mail->uid, &rseq))
		return TRUE;

	/* we may be running against a server that hasn't bothered sending
	   us an EXPUNGE. see if NOOP sends it. */
	imapc_mailbox_noop(mbox);

	return !imapc_msgmap_uid_to_rseq(msgmap, _mail->uid, &rseq);
}

static int imapc_mail_failed(struct mail *mail, const char *field)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)mail->box;

	if (mail->expunged || imapc_mail_is_expunged(mail)) {
		mail_set_expunged(mail);
		return -1;
	} else if (!imapc_client_mailbox_is_opened(mbox->client_box)) {
		/* we've already logged a disconnection error */
		mail_storage_set_internal_error(mail->box->storage);
		return -1;
	} else {
		mail_storage_set_critical(mail->box->storage,
			"imapc: Remote server didn't send %s for UID %u in %s",
			field, mail->uid, mail->box->vname);
		return 0;
	}
}

static int imapc_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (data->received_date == (time_t)-1) {
		if (imapc_mail_fetch(_mail, MAIL_FETCH_RECEIVED_DATE) < 0)
			return -1;
		if (data->received_date == (time_t)-1) {
			if (imapc_mail_failed(_mail, "INTERNALDATE") < 0)
				return -1;
			/* assume that the server never returns INTERNALDATE
			   for this mail (see BODY[] failure handling) */
			data->received_date = 0;
		}
	}
	*date_r = data->received_date;
	return 0;
}

static int imapc_mail_get_save_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;

	if (data->save_date == (time_t)-1) {
		/* FIXME: we could use a value stored in cache */
		return imapc_mail_get_received_date(_mail, date_r);
	}
	*date_r = data->save_date;
	return 0;
}

static int imapc_mail_get_physical_size(struct mail *_mail, uoff_t *size_r)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;
	struct index_mail *mail = (struct index_mail *)_mail;
	struct index_mail_data *data = &mail->data;
	struct istream *input;
	uoff_t old_offset;
	int ret;

	if (data->physical_size == (uoff_t)-1) {
		(void)index_mail_get_physical_size(_mail, size_r);
		if (data->physical_size != (uoff_t)-1) {
			*size_r = data->physical_size;
			return 0;
		}
	}

	if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE) &&
	    data->stream == NULL) {
		/* trust RFC822.SIZE to be correct */
		if (imapc_mail_fetch(_mail, MAIL_FETCH_PHYSICAL_SIZE) < 0)
			return -1;
		if (data->physical_size == (uoff_t)-1) {
			if (imapc_mail_failed(_mail, "RFC822.SIZE") < 0)
				return -1;
			/* assume that the server never returns RFC822.SIZE
			   for this mail (see BODY[] failure handling) */
			data->physical_size = 0;
		}
		*size_r = data->physical_size;
		return 0;
	}

	old_offset = data->stream == NULL ? 0 : data->stream->v_offset;
	if (mail_get_stream(_mail, NULL, NULL, &input) < 0)
		return -1;
	i_stream_seek(data->stream, old_offset);

	ret = i_stream_get_size(data->stream, TRUE,
				&data->physical_size);
	if (ret <= 0) {
		i_assert(ret != 0);
		mail_storage_set_critical(_mail->box->storage,
					  "imapc: stat(%s) failed: %m",
					  i_stream_get_name(data->stream));
		return -1;
	}
	*size_r = data->physical_size;
	return 0;
}

static int
imapc_mail_get_stream(struct mail *_mail, bool get_body,
		      struct message_size *hdr_size,
		      struct message_size *body_size, struct istream **stream_r)
{
	struct imapc_mail *mail = (struct imapc_mail *)_mail;
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fetch_field;

	if (get_body && !mail->body_fetched &&
	    mail->imail.data.stream != NULL) {
		/* we've fetched the header, but we need the body now too */
		index_mail_close_streams(&mail->imail);
	}

	if (data->stream == NULL) {
		if (!data->initialized) {
			/* coming here from mail_set_seq() */
			mail_set_aborted(_mail);
			return -1;
		}
		fetch_field = get_body ||
			(data->access_part & READ_BODY) != 0 ?
			MAIL_FETCH_STREAM_BODY : MAIL_FETCH_STREAM_HEADER;
		if (imapc_mail_fetch(_mail, fetch_field) < 0)
			return -1;

		if (data->stream == NULL) {
			if (imapc_mail_failed(_mail, "BODY[]") < 0)
				return -1;
			i_assert(data->stream == NULL);

			/* this could be either a temporary server bug, or the
			   server may permanently just not return anything for
			   this mail. the latter happens at least with Exchange
			   when trying to fetch calendar "mails", so we'll just
			   return them as empty mails instead of disconnecting
			   the client. */
			mail->body_fetched = TRUE;
			data->stream = i_stream_create_from_data(&uchar_nul, 0);
			imapc_mail_init_stream(mail, TRUE);
		}
	}

	return index_mail_init_stream(&mail->imail, hdr_size, body_size,
				      stream_r);
}

static bool
imapc_mail_has_headers_in_cache(struct index_mail *mail,
				struct mailbox_header_lookup_ctx *headers)
{
	struct mail *_mail = &mail->mail.mail;
	unsigned int i;

	for (i = 0; i < headers->count; i++) {
		if (mail_cache_field_exists(_mail->transaction->cache_view,
					    _mail->seq, headers->idx[i]) <= 0)
			return FALSE;
	}
	return TRUE;
}

static void index_mail_update_access_parts(struct index_mail *mail)
{
	struct mail *_mail = &mail->mail.mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;
	struct index_mail_data *data = &mail->data;
	struct mailbox_header_lookup_ctx *header_ctx;
	time_t date;
	uoff_t size;

	if ((data->wanted_fields & MAIL_FETCH_RECEIVED_DATE) != 0)
		(void)index_mail_get_received_date(_mail, &date);
	if ((data->wanted_fields & MAIL_FETCH_PHYSICAL_SIZE) != 0) {
		if (index_mail_get_physical_size(_mail, &size) < 0 &&
		    !IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE))
			data->access_part |= READ_HDR | READ_BODY;
	}

	if (data->access_part == 0 && data->wanted_headers != NULL) {
		/* see if all wanted headers exist in cache */
		if (!imapc_mail_has_headers_in_cache(mail, data->wanted_headers))
			data->access_part |= PARSE_HDR;
	}
	if (data->access_part == 0 &&
	    (data->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) != 0) {
		/* the common code already checked this partially,
		   but we need a guaranteed correct answer */
		header_ctx = mailbox_header_lookup_init(_mail->box,
							imap_envelope_headers);
		if (!imapc_mail_has_headers_in_cache(mail, header_ctx))
			data->access_part |= PARSE_HDR;
		mailbox_header_lookup_unref(&header_ctx);
	}
}

static void imapc_mail_set_seq(struct mail *_mail, uint32_t seq, bool saving)
{
	struct imapc_mail *imail = (struct imapc_mail *)_mail;
	struct index_mail *mail = &imail->imail;

	index_mail_set_seq(_mail, seq, saving);

	/* searching code handles prefetching internally,
	   elsewhere we want to do it immediately */
	if (!mail->search_mail && !_mail->saving)
		(void)imapc_mail_prefetch(_mail);
}

static void
imapc_mail_add_temp_wanted_fields(struct mail *_mail,
				  enum mail_fetch_field fields,
				  struct mailbox_header_lookup_ctx *headers)
{
	struct index_mail *mail = (struct index_mail *)_mail;

	index_mail_add_temp_wanted_fields(_mail, fields, headers);
	index_mail_update_access_parts(mail);
}

static void imapc_mail_close(struct mail *_mail)
{
	struct imapc_mail *mail = (struct imapc_mail *)_mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;
	struct imapc_mail_cache *cache = &mbox->prev_mail_cache;

	while (mail->fetch_count > 0)
		imapc_storage_run(mbox->storage);

	index_mail_close(_mail);

	if (mail->body_fetched) {
		imapc_mail_cache_free(cache);
		cache->uid = _mail->uid;
		if (cache->fd != -1) {
			cache->fd = mail->fd;
			mail->fd = -1;
		} else {
			cache->buf = mail->body;
			mail->body = NULL;
		}
	}
	if (mail->fd != -1) {
		if (close(mail->fd) < 0)
			i_error("close(imapc mail) failed: %m");
		mail->fd = -1;
	}
	if (mail->body != NULL)
		buffer_free(&mail->body);
}

static int imapc_mail_get_hdr_hash(struct index_mail *imail)
{
	struct istream *input;
	const unsigned char *data;
	size_t size;
	uoff_t old_offset;
	struct sha1_ctxt sha1_ctx;
	unsigned char sha1_output[SHA1_RESULTLEN];
	const char *sha1_str;

	sha1_init(&sha1_ctx);
	old_offset = imail->data.stream == NULL ? 0 :
		imail->data.stream->v_offset;
	if (mail_get_hdr_stream(&imail->mail.mail, NULL, &input) < 0)
		return -1;
	while (i_stream_read_data(input, &data, &size, 0) > 0) {
		sha1_loop(&sha1_ctx, data, size);
		i_stream_skip(input, size);
	}
	i_stream_seek(imail->data.stream, old_offset);
	sha1_result(&sha1_ctx, sha1_output);

	sha1_str = binary_to_hex(sha1_output, sizeof(sha1_output));
	imail->data.guid = p_strdup(imail->mail.data_pool, sha1_str);
	return 0;
}

static int imapc_mail_get_guid(struct mail *_mail, const char **value_r)
{
	struct index_mail *imail = (struct index_mail *)_mail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;
	const enum index_cache_field cache_idx =
		imail->ibox->cache_fields[MAIL_CACHE_GUID].idx;
	string_t *str;

	if (imail->data.guid != NULL) {
		*value_r = imail->data.guid;
		return 0;
	}

	str = str_new(imail->mail.data_pool, 64);
	if (mail_cache_lookup_field(_mail->transaction->cache_view,
				    str, imail->mail.mail.seq, cache_idx) > 0) {
		*value_r = str_c(str);
		return 0;
	}

	/* GUID not in cache, fetch it */
	if (mbox->guid_fetch_field_name != NULL) {
		if (imapc_mail_fetch(_mail, MAIL_FETCH_GUID) < 0)
			return -1;
		if (imail->data.guid == NULL) {
			(void)imapc_mail_failed(_mail, mbox->guid_fetch_field_name);
			return -1;
		}
	} else {
		/* use hash of message headers as the GUID */
		if (imapc_mail_get_hdr_hash(imail) < 0)
			return -1;
	}

	index_mail_cache_add_idx(imail, cache_idx,
				 imail->data.guid, strlen(imail->data.guid)+1);
	*value_r = imail->data.guid;
	return 0;
}

static int
imapc_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		       const char **value_r)
{
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;

	switch (field) {
	case MAIL_FETCH_GUID:
		if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_GUID_FORCED) &&
		    mbox->guid_fetch_field_name == NULL) {
			/* GUIDs not supported by server */
			break;
		}
		*value_r = "";
		return imapc_mail_get_guid(_mail, value_r);
	default:
		break;
	}

	return index_mail_get_special(_mail, field, value_r);
}

struct mail_vfuncs imapc_mail_vfuncs = {
	imapc_mail_close,
	index_mail_free,
	imapc_mail_set_seq,
	index_mail_set_uid,
	index_mail_set_uid_cache_updates,
	imapc_mail_prefetch,
	index_mail_precache,
	imapc_mail_add_temp_wanted_fields,

	index_mail_get_flags,
	index_mail_get_keywords,
	index_mail_get_keyword_indexes,
	index_mail_get_modseq,
	index_mail_get_pvt_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	imapc_mail_get_received_date,
	imapc_mail_get_save_date,
	index_mail_get_virtual_size,
	imapc_mail_get_physical_size,
	index_mail_get_first_header,
	index_mail_get_headers,
	index_mail_get_header_stream,
	imapc_mail_get_stream,
	index_mail_get_binary_stream,
	imapc_mail_get_special,
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
