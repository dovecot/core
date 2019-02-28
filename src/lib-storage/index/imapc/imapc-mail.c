/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "hex-binary.h"
#include "sha1.h"
#include "istream.h"
#include "message-part-data.h"
#include "imap-envelope.h"
#include "imapc-msgmap.h"
#include "imapc-mail.h"
#include "imapc-storage.h"

static bool imapc_mail_get_cached_guid(struct mail *_mail);

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
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct imapc_msgmap *msgmap;
	uint32_t lseq, rseq;

	if (!mbox->initial_sync_done) {
		/* unknown at this point */
		return FALSE;
	}

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
	if (!mbox->initial_sync_done) {
		/* NOOP caused a reconnection and desync */
		return FALSE;
	}

	return !imapc_msgmap_uid_to_rseq(msgmap, _mail->uid, &rseq);
}

static int imapc_mail_failed(struct mail *mail, const char *field)
{
	struct imapc_mail *imail = IMAPC_MAIL(mail);
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(mail->box);
	bool fix_broken_mail = FALSE;

	if (mail->expunged || imapc_mail_is_expunged(mail)) {
		mail_set_expunged(mail);
	} else if (!imapc_client_mailbox_is_opened(mbox->client_box)) {
		/* we've already logged a disconnection error */
		mail_storage_set_internal_error(mail->box->storage);
	} else {
		/* By default we'll assume that this is a critical failure,
		   because we don't want to lose any data. We can be here
		   either because it's a temporary failure on the server or
		   it's a permanent failure. Unfortunately we can't know
		   which case it is, so permanent failures need to be worked
		   around by setting imapc_features=fetch-fix-broken-mails.

		   One reason for permanent failures was that earlier Exchange
		   versions failed to return any data for messages in Calendars
		   mailbox. This seems to be fixed in newer versions.
		   */
		fix_broken_mail = imail->fetch_ignore_if_missing;
		mail_set_critical(mail,
			"imapc: Remote server didn't send %s%s (FETCH replied: %s)",
			field, fix_broken_mail ? " - treating it as empty" : "",
			imail->last_fetch_reply);
	}
	return fix_broken_mail ? 0 : -1;
}

static uint64_t imapc_mail_get_modseq(struct mail *_mail)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct imapc_msgmap *msgmap;
	const uint64_t *modseqs;
	unsigned int count;
	uint32_t rseq;

	if (!imapc_mailbox_has_modseqs(mbox))
		return index_mail_get_modseq(_mail);

	msgmap = imapc_client_mailbox_get_msgmap(mbox->client_box);
	if (imapc_msgmap_uid_to_rseq(msgmap, _mail->uid, &rseq)) {
		modseqs = array_get(&mbox->rseq_modseqs, &count);
		if (rseq <= count)
			return modseqs[rseq-1];
	}
	return 1; /* unknown modseq */
}

static int imapc_mail_get_received_date(struct mail *_mail, time_t *date_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;

	if (index_mail_get_received_date(_mail, date_r) == 0)
		return 0;

	if (data->received_date == (time_t)-1) {
		if (imapc_mail_fetch(_mail, MAIL_FETCH_RECEIVED_DATE, NULL) < 0)
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
	struct index_mail *mail = INDEX_MAIL(_mail);
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
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;
	struct istream *input;
	uoff_t old_offset;
	int ret;

	if (data->physical_size == (uoff_t)-1)
		(void)index_mail_get_physical_size(_mail, size_r);
	if (data->physical_size != (uoff_t)-1) {
		*size_r = data->physical_size;
		return 0;
	}

	if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE) &&
	    data->stream == NULL) {
		/* Trust RFC822.SIZE to be correct enough to present to the
		   IMAP client. However, it can be wrong in some implementation
		   so try not to trust it too much. */
		if (imapc_mail_fetch(_mail, MAIL_FETCH_PHYSICAL_SIZE, NULL) < 0)
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
	i_assert(data->stream != NULL);
	i_stream_seek(data->stream, old_offset);

	ret = i_stream_get_size(data->stream, TRUE,
				&data->physical_size);
	if (ret <= 0) {
		i_assert(ret != 0);
		mail_set_critical(_mail, "imapc: stat(%s) failed: %m",
				  i_stream_get_name(data->stream));
		return -1;
	}
	*size_r = data->physical_size;
	return 0;
}

static int imapc_mail_get_virtual_size(struct mail *_mail, uoff_t *size_r)
{
	struct index_mail *mail = INDEX_MAIL(_mail);
	struct index_mail_data *data = &mail->data;

	if (imapc_mail_get_physical_size(_mail, size_r) < 0)
		return -1;
	data->virtual_size = data->physical_size;
	return 0;
}

static int
imapc_mail_get_header_stream(struct mail *_mail,
			     struct mailbox_header_lookup_ctx *headers,
			     struct istream **stream_r)
{
	struct imapc_mail *mail = IMAPC_MAIL(_mail);
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	enum mail_lookup_abort old_abort = _mail->lookup_abort;
	int ret;

	if (mail->imail.data.access_part != 0 ||
	    !IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_HEADERS)) {
		/* we're going to be reading the header/body anyway */
		return index_mail_get_header_stream(_mail, headers, stream_r);
	}

	/* see if the wanted headers are already in cache */
	_mail->lookup_abort = MAIL_LOOKUP_ABORT_READ_MAIL;
	ret = index_mail_get_header_stream(_mail, headers, stream_r);
	_mail->lookup_abort = old_abort;
	if (ret == 0)
		return 0;

	/* fetch only the wanted headers */
	if (imapc_mail_fetch(_mail, 0, headers->name) < 0)
		return -1;
	/* the headers should cached now. */
	return index_mail_get_header_stream(_mail, headers, stream_r);
}

static int
imapc_mail_get_headers(struct mail *_mail, const char *field,
		       bool decode_to_utf8, const char *const **value_r)
{
	struct mailbox_header_lookup_ctx *headers;
	const char *header_names[2];
	const unsigned char *data;
	size_t size;
	struct istream *input;
	int ret;

	header_names[0] = field;
	header_names[1] = NULL;
	headers = mailbox_header_lookup_init(_mail->box, header_names);
	ret = mail_get_header_stream(_mail, headers, &input);
	mailbox_header_lookup_unref(&headers);
	if (ret < 0)
		return -1;

	while (i_stream_read_more(input, &data, &size) > 0)
		i_stream_skip(input, size);
	/* the header should cached now. */
	return index_mail_get_headers(_mail, field, decode_to_utf8, value_r);
}

static int
imapc_mail_get_first_header(struct mail *_mail, const char *field,
			    bool decode_to_utf8, const char **value_r)
{
	const char *const *values;
	int ret;

	ret = imapc_mail_get_headers(_mail, field, decode_to_utf8, &values);
	if (ret <= 0)
		return ret;
	*value_r = values[0];
	return 1;
}

static int
imapc_mail_get_stream(struct mail *_mail, bool get_body,
		      struct message_size *hdr_size,
		      struct message_size *body_size, struct istream **stream_r)
{
	struct imapc_mail *mail = IMAPC_MAIL(_mail);
	struct index_mail_data *data = &mail->imail.data;
	enum mail_fetch_field fetch_field;

	if (get_body && !mail->body_fetched &&
	    mail->imail.data.stream != NULL) {
		/* we've fetched the header, but we need the body now too */
		index_mail_close_streams(&mail->imail);
		/* don't re-use any cached header sizes. we may be
		   intentionally downloading the full body because the header
		   wasn't returned correctly (e.g. pop3-migration does this) */
		data->hdr_size_set = FALSE;
	}

	/* See if we can get it from cache. If the wanted_fields/headers are
	   set properly, this is usually already done by prefetching. */
	imapc_mail_try_init_stream_from_cache(mail);

	if (data->stream == NULL) {
		if (!data->initialized) {
			/* coming here from mail_set_seq() */
			mail_set_aborted(_mail);
			return -1;
		}
		if (_mail->expunged) {
			/* We already detected that the mail is expunged.
			   Don't spend time trying to FETCH it again. */
			mail_set_expunged(_mail);
			return -1;
		}
		fetch_field = get_body ||
			(data->access_part & READ_BODY) != 0 ?
			MAIL_FETCH_STREAM_BODY : MAIL_FETCH_STREAM_HEADER;
		if (imapc_mail_fetch(_mail, fetch_field, NULL) < 0)
			return -1;

		if (data->stream == NULL) {
			if (imapc_mail_failed(_mail, "BODY[]") < 0)
				return -1;
			i_assert(data->stream == NULL);

			/* return the broken email as empty */
			mail->body_fetched = TRUE;
			data->stream = i_stream_create_from_data(NULL, 0);
			imapc_mail_init_stream(mail);
		}
	}

	return index_mail_init_stream(&mail->imail, hdr_size, body_size,
				      stream_r);
}

bool imapc_mail_has_headers_in_cache(struct index_mail *mail,
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

void imapc_mail_update_access_parts(struct index_mail *mail)
{
	struct mail *_mail = &mail->mail.mail;
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct index_mail_data *data = &mail->data;
	struct mailbox_header_lookup_ctx *header_ctx;
	const char *str;
	time_t date;
	uoff_t size;

	if ((data->wanted_fields & MAIL_FETCH_RECEIVED_DATE) != 0)
		(void)index_mail_get_received_date(_mail, &date);
	if ((data->wanted_fields & MAIL_FETCH_SAVE_DATE) != 0) {
		if (index_mail_get_save_date(_mail, &date) < 0) {
			(void)index_mail_get_received_date(_mail, &date);
			data->save_date = data->received_date;
		}
	}
	if ((data->wanted_fields & (MAIL_FETCH_PHYSICAL_SIZE |
				    MAIL_FETCH_VIRTUAL_SIZE)) != 0) {
		if (index_mail_get_physical_size(_mail, &size) < 0 &&
		    !IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE))
			data->access_part |= READ_HDR | READ_BODY;
	}
	if ((data->wanted_fields & MAIL_FETCH_GUID) != 0)
		(void)imapc_mail_get_cached_guid(_mail);
	if ((data->wanted_fields & MAIL_FETCH_IMAP_BODY) != 0)
		(void)index_mail_get_cached_body(mail, &str);
	if ((data->wanted_fields & MAIL_FETCH_IMAP_BODYSTRUCTURE) != 0)
		(void)index_mail_get_cached_bodystructure(mail, &str);

	if (data->access_part == 0 && data->wanted_headers != NULL &&
	    !IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_HEADERS)) {
		/* see if all wanted headers exist in cache */
		if (!imapc_mail_has_headers_in_cache(mail, data->wanted_headers))
			data->access_part |= PARSE_HDR;
	}
	if (data->access_part == 0 &&
	    (data->wanted_fields & MAIL_FETCH_IMAP_ENVELOPE) != 0 &&
	    !IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_HEADERS)) {
		/* the common code already checked this partially,
		   but we need a guaranteed correct answer */
		header_ctx = mailbox_header_lookup_init(_mail->box,
							message_part_envelope_headers);
		if (!imapc_mail_has_headers_in_cache(mail, header_ctx))
			data->access_part |= PARSE_HDR;
		mailbox_header_lookup_unref(&header_ctx);
	}
}

static void imapc_mail_set_seq(struct mail *_mail, uint32_t seq, bool saving)
{
	struct imapc_mail *imail = IMAPC_MAIL(_mail);
	struct index_mail *mail = &imail->imail;
	struct imapc_mailbox *mbox = (struct imapc_mailbox *)_mail->box;

	index_mail_set_seq(_mail, seq, saving);
	if (IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_RFC822_SIZE)) {
		/* RFC822.SIZE may be read from vsize record or cache. It may
		   not be exactly correct. */
		mail->data.inexact_total_sizes = TRUE;
	}

	/* searching code handles prefetching internally,
	   elsewhere we want to do it immediately */
	if (!mail->mail.search_mail && !_mail->saving)
		(void)imapc_mail_prefetch(_mail);
}

static void
imapc_mail_add_temp_wanted_fields(struct mail *_mail,
				  enum mail_fetch_field fields,
				  struct mailbox_header_lookup_ctx *headers)
{
	struct index_mail *mail = INDEX_MAIL(_mail);

	index_mail_add_temp_wanted_fields(_mail, fields, headers);
	if (_mail->seq != 0)
		imapc_mail_update_access_parts(mail);
}

static void imapc_mail_close(struct mail *_mail)
{
	struct imapc_mail *mail = IMAPC_MAIL(_mail);
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct imapc_mail_cache *cache = &mbox->prev_mail_cache;

	if (mail->fetch_count > 0) {
		imapc_mail_fetch_flush(mbox);
		while (mail->fetch_count > 0)
			imapc_mailbox_run_nofetch(mbox);
	}

	index_mail_close(_mail);

	mail->fetching_headers = NULL;
	if (mail->body_fetched) {
		imapc_mail_cache_free(cache);
		cache->uid = _mail->uid;
		if (mail->fd != -1) {
			cache->fd = mail->fd;
			mail->fd = -1;
		} else {
			cache->buf = mail->body;
			mail->body = NULL;
		}
	}
	i_close_fd(&mail->fd);
	buffer_free(&mail->body);
	mail->header_fetched = FALSE;
	mail->body_fetched = FALSE;

	i_assert(mail->fetch_count == 0);
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
	i_assert(imail->data.stream != NULL);
	while (i_stream_read_more(input, &data, &size) > 0) {
		sha1_loop(&sha1_ctx, data, size);
		i_stream_skip(input, size);
	}
	i_stream_seek(imail->data.stream, old_offset);
	sha1_result(&sha1_ctx, sha1_output);

	sha1_str = binary_to_hex(sha1_output, sizeof(sha1_output));
	imail->data.guid = p_strdup(imail->mail.data_pool, sha1_str);
	return 0;
}

static bool imapc_mail_get_cached_guid(struct mail *_mail)
{
	struct index_mail *imail = INDEX_MAIL(_mail);
	const enum index_cache_field cache_idx =
		imail->ibox->cache_fields[MAIL_CACHE_GUID].idx;
	string_t *str;

	if (imail->data.guid != NULL) {
		if (mail_cache_field_can_add(_mail->transaction->cache_trans,
					     _mail->seq, cache_idx)) {
			/* GUID was prefetched - add to cache */
			index_mail_cache_add_idx(imail, cache_idx,
				imail->data.guid, strlen(imail->data.guid));
		}
		return TRUE;
	}

	str = str_new(imail->mail.data_pool, 64);
	if (mail_cache_lookup_field(_mail->transaction->cache_view,
				    str, imail->mail.mail.seq, cache_idx) > 0) {
		imail->data.guid = str_c(str);
		return TRUE;
	}
	return FALSE;
}

static int imapc_mail_get_guid(struct mail *_mail, const char **value_r)
{
	struct index_mail *imail = INDEX_MAIL(_mail);
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	const enum index_cache_field cache_idx =
		imail->ibox->cache_fields[MAIL_CACHE_GUID].idx;

	if (imapc_mail_get_cached_guid(_mail)) {
		*value_r = imail->data.guid;
		return 0;
	}

	/* GUID not in cache, fetch it */
	if (mbox->guid_fetch_field_name != NULL) {
		if (imapc_mail_fetch(_mail, MAIL_FETCH_GUID, NULL) < 0)
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
				 imail->data.guid, strlen(imail->data.guid));
	*value_r = imail->data.guid;
	return 0;
}

static int
imapc_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
		       const char **value_r)
{
	struct imapc_mailbox *mbox = IMAPC_MAILBOX(_mail->box);
	struct index_mail *imail = INDEX_MAIL(_mail);
	uint64_t num;

	switch (field) {
	case MAIL_FETCH_GUID:
		if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_GUID_FORCED) &&
		    mbox->guid_fetch_field_name == NULL) {
			/* GUIDs not supported by server */
			break;
		}
		*value_r = "";
		return imapc_mail_get_guid(_mail, value_r);
	case MAIL_FETCH_UIDL_BACKEND:
		if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_GMAIL_MIGRATION))
			break;
		if (imapc_mail_get_guid(_mail, value_r) < 0)
			return -1;
		if (str_to_uint64(*value_r, &num) < 0) {
			mail_set_critical(_mail,
				"X-GM-MSGID not 64bit integer as expected for POP3 UIDL generation: %s", *value_r);
			return -1;
		}

		*value_r = p_strdup_printf(imail->mail.data_pool,
					   "GmailId%"PRIx64, num);
		return 0;
	case MAIL_FETCH_IMAP_BODY:
		if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_BODYSTRUCTURE))
			break;

		if (index_mail_get_cached_body(imail, value_r))
			return 0;
		if (imapc_mail_fetch(_mail, field, NULL) < 0)
			return -1;
		if (imail->data.body == NULL) {
			(void)imapc_mail_failed(_mail, "BODY");
			return -1;
		}
		*value_r = imail->data.body;
		return 0;
	case MAIL_FETCH_IMAP_BODYSTRUCTURE:
		if (!IMAPC_BOX_HAS_FEATURE(mbox, IMAPC_FEATURE_FETCH_BODYSTRUCTURE))
			break;

		if (index_mail_get_cached_bodystructure(imail, value_r))
			return 0;
		if (imapc_mail_fetch(_mail, field, NULL) < 0)
			return -1;
		if (imail->data.bodystructure == NULL) {
			(void)imapc_mail_failed(_mail, "BODYSTRUCTURE");
			return -1;
		}
		*value_r = imail->data.bodystructure;
		return 0;
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
	imapc_mail_get_modseq,
	index_mail_get_pvt_modseq,
	index_mail_get_parts,
	index_mail_get_date,
	imapc_mail_get_received_date,
	imapc_mail_get_save_date,
	imapc_mail_get_virtual_size,
	imapc_mail_get_physical_size,
	imapc_mail_get_first_header,
	imapc_mail_get_headers,
	imapc_mail_get_header_stream,
	imapc_mail_get_stream,
	index_mail_get_binary_stream,
	imapc_mail_get_special,
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
