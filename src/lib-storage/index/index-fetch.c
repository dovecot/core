/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "obuffer.h"
#include "temp-string.h"
#include "mail-custom-flags.h"
#include "index-storage.h"
#include "index-fetch.h"
#include "index-messageset.h"
#include "message-send.h"
#include "imap-date.h"
#include "imap-util.h"
#include "imap-message-cache.h"

#include <unistd.h>

static int index_fetch_body(MailIndexRecord *rec, FetchContext *ctx)
{
	const char *body;

	body = imap_msgcache_get(ctx->cache, IMAP_CACHE_BODY);
	if (body != NULL) {
		t_string_printfa(ctx->str, "BODY (%s) ", body);
		return TRUE;
	} else {
		mail_storage_set_critical(ctx->storage,
			"Couldn't generate BODY for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}
}

static int index_fetch_bodystructure(MailIndexRecord *rec, FetchContext *ctx)
{
	const char *bodystructure;

	bodystructure = imap_msgcache_get(ctx->cache, IMAP_CACHE_BODYSTRUCTURE);
	if (bodystructure != NULL) {
		t_string_printfa(ctx->str, "BODYSTRUCTURE (%s) ",
				 bodystructure);
		return TRUE;
	} else {
		mail_storage_set_critical(ctx->storage,
			"Couldn't generate BODYSTRUCTURE for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}
}

static int index_fetch_envelope(MailIndexRecord *rec, FetchContext *ctx)
{
	const char *envelope;

	envelope = imap_msgcache_get(ctx->cache, IMAP_CACHE_ENVELOPE);
	if (envelope != NULL) {
		t_string_printfa(ctx->str, "ENVELOPE (%s) ", envelope);
		return TRUE;
	} else {
		mail_storage_set_critical(ctx->storage,
			"Couldn't generate ENVELOPE for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}
}

static int index_fetch_rfc822_size(MailIndexRecord *rec, FetchContext *ctx)
{
	MessageSize hdr_size, body_size;

	if (!imap_msgcache_get_rfc822(ctx->cache, NULL,
				      &hdr_size, &body_size)) {
		mail_storage_set_critical(ctx->storage,
			"Couldn't get RFC822.SIZE for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}

	t_string_printfa(ctx->str, "RFC822.SIZE %"PRIuUOFF_T" ",
			 hdr_size.virtual_size + body_size.virtual_size);
	return TRUE;
}

static void index_fetch_flags(MailIndexRecord *rec, FetchContext *ctx)
{
	MailFlags flags;

	flags = rec->msg_flags;
	if (rec->uid >= ctx->index->first_recent_uid)
		flags |= MAIL_RECENT;
	if (ctx->update_seen)
		flags |= MAIL_SEEN;

	t_string_printfa(ctx->str, "FLAGS (%s) ",
			 imap_write_flags(flags, ctx->custom_flags));
}

static void index_fetch_internaldate(MailIndexRecord *rec, FetchContext *ctx)
{
	t_string_printfa(ctx->str, "INTERNALDATE \"%s\" ",
			 imap_to_datetime(rec->internal_date));
}

static void index_fetch_uid(MailIndexRecord *rec, FetchContext *ctx)
{
	t_string_printfa(ctx->str, "UID %u ", rec->uid);
}

static int index_fetch_send_rfc822(MailIndexRecord *rec, FetchContext *ctx)
{
	MessageSize hdr_size, body_size;
	IBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(ctx->cache, &inbuf,
				      &hdr_size, &body_size)) {
		mail_storage_set_critical(ctx->storage,
			"Couldn't get RFC822 for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}

	str = t_strdup_printf(" RFC822 {%"PRIuUOFF_T"}\r\n",
			      hdr_size.virtual_size + body_size.virtual_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_buffer_send(ctx->outbuf, str, strlen(str)) < 0)
		return FALSE;

	body_size.physical_size += hdr_size.physical_size;
	body_size.virtual_size += hdr_size.virtual_size;
	return message_send(ctx->outbuf, inbuf, &body_size, 0, (uoff_t)-1);
}

static int index_fetch_send_rfc822_header(MailIndexRecord *rec,
					  FetchContext *ctx)
{
	MessageSize hdr_size;
	IBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(ctx->cache, &inbuf, &hdr_size, NULL)) {
		mail_storage_set_critical(ctx->storage,
			"Couldn't get RFC822.HEADER for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}

	str = t_strdup_printf(" RFC822.HEADER {%"PRIuUOFF_T"}\r\n",
			      hdr_size.virtual_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_buffer_send(ctx->outbuf, str, strlen(str)) < 0)
		return FALSE;

	return message_send(ctx->outbuf, inbuf, &hdr_size, 0, (uoff_t)-1);
}

static int index_fetch_send_rfc822_text(MailIndexRecord *rec, FetchContext *ctx)
{
	MessageSize body_size;
	IBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(ctx->cache, &inbuf, NULL, &body_size)) {
		mail_storage_set_critical(ctx->storage,
			"Couldn't get RFC822.TEXT for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}

	str = t_strdup_printf(" RFC822.TEXT {%"PRIuUOFF_T"}\r\n",
			      body_size.virtual_size);
	if (ctx->first) {
		str++; ctx->first = FALSE;
	}
	if (o_buffer_send(ctx->outbuf, str, strlen(str)) < 0)
		return FALSE;

	return message_send(ctx->outbuf, inbuf, &body_size, 0, (uoff_t)-1);
}

static ImapCacheField index_get_cache(MailFetchData *fetch_data)
{
	MailFetchBodyData *sect;
	ImapCacheField field;

	field = 0;
	if (fetch_data->body)
		field |= IMAP_CACHE_BODY;
	if (fetch_data->bodystructure)
		field |= IMAP_CACHE_BODYSTRUCTURE;
	if (fetch_data->envelope)
		field |= IMAP_CACHE_ENVELOPE;

	if (fetch_data->rfc822_size) {
		field |= IMAP_CACHE_MESSAGE_HDR_SIZE |
			IMAP_CACHE_MESSAGE_BODY_SIZE;
	}
	if (fetch_data->rfc822) {
		field |= IMAP_CACHE_MESSAGE_OPEN | IMAP_CACHE_MESSAGE_HDR_SIZE |
			IMAP_CACHE_MESSAGE_BODY_SIZE;
	}
	if (fetch_data->rfc822_header)
		field |= IMAP_CACHE_MESSAGE_OPEN | IMAP_CACHE_MESSAGE_HDR_SIZE;
	if (fetch_data->rfc822_text)
		field |= IMAP_CACHE_MESSAGE_OPEN | IMAP_CACHE_MESSAGE_BODY_SIZE;

	/* check what body[] sections want */
	sect = fetch_data->body_sections;
	for (; sect != NULL; sect = sect->next)
		field |= index_fetch_body_get_cache(sect->section);
	return field;
}

static void index_msgcache_open(FetchContext *ctx, MailIndexRecord *rec)
{
	ImapCacheField fields;
	uoff_t virtual_header_size, virtual_body_size;
	void *mail_cache_context;

	fields = index_get_cache(ctx->fetch_data);
	if (fields == 0)
		return;

        mail_cache_context = index_msgcache_get_context(ctx->index, rec);

	if (rec->header_size == 0) {
		virtual_header_size = 0;
		virtual_body_size = 0;
	} else {
		virtual_header_size =
			(rec->index_flags & INDEX_MAIL_FLAG_BINARY_HEADER) ?
			rec->header_size : 0;
		virtual_body_size =
			(rec->index_flags & INDEX_MAIL_FLAG_BINARY_BODY) ?
			rec->body_size : 0;
	}

	imap_msgcache_open(ctx->cache, rec->uid, fields,
			   virtual_header_size, virtual_body_size,
			   mail_cache_context);
}

static int index_fetch_mail(MailIndex *index __attr_unused__,
			    MailIndexRecord *rec,
			    unsigned int client_seq,
			    unsigned int idx_seq,
			    void *context)
{
	FetchContext *ctx = context;
	MailFetchBodyData *sect;
	unsigned int orig_len;
	int failed, data_written, fetch_flags;

	if (ctx->update_seen && (rec->msg_flags & MAIL_SEEN) == 0) {
		(void)index->update_flags(index, rec, idx_seq,
					  rec->msg_flags | MAIL_SEEN, FALSE);
		fetch_flags = TRUE;
	} else {
		fetch_flags = FALSE;
	}

	ctx->str = t_string_new(2048);

	t_string_printfa(ctx->str, "* %u FETCH (", client_seq);
	orig_len = ctx->str->len;

	/* first see what we need to do. this way we don't first do some
	   light parsing and later notice that we need to do heavier parsing
	   anyway */
	index_msgcache_open(ctx, rec);

	failed = TRUE;
	data_written = FALSE;
	do {
		/* these can't fail */
		if (ctx->fetch_data->uid)
			index_fetch_uid(rec, ctx);
		if (ctx->fetch_data->flags || fetch_flags)
			index_fetch_flags(rec, ctx);
		if (ctx->fetch_data->internaldate)
			index_fetch_internaldate(rec, ctx);

		/* rest can */
		if (ctx->fetch_data->body)
			if (!index_fetch_body(rec, ctx))
				break;
		if (ctx->fetch_data->bodystructure)
			if (!index_fetch_bodystructure(rec, ctx))
				break;
		if (ctx->fetch_data->envelope)
			if (!index_fetch_envelope(rec, ctx))
				break;
		if (ctx->fetch_data->rfc822_size)
			if (!index_fetch_rfc822_size(rec, ctx))
				break;

		/* send the data written into temp string,
		   not including the trailing zero */
		ctx->first = ctx->str->len == orig_len;
		if (ctx->str->len > 0) {
			if (!ctx->first)
				ctx->str->len--;

			if (o_buffer_send(ctx->outbuf, ctx->str->str,
					  ctx->str->len) < 0)
				break;
		}

		data_written = TRUE;

		/* large data */
		if (ctx->fetch_data->rfc822)
			if (!index_fetch_send_rfc822(rec, ctx))
				break;
		if (ctx->fetch_data->rfc822_text)
			if (!index_fetch_send_rfc822_text(rec, ctx))
				break;
		if (ctx->fetch_data->rfc822_header)
			if (!index_fetch_send_rfc822_header(rec, ctx))
				break;

		sect = ctx->fetch_data->body_sections;
		for (; sect != NULL; sect = sect->next) {
			if (!index_fetch_body_section(rec, sect, ctx))
				break;
		}

		failed = FALSE;
	} while (0);

	if (data_written) {
		if (o_buffer_send(ctx->outbuf, ")\r\n", 3) < 0)
			failed = TRUE;
	}

	imap_msgcache_close(ctx->cache);
	return !failed;
}

int index_storage_fetch(Mailbox *box, MailFetchData *fetch_data,
			OBuffer *outbuf, int *all_found)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	FetchContext ctx;
	MailFetchBodyData *sect;
	int ret;

	if (!index_storage_sync_if_possible(ibox))
		return FALSE;

	memset(&ctx, 0, sizeof(ctx));

	if (!box->readonly) {
		/* If we have any BODY[..] sections, \Seen flag is added for
		   all messages */
		sect = fetch_data->body_sections;
		for (; sect != NULL; sect = sect->next) {
			if (!sect->peek) {
				ctx.update_seen = TRUE;
				break;
			}
		}
	}

	if (ctx.update_seen) {
		/* need exclusive lock to update the \Seen flags */
		if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_EXCLUSIVE))
			return mail_storage_set_index_error(ibox);

		/* if all messages are already seen, there's no point in
		   keeping exclusive lock */
		if (ibox->index->header->messages_count ==
		    ibox->index->header->seen_messages_count)
			ctx.update_seen = FALSE;
	}

	if (!ctx.update_seen) {
		if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
			return mail_storage_set_index_error(ibox);
	}

	ctx.box = box;
	ctx.storage = box->storage;
	ctx.cache = ibox->cache;
	ctx.index = ibox->index;
	ctx.custom_flags =
		mail_custom_flags_list_get(ibox->index->custom_flags);

	ctx.fetch_data = fetch_data;
	ctx.outbuf = outbuf;

	ret = index_messageset_foreach(ibox, fetch_data->messageset,
				       fetch_data->uidset,
				       index_fetch_mail, &ctx);

        mail_custom_flags_list_unref(ibox->index->custom_flags);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	if (all_found != NULL)
		*all_found = ret == 1;

	return ret > 0;
}
