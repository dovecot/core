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

static int index_fetch_internaldate(MailIndexRecord *rec, FetchContext *ctx)
{
	time_t date;

	date = imap_msgcache_get_internal_date(ctx->cache);
	if (date != (time_t)-1) {
		t_string_printfa(ctx->str, "INTERNALDATE \"%s\" ",
				 imap_to_datetime(date));
		return TRUE;
	} else {
		mail_storage_set_critical(ctx->storage,
			"Couldn't generate INTERNALDATE for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}
}

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
	uoff_t size;

	size = imap_msgcache_get_virtual_size(ctx->cache);
	if (size == (uoff_t)-1) {
		mail_storage_set_critical(ctx->storage,
			"Couldn't get RFC822.SIZE for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return FALSE;
	}

	t_string_printfa(ctx->str, "RFC822.SIZE %"PRIuUOFF_T" ", size);
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
			 imap_write_flags(flags, ctx->custom_flags,
					  ctx->custom_flags_count));
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
	if (fetch_data->internaldate)
		field |= IMAP_CACHE_INTERNALDATE;

	if (fetch_data->rfc822_size)
		field |= IMAP_CACHE_VIRTUAL_SIZE;
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

static int fetch_msgcache_open(FetchContext *ctx, MailIndexRecord *rec)
{
	ImapCacheField fields;

	fields = index_get_cache(ctx->fetch_data);
	if (fields == 0)
		return TRUE;

	return index_msgcache_open(ctx->cache, ctx->index, rec, fields);
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

	/* first see what we need to do. this way we don't first do some
	   light parsing and later notice that we need to do heavier parsing
	   anyway */
	if (!fetch_msgcache_open(ctx, rec)) {
		/* most likely message not found, just ignore it. */
		imap_msgcache_close(ctx->cache);
		ctx->failed = TRUE;
		return TRUE;
	}

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

	failed = TRUE;
	data_written = FALSE;
	do {
		/* these can't fail */
		if (ctx->fetch_data->uid)
			index_fetch_uid(rec, ctx);
		if (ctx->fetch_data->flags || fetch_flags)
			index_fetch_flags(rec, ctx);

		/* rest can */
		if (ctx->fetch_data->internaldate)
			if (!index_fetch_internaldate(rec, ctx))
				break;
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

		if (fetch_data->rfc822 || fetch_data->rfc822_text)
			ctx.update_seen = TRUE;
	}

	/* need exclusive lock to update the \Seen flags */
	if (ctx.update_seen) {
		if (!index_storage_lock(ibox, MAIL_LOCK_EXCLUSIVE))
			return FALSE;
	}

	if (!index_storage_sync_and_lock(ibox, TRUE, MAIL_LOCK_SHARED))
		return FALSE;

	if (ctx.update_seen &&
	    ibox->index->header->messages_count ==
	    ibox->index->header->seen_messages_count) {
		/* if all messages are already seen, there's no point in
		   keeping exclusive lock */
		ctx.update_seen = FALSE;
		(void)index_storage_lock(ibox, MAIL_LOCK_SHARED);
	}

	ctx.box = box;
	ctx.storage = box->storage;
	ctx.cache = ibox->cache;
	ctx.index = ibox->index;
	ctx.custom_flags =
		mail_custom_flags_list_get(ibox->index->custom_flags);
        ctx.custom_flags_count = MAIL_CUSTOM_FLAGS_COUNT;

	ctx.fetch_data = fetch_data;
	ctx.outbuf = outbuf;

	ret = index_messageset_foreach(ibox, fetch_data->messageset,
				       fetch_data->uidset,
				       index_fetch_mail, &ctx);

	if (!index_storage_lock(ibox, MAIL_LOCK_UNLOCK))
		return FALSE;

	if (all_found != NULL)
		*all_found = ret == 1 && !ctx.failed;

	return ret > 0;
}
