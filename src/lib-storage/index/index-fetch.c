/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "temp-string.h"
#include "rfc822-date.h"
#include "index-storage.h"
#include "index-fetch.h"
#include "mail-messageset.h"
#include "message-send.h"
#include "imap-util.h"
#include "imap-message-cache.h"

#include <unistd.h>

static void index_fetch_body(MailIndexRecord *rec, FetchContext *ctx)
{
	const char *body;

	body = imap_msgcache_get(ctx->cache, IMAP_CACHE_BODY);
	if (body != NULL)
		t_string_printfa(ctx->str, " BODY %s", body);
	else {
		i_error("Couldn't generate BODY for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
	}
}

static void index_fetch_bodystructure(MailIndexRecord *rec, FetchContext *ctx)
{
	const char *bodystructure;

	bodystructure = imap_msgcache_get(ctx->cache, IMAP_CACHE_BODYSTRUCTURE);
	if (bodystructure != NULL) {
		t_string_printfa(ctx->str, " BODYSTRUCTURE %s",
				 bodystructure);
	} else {
		i_error("Couldn't generate BODYSTRUCTURE for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
	}
}

static void index_fetch_envelope(MailIndexRecord *rec, FetchContext *ctx)
{
	const char *envelope;

	envelope = imap_msgcache_get(ctx->cache, IMAP_CACHE_ENVELOPE);
	if (envelope != NULL)
		t_string_printfa(ctx->str, " ENVELOPE (%s)", envelope);
	else {
		i_error("Couldn't generate ENVELOPE for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
	}
}

static void index_fetch_rfc822_size(MailIndexRecord *rec, FetchContext *ctx)
{
	t_string_printfa(ctx->str, " RFC822.SIZE %lu",
			 (unsigned long) rec->full_virtual_size);
}

static void index_fetch_flags(MailIndexRecord *rec, FetchContext *ctx)
{
	MailFlags flags;

	flags = rec->msg_flags;
	if (rec->uid >= ctx->index->first_recent_uid)
		flags |= MAIL_RECENT;
	if (ctx->update_seen)
		flags |= MAIL_SEEN;

	t_string_printfa(ctx->str, " FLAGS (%s)",
			 imap_write_flags(flags, ctx->custom_flags));
}

static void index_fetch_internaldate(MailIndexRecord *rec, FetchContext *ctx)
{
	t_string_printfa(ctx->str, " INTERNALDATE \"%s\"",
                         rfc822_to_date(rec->internal_date));
}

static void index_fetch_uid(MailIndexRecord *rec, FetchContext *ctx)
{
	t_string_printfa(ctx->str, " UID %u", rec->uid);
}

static void index_fetch_rfc822(MailIndexRecord *rec, FetchContext *ctx)
{
	MessageSize hdr_size, body_size;
	IOBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(ctx->cache, &inbuf,
				      &hdr_size, &body_size)) {
		i_error("Couldn't get RFC822 for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return;
	}

	str = t_strdup_printf(" RFC822 {%lu}\r\n",
			      (unsigned long) (hdr_size.virtual_size +
					       body_size.virtual_size));
	(void)io_buffer_send(ctx->outbuf, str, strlen(str));

	body_size.physical_size += hdr_size.physical_size;
	body_size.virtual_size += hdr_size.virtual_size;
	(void)message_send(ctx->outbuf, inbuf, &body_size, 0, (uoff_t)-1);
}

static void index_fetch_rfc822_header(MailIndexRecord *rec, FetchContext *ctx)
{
	MessageSize hdr_size;
	IOBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(ctx->cache, &inbuf, &hdr_size, NULL)) {
		i_error("Couldn't get RFC822.HEADER for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return;
	}

	str = t_strdup_printf(" RFC822.HEADER {%lu}\r\n",
			      (unsigned long) hdr_size.virtual_size);
	(void)io_buffer_send(ctx->outbuf, str, strlen(str));
	(void)message_send(ctx->outbuf, inbuf, &hdr_size, 0, (uoff_t)-1);
}

static void index_fetch_rfc822_text(MailIndexRecord *rec, FetchContext *ctx)
{
	MessageSize body_size;
	IOBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(ctx->cache, &inbuf, NULL, &body_size)) {
		i_error("Couldn't get RFC822.TEXT for UID %u (index %s)",
			rec->uid, ctx->index->filepath);
		return;
	}

	str = t_strdup_printf(" RFC822.TEXT {%lu}\r\n",
			      (unsigned long) body_size.virtual_size);
	(void)io_buffer_send(ctx->outbuf, str, strlen(str));
	(void)message_send(ctx->outbuf, inbuf, &body_size, 0, (uoff_t)-1);
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
	void *mail_cache_context;

	fields = index_get_cache(ctx->fetch_data);
	if (fields == 0)
		return;

        mail_cache_context = index_msgcache_get_context(ctx->index, rec);

	if (MSG_HAS_VALID_CRLF_DATA(rec)) {
		imap_msgcache_open(ctx->cache, rec->uid, fields,
				   rec->full_virtual_size,
				   rec->header_size, rec->body_size,
				   mail_cache_context);
	} else {
		imap_msgcache_open(ctx->cache, rec->uid, fields,
				   rec->full_virtual_size, 0, 0,
				   mail_cache_context);
	}
}

static int index_fetch_mail(MailIndex *index __attr_unused__,
			    MailIndexRecord *rec, unsigned int seq,
			    void *context)
{
	FetchContext *ctx = context;
	MailFetchBodyData *sect;

	ctx->str = t_string_new(2048);

	t_string_printfa(ctx->str, "* %u FETCH (", seq);
	(void)io_buffer_send(ctx->outbuf, ctx->str->str, ctx->str->len);
	t_string_truncate(ctx->str, 0);

	/* first see what we need to do. this way we don't first do some
	   light parsing and later notice that we need to do heavier parsing
	   anyway */
	index_msgcache_open(ctx, rec);

	if (ctx->fetch_data->uid)
		index_fetch_uid(rec, ctx);
	if (ctx->fetch_data->flags)
		index_fetch_flags(rec, ctx);
	if (ctx->fetch_data->internaldate)
		index_fetch_internaldate(rec, ctx);

	if (ctx->fetch_data->body)
		index_fetch_body(rec, ctx);
	if (ctx->fetch_data->bodystructure)
		index_fetch_bodystructure(rec, ctx);
	if (ctx->fetch_data->envelope)
		index_fetch_envelope(rec, ctx);
	if (ctx->fetch_data->rfc822_size)
		index_fetch_rfc822_size(rec, ctx);

	/* send the data written into temp string, skipping the initial space */
	if (ctx->str->len > 0) {
		(void)io_buffer_send(ctx->outbuf, ctx->str->str+1,
				     ctx->str->len-1);
	}

	/* large data */
	if (ctx->fetch_data->rfc822)
		index_fetch_rfc822(rec, ctx);
	if (ctx->fetch_data->rfc822_text)
		index_fetch_rfc822_text(rec, ctx);
	if (ctx->fetch_data->rfc822_header)
		index_fetch_rfc822_header(rec, ctx);

	sect = ctx->fetch_data->body_sections;
	for (; sect != NULL; sect = sect->next)
		index_fetch_body_section(rec, seq, sect, ctx);

	(void)io_buffer_send(ctx->outbuf, ")\r\n", 3);

	imap_msgcache_close(ctx->cache);
	return TRUE;
}

int index_storage_fetch(Mailbox *box, MailFetchData *fetch_data,
			IOBuffer *outbuf, int *all_found)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	FetchContext ctx;
	MailFetchBodyData *sect;
	int ret;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	memset(&ctx, 0, sizeof(ctx));
	ctx.box = box;
	ctx.cache = ibox->cache;
	ctx.index = ibox->index;
	ctx.custom_flags = flags_file_list_get(ibox->flagsfile);

	ctx.fetch_data = fetch_data;
	ctx.outbuf = outbuf;

	/* If we have any BODY[..] sections, \Seen flag is added for
	   all messages */
	sect = ctx.fetch_data->body_sections;
	for (; sect != NULL; sect = sect->next) {
		if (!sect->peek) {
			ctx.update_seen = TRUE;
			break;
		}
	}

	ret = index_messageset_foreach(ibox, fetch_data->messageset,
				       fetch_data->uidset,
				       index_fetch_mail, &ctx);

        flags_file_list_unref(ibox->flagsfile);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK))
		return mail_storage_set_index_error(ibox);

	if (all_found != NULL)
		*all_found = ret == 1;

	if (ret >= 1 && ctx.update_seen && !box->readonly) {
		/* BODY[..] was fetched, set \Seen flag for all messages.
		   This needs to be done separately because we need exclusive
		   lock for it */
		if (!index_storage_update_flags(box, fetch_data->messageset,
						fetch_data->uidset,
						MAIL_SEEN, NULL, MODIFY_ADD,
						NULL, NULL, NULL))
			return FALSE;
	}

	return ret >= 0;
}
