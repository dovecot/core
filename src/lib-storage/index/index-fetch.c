/* Copyright (C) 2002 Timo Sirainen */

#include "lib.h"
#include "iobuffer.h"
#include "temp-string.h"
#include "rfc822-date.h"
#include "index-storage.h"
#include "index-fetch.h"
#include "mail-messageset.h"
#include "imap-util.h"
#include "imap-message-cache.h"
#include "imap-message-send.h"

#include <unistd.h>

static void index_fetch_body(MailIndexRecord *rec, FetchData *data)
{
	const char *body;

	body = imap_msgcache_get(data->cache, rec->uid, IMAP_CACHE_BODY);
	if (body != NULL)
		t_string_printfa(data->str, " BODY %s", body);
	else {
		i_error("Couldn't generate BODY for UID %u (index %s)",
			rec->uid, data->index->filepath);
	}
}

static void index_fetch_bodystructure(MailIndexRecord *rec, FetchData *data)
{
	const char *bodystructure;

	bodystructure = imap_msgcache_get(data->cache, rec->uid,
					  IMAP_CACHE_BODYSTRUCTURE);
	if (bodystructure != NULL) {
		t_string_printfa(data->str, " BODYSTRUCTURE %s",
				 bodystructure);
	} else {
		i_error("Couldn't generate BODYSTRUCTURE for UID %u (index %s)",
			rec->uid, data->index->filepath);
	}
}

static void index_fetch_envelope(MailIndexRecord *rec, FetchData *data)
{
	const char *envelope;

	envelope = imap_msgcache_get(data->cache, rec->uid,
				     IMAP_CACHE_ENVELOPE);
	if (envelope != NULL)
		t_string_printfa(data->str, " ENVELOPE (%s)", envelope);
	else {
		i_error("Couldn't generate ENVELOPE for UID %u (index %s)",
			rec->uid, data->index->filepath);
	}
}

static void index_fetch_rfc822_size(MailIndexRecord *rec, FetchData *data)
{
	t_string_printfa(data->str, " RFC822.SIZE %lu",
			 (unsigned long) rec->full_virtual_size);
}

static void index_fetch_flags(MailIndexRecord *rec, FetchData *data)
{
	MailFlags flags;

	flags = rec->msg_flags;
	if (rec->uid >= data->index->first_recent_uid)
		flags |= MAIL_RECENT;
	if (data->update_seen)
		flags |= MAIL_SEEN;

	t_string_printfa(data->str, " FLAGS (%s)",
			 imap_write_flags(flags, data->custom_flags));
}

static void index_fetch_internaldate(MailIndexRecord *rec, FetchData *data)
{
	t_string_printfa(data->str, " INTERNALDATE \"%s\"",
                         rfc822_to_date(rec->internal_date));
}

static void index_fetch_uid(MailIndexRecord *rec, FetchData *data)
{
	t_string_printfa(data->str, " UID %u", rec->uid);
}

static void index_fetch_rfc822(MailIndexRecord *rec, FetchData *data)
{
	MessageSize hdr_size, body_size;
	IOBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(data->cache, rec->uid,
				      &hdr_size, &body_size, &inbuf)) {
		i_error("Couldn't get RFC822 for UID %u (index %s)",
			rec->uid, data->index->filepath);
		return;
	}

	str = t_strdup_printf(" RFC822 {%lu}\r\n",
			      (unsigned long) (hdr_size.virtual_size +
					       body_size.virtual_size));
	(void)io_buffer_send(data->outbuf, str, strlen(str));

	body_size.physical_size += hdr_size.physical_size;
	body_size.virtual_size += hdr_size.virtual_size;
	(void)imap_message_send(data->outbuf, inbuf, &body_size, 0, -1);
}

static void index_fetch_rfc822_header(MailIndexRecord *rec, FetchData *data)
{
	MessageSize hdr_size;
	IOBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(data->cache, rec->uid,
				      &hdr_size, NULL, &inbuf)) {
		i_error("Couldn't get RFC822.HEADER for UID %u (index %s)",
			rec->uid, data->index->filepath);
		return;
	}

	str = t_strdup_printf(" RFC822.HEADER {%lu}\r\n",
			      (unsigned long) hdr_size.virtual_size);
	(void)io_buffer_send(data->outbuf, str, strlen(str));
	(void)imap_message_send(data->outbuf, inbuf, &hdr_size, 0, -1);
}

static void index_fetch_rfc822_text(MailIndexRecord *rec, FetchData *data)
{
	MessageSize body_size;
	IOBuffer *inbuf;
	const char *str;

	if (!imap_msgcache_get_rfc822(data->cache, rec->uid,
				      NULL, &body_size, &inbuf)) {
		i_error("Couldn't get RFC822.TEXT for UID %u (index %s)",
			rec->uid, data->index->filepath);
		return;
	}

	str = t_strdup_printf(" RFC822.TEXT {%lu}\r\n",
			      (unsigned long) body_size.virtual_size);
	(void)io_buffer_send(data->outbuf, str, strlen(str));
	(void)imap_message_send(data->outbuf, inbuf, &body_size, 0, -1);
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

static IOBuffer *inbuf_rewind(IOBuffer *inbuf, void *user_data __attr_unused__)
{
	if (!io_buffer_seek(inbuf, 0)) {
		i_error("inbuf_rewind: lseek() failed: %m");

		(void)close(inbuf->fd);
		io_buffer_destroy(inbuf);
		return NULL;
	}

	return inbuf;
}

static int index_cache_message(MailIndexRecord *rec, FetchData *data,
			       ImapCacheField field)
{
	IOBuffer *inbuf;

	inbuf = data->index->open_mail(data->index, rec);
	if (inbuf == NULL) {
		i_error("Couldn't open message UID %u (index %s)",
			rec->uid, data->index->filepath);
		return FALSE;
	}

	if (MSG_HAS_VALID_CRLF_DATA(rec)) {
		imap_msgcache_message(data->cache, rec->uid,
				      field, rec->full_virtual_size,
				      rec->header_size, rec->body_size,
				      inbuf, inbuf_rewind, NULL);
	} else {
		imap_msgcache_message(data->cache, rec->uid,
				      field, rec->full_virtual_size,
				      0, 0, inbuf, inbuf_rewind, NULL);
	}

	return TRUE;
}

static void index_cache_mail(FetchData *data, MailIndexRecord *rec)
{
	ImapCacheField fields;
	const char *value;

	fields = index_get_cache(data->fetch_data);
	if (imap_msgcache_is_cached(data->cache, rec->uid, fields))
		return;

	/* see if we can get some of the values from our index */
	if (fields & IMAP_CACHE_BODY) {
		value = data->index->lookup_field(data->index, rec,
						  FIELD_TYPE_BODY);
		imap_msgcache_set(data->cache, rec->uid,
				  IMAP_CACHE_BODY, value);
	}

	if (fields & IMAP_CACHE_BODYSTRUCTURE) {
		value = data->index->lookup_field(data->index, rec,
						  FIELD_TYPE_BODYSTRUCTURE);
		imap_msgcache_set(data->cache, rec->uid,
				  IMAP_CACHE_BODYSTRUCTURE, value);
	}

	if (fields & IMAP_CACHE_ENVELOPE) {
		value = data->index->lookup_field(data->index, rec,
						  FIELD_TYPE_ENVELOPE);
		imap_msgcache_set(data->cache, rec->uid,
				  IMAP_CACHE_ENVELOPE, value);
	}

	/* if we still don't have everything, open the message and
	   cache the needed fields */
	if (fields != 0 &&
	    !imap_msgcache_is_cached(data->cache, rec->uid, fields))
		(void)index_cache_message(rec, data, fields);
}

static int index_fetch_mail(MailIndex *index __attr_unused__,
			    MailIndexRecord *rec, unsigned int seq,
			    void *user_data)
{
	FetchData *data = user_data;
	MailFetchBodyData *sect;

	data->str = t_string_new(2048);

	t_string_printfa(data->str, "* %u FETCH (", seq);
	(void)io_buffer_send(data->outbuf, data->str->str, data->str->len);
	t_string_truncate(data->str, 0);

	/* first see what we need to do. this way we don't first do some
	   light parsing and later notice that we need to do heavier parsing
	   anyway */
	index_cache_mail(data, rec);

	if (data->fetch_data->uid)
		index_fetch_uid(rec, data);
	if (data->fetch_data->flags)
		index_fetch_flags(rec, data);
	if (data->fetch_data->internaldate)
		index_fetch_internaldate(rec, data);

	if (data->fetch_data->body)
		index_fetch_body(rec, data);
	if (data->fetch_data->bodystructure)
		index_fetch_bodystructure(rec, data);
	if (data->fetch_data->envelope)
		index_fetch_envelope(rec, data);
	if (data->fetch_data->rfc822_size)
		index_fetch_rfc822_size(rec, data);

	/* send the data written into temp string, skipping the initial space */
	if (data->str->len > 0) {
		(void)io_buffer_send(data->outbuf, data->str->str+1,
				     data->str->len-1);
	}

	/* large data */
	if (data->fetch_data->rfc822)
		index_fetch_rfc822(rec, data);
	if (data->fetch_data->rfc822_text)
		index_fetch_rfc822_text(rec, data);
	if (data->fetch_data->rfc822_header)
		index_fetch_rfc822_header(rec, data);

	sect = data->fetch_data->body_sections;
	for (; sect != NULL; sect = sect->next)
		index_fetch_body_section(rec, seq, sect, data);

	(void)io_buffer_send(data->outbuf, ")\r\n", 3);

	return TRUE;
}

int index_storage_fetch(Mailbox *box, MailFetchData *fetch_data,
			IOBuffer *outbuf, int *all_found)
{
	IndexMailbox *ibox = (IndexMailbox *) box;
	FetchData data;
	MailFetchBodyData *sect;
	int ret;

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_SHARED))
		return mail_storage_set_index_error(ibox);

	memset(&data, 0, sizeof(data));
	data.box = box;
	data.cache = ibox->cache;
	data.index = ibox->index;
	data.custom_flags = flags_file_list_get(ibox->flagsfile);

	data.fetch_data = fetch_data;
	data.outbuf = outbuf;

	/* If we have any BODY[..] sections, \Seen flag is added for
	   all messages */
	sect = data.fetch_data->body_sections;
	for (; sect != NULL; sect = sect->next) {
		if (!sect->peek) {
			data.update_seen = TRUE;
			break;
		}
	}

	if (fetch_data->uidset) {
		ret = mail_index_uidset_foreach(ibox->index,
						fetch_data->messageset,
						ibox->synced_messages_count,
						index_fetch_mail, &data);
	} else {
		ret = mail_index_messageset_foreach(ibox->index,
						    fetch_data->messageset,
						    ibox->synced_messages_count,
						    index_fetch_mail, &data);
	}

        flags_file_list_unref(ibox->flagsfile);

	if (!ibox->index->set_lock(ibox->index, MAIL_LOCK_UNLOCK) || ret == -1)
		return mail_storage_set_index_error(ibox);

	if (all_found != NULL)
		*all_found = ret == 1;

	if (ret >= 1 && data.update_seen && !box->readonly) {
		/* BODY[..] was fetched, set \Seen flag for all messages.
		   This needs to be done separately because we need exclusive
		   lock for it */
		if (!index_storage_update_flags(box, fetch_data->messageset,
						fetch_data->uidset,
						MAIL_SEEN, NULL, MODIFY_ADD,
						NULL, NULL, NULL))
			return FALSE;
	}

	return TRUE;
}
