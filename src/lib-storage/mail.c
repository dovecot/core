/* Copyright (c) 2002-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "hex-binary.h"
#include "crc32.h"
#include "sha1.h"
#include "hostpid.h"
#include "mail-cache.h"
#include "mail-storage-private.h"

#include <time.h>

struct mail *mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields,
			struct mailbox_header_lookup_ctx *wanted_headers)
{
	struct mail *mail;

	T_BEGIN {
		mail = t->box->v.mail_alloc(t, wanted_fields, wanted_headers);
		hook_mail_allocated(mail);
	} T_END;

	return mail;
}

void mail_free(struct mail **mail)
{
	struct mail_private *p = (struct mail_private *)*mail;

	p->v.free(*mail);
	*mail = NULL;
}

void mail_set_seq(struct mail *mail, uint32_t seq)
{
	struct mail_private *p = (struct mail_private *)mail;

	p->v.set_seq(mail, seq);
}

bool mail_set_uid(struct mail *mail, uint32_t uid)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.set_uid(mail, uid);
}

enum mail_flags mail_get_flags(struct mail *mail)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_flags(mail);
}

uint64_t mail_get_modseq(struct mail *mail)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_modseq(mail);
}

const char *const *mail_get_keywords(struct mail *mail)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_keywords(mail);
}

const ARRAY_TYPE(keyword_indexes) *mail_get_keyword_indexes(struct mail *mail)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_keyword_indexes(mail);
}

int mail_get_parts(struct mail *mail, struct message_part **parts_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_parts(mail, parts_r);
}

int mail_get_date(struct mail *mail, time_t *date_r, int *timezone_r)
{
	struct mail_private *p = (struct mail_private *)mail;
	int tz;

	if (timezone_r == NULL)
		timezone_r = &tz;

	return p->v.get_date(mail, date_r, timezone_r);
}

int mail_get_received_date(struct mail *mail, time_t *date_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_received_date(mail, date_r);
}

int mail_get_save_date(struct mail *mail, time_t *date_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_save_date(mail, date_r);
}

int mail_get_virtual_size(struct mail *mail, uoff_t *size_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_virtual_size(mail, size_r);
}

int mail_get_physical_size(struct mail *mail, uoff_t *size_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_physical_size(mail, size_r);
}

int mail_get_first_header(struct mail *mail, const char *field,
			  const char **value_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_first_header(mail, field, FALSE, value_r);
}

int mail_get_first_header_utf8(struct mail *mail, const char *field,
			       const char **value_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_first_header(mail, field, TRUE, value_r);
}

int mail_get_headers(struct mail *mail, const char *field,
		     const char *const **value_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_headers(mail, field, FALSE, value_r);
}

int mail_get_headers_utf8(struct mail *mail, const char *field,
			  const char *const **value_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_headers(mail, field, TRUE, value_r);
}

int mail_get_header_stream(struct mail *mail,
			   struct mailbox_header_lookup_ctx *headers,
			   struct istream **stream_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_header_stream(mail, headers, stream_r);
}

int mail_set_aborted(struct mail *mail)
{
	mail_storage_set_error(mail->box->storage, MAIL_ERROR_NOTPOSSIBLE,
			       "Mail field not cached");
	return -1;
}

int mail_get_stream(struct mail *mail, struct message_size *hdr_size,
		    struct message_size *body_size, struct istream **stream_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	if (mail->lookup_abort != MAIL_LOOKUP_ABORT_NEVER)
		return mail_set_aborted(mail);
	return p->v.get_stream(mail, hdr_size, body_size, stream_r);
}

int mail_get_special(struct mail *mail, enum mail_fetch_field field,
		     const char **value_r)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_special(mail, field, value_r);
}

struct mail *mail_get_real_mail(struct mail *mail)
{
	struct mail_private *p = (struct mail_private *)mail;

	return p->v.get_real_mail(mail);
}

void mail_update_flags(struct mail *mail, enum modify_type modify_type,
		       enum mail_flags flags)
{
	struct mail_private *p = (struct mail_private *)mail;

	p->v.update_flags(mail, modify_type, flags);
}

void mail_update_keywords(struct mail *mail, enum modify_type modify_type,
			  struct mail_keywords *keywords)
{
	struct mail_private *p = (struct mail_private *)mail;

	p->v.update_keywords(mail, modify_type, keywords);
}

void mail_update_modseq(struct mail *mail, uint64_t min_modseq)
{
	struct mail_private *p = (struct mail_private *)mail;

	p->v.update_modseq(mail, min_modseq);
}

void mail_update_pop3_uidl(struct mail *mail, const char *uidl)
{
	struct mail_private *p = (struct mail_private *)mail;

	if (p->v.update_pop3_uidl != NULL)
		p->v.update_pop3_uidl(mail, uidl);
}

void mail_expunge(struct mail *mail)
{
	struct mail_private *p = (struct mail_private *)mail;

	p->v.expunge(mail);
}

void mail_set_expunged(struct mail *mail)
{
	mail_storage_set_error(mail->box->storage, MAIL_ERROR_EXPUNGED,
			       "Message was expunged");
	mail->expunged = TRUE;
}

bool mail_is_cached(struct mail *mail)
{
	return mail_cache_field_exists_any(mail->transaction->cache_view,
					   mail->seq);
}

void mail_parse(struct mail *mail, bool parse_body)
{
	struct mail_private *p = (struct mail_private *)mail;

	p->v.parse(mail, parse_body);
}

void mail_set_cache_corrupted(struct mail *mail, enum mail_fetch_field field)
{
	struct mail_private *p = (struct mail_private *)mail;

	p->v.set_cache_corrupted(mail, field);
}

const char *mail_generate_guid_string(void)
{
	static struct timespec ts = { 0, 0 };
	static unsigned int pid = 0;

	/* we'll use the current time in nanoseconds as the initial 64bit
	   counter. */
	if (ts.tv_sec == 0) {
		if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
			i_fatal("clock_gettime() failed: %m");
		pid = getpid();
	} else if ((uint32_t)ts.tv_nsec < (uint32_t)-1) {
		ts.tv_nsec++;
	} else {
		ts.tv_sec++;
		ts.tv_nsec = 0;
	}
	return t_strdup_printf("%04x%04lx%04x%s",
			       (unsigned int)ts.tv_nsec,
			       (unsigned long)ts.tv_sec,
			       pid, my_hostname);
}

void mail_generate_guid_128(uint8_t guid[MAIL_GUID_128_SIZE])
{
	static struct timespec ts = { 0, 0 };
	static uint8_t guid_static[8];
	uint32_t pid, host_crc;

	/* we'll use the current time in nanoseconds as the initial 64bit
	   counter. */
	if (ts.tv_sec == 0) {
		if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
			i_fatal("clock_gettime() failed: %m");
		pid = getpid();
		host_crc = crc32_str(my_hostname);

		guid_static[0] = (pid & 0x000000ff);
		guid_static[1] = (pid & 0x0000ff00) >> 8;
		guid_static[2] = (pid & 0x00ff0000) >> 16;
		guid_static[3] = (pid & 0xff000000) >> 24;
		guid_static[4] = (host_crc & 0x000000ff);
		guid_static[5] = (host_crc & 0x0000ff00) >> 8;
		guid_static[6] = (host_crc & 0x00ff0000) >> 16;
		guid_static[7] = (host_crc & 0xff000000) >> 24;
	} else if ((uint32_t)ts.tv_nsec < (uint32_t)-1) {
		ts.tv_nsec++;
	} else {
		ts.tv_sec++;
		ts.tv_nsec = 0;
	}

	guid[0] = (ts.tv_nsec & 0x000000ff);
	guid[1] = (ts.tv_nsec & 0x0000ff00) >> 8;
	guid[2] = (ts.tv_nsec & 0x00ff0000) >> 16;
	guid[3] = (ts.tv_nsec & 0xff000000) >> 24;
	guid[4] = (ts.tv_sec & 0x000000ff);
	guid[5] = (ts.tv_sec & 0x0000ff00) >> 8;
	guid[6] = (ts.tv_sec & 0x00ff0000) >> 16;
	guid[7] = (ts.tv_sec & 0xff000000) >> 24;
	memcpy(guid + 8, guid_static, 8);
}

void mail_generate_guid_128_hash(const char *guid,
				 uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	unsigned char sha1_sum[SHA1_RESULTLEN];
	buffer_t buf;

	buffer_create_data(&buf, guid_128, MAIL_GUID_128_SIZE);
	if (strlen(guid) != MAIL_GUID_128_SIZE*2 ||
	    hex_to_binary(guid, &buf) < 0 ||
	    buf.used != MAIL_GUID_128_SIZE) {
		/* not 128bit hex. use a hash of it instead. */
		buffer_set_used_size(&buf, 0);
		sha1_get_digest(guid, strlen(guid), sha1_sum);
#if SHA1_RESULTLEN < DBOX_GUID_BIN_LEN
#  error not possible
#endif
		buffer_append(&buf,
			      sha1_sum + SHA1_RESULTLEN - MAIL_GUID_128_SIZE,
			      MAIL_GUID_128_SIZE);
	}
}

bool mail_guid_128_is_empty(const uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	unsigned int i;

	for (i = 0; i < MAIL_GUID_128_SIZE; i++) {
		if (guid_128[i] != 0)
			return FALSE;
	}
	return TRUE;
}

const char *mail_guid_128_to_string(const uint8_t guid_128[MAIL_GUID_128_SIZE])
{
	return binary_to_hex(guid_128, MAIL_GUID_128_SIZE);
}
