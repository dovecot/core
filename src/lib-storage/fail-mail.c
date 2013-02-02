/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "fail-mail-storage.h"

extern struct mail_vfuncs fail_mail_vfuncs;

struct mail *
fail_mailbox_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields ATTR_UNUSED,
			struct mailbox_header_lookup_ctx *wanted_headers ATTR_UNUSED)
{
	struct mail_private *mail;
	pool_t pool;

	pool = pool_alloconly_create("fail mail", 1024);
	mail = p_new(pool, struct mail_private, 1);
	mail->mail.box = t->box;
	mail->mail.transaction = t;
	mail->v = fail_mail_vfuncs;
	mail->pool = pool;
	p_array_init(&mail->module_contexts, pool, 5);
	return &mail->mail;
}

static void fail_mail_free(struct mail *mail)
{
	struct mail_private *pmail = (struct mail_private *)mail;

	pool_unref(&pmail->pool);
}

static void fail_mail_set_seq(struct mail *mail, uint32_t seq, bool saving)
{
	mail->seq = seq;
	mail->uid = seq;
	mail->saving = saving;

	mail->expunged = TRUE;
	mail->has_nuls = FALSE;
	mail->has_no_nuls = FALSE;
}

static bool fail_mail_set_uid(struct mail *mail, uint32_t uid)
{
	fail_mail_set_seq(mail, uid, FALSE);
	return TRUE;
}

static void fail_mail_set_uid_cache_updates(struct mail *mail ATTR_UNUSED,
					    bool set ATTR_UNUSED)
{
}

static bool fail_mail_prefetch(struct mail *mail ATTR_UNUSED)
{
	return TRUE;
}

static void fail_mail_precache(struct mail *mail ATTR_UNUSED)
{
}

static void
fail_mail_add_temp_wanted_fields(struct mail *mail ATTR_UNUSED,
				 enum mail_fetch_field fields ATTR_UNUSED,
				 struct mailbox_header_lookup_ctx *headers ATTR_UNUSED)
{
}

static enum mail_flags fail_mail_get_flags(struct mail *mail ATTR_UNUSED)
{
	return 0;
}

static const char *const *
fail_mail_get_keywords(struct mail *mail ATTR_UNUSED)
{
	return t_new(const char *, 1);
}

static const ARRAY_TYPE(keyword_indexes) *
fail_mail_get_keyword_indexes(struct mail *mail ATTR_UNUSED)
{
	ARRAY_TYPE(keyword_indexes) *kw_indexes;

	kw_indexes = t_new(ARRAY_TYPE(keyword_indexes), 1);
	t_array_init(kw_indexes, 1);
	array_append_zero(kw_indexes);
	return kw_indexes;
}

static uint64_t fail_mail_get_modseq(struct mail *mail ATTR_UNUSED)
{
	return 0;
}

static int
fail_mail_get_parts(struct mail *mail ATTR_UNUSED,
		    struct message_part **parts_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_date(struct mail *mail ATTR_UNUSED,
		   time_t *date_r ATTR_UNUSED, int *timezone_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_received_date(struct mail *mail ATTR_UNUSED,
			    time_t *date_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_save_date(struct mail *mail ATTR_UNUSED,
			time_t *date_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_fail_mail_size(struct mail *mail ATTR_UNUSED,
			     uoff_t *size_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_physical_size(struct mail *mail ATTR_UNUSED,
			    uoff_t *size_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_first_header(struct mail *mail ATTR_UNUSED,
			   const char *field ATTR_UNUSED,
			   bool decode_to_utf8 ATTR_UNUSED,
			   const char **value_r)
{
	*value_r = NULL;
	return 0;
}

static int
fail_mail_get_headers(struct mail *mail ATTR_UNUSED,
		      const char *field ATTR_UNUSED,
		      bool decode_to_utf8 ATTR_UNUSED,
		      const char *const **value_r)
{
	*value_r = NULL;
	return 0;
}

static int
fail_mail_get_header_stream(struct mail *mail ATTR_UNUSED,
			    struct mailbox_header_lookup_ctx *headers ATTR_UNUSED,
			    struct istream **stream_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_stream(struct mail *mail ATTR_UNUSED, bool get_body ATTR_UNUSED,
		     struct message_size *hdr_size ATTR_UNUSED,
		     struct message_size *body_size ATTR_UNUSED,
		     struct istream **stream_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_binary_stream(struct mail *_mail ATTR_UNUSED,
			    const struct message_part *part ATTR_UNUSED,
			    bool include_hdr ATTR_UNUSED,
			    uoff_t *size_r ATTR_UNUSED,
			    unsigned int *body_lines_r ATTR_UNUSED,
			    bool *binary_r ATTR_UNUSED,
			    struct istream **stream_r ATTR_UNUSED)
{
	return -1;
}

static int
fail_mail_get_special(struct mail *mail ATTR_UNUSED,
		      enum mail_fetch_field field ATTR_UNUSED,
		      const char **value_r ATTR_UNUSED)
{
	return -1;
}

static struct mail *fail_mail_get_real_mail(struct mail *mail)
{
	return mail;
}

static void
fail_mail_update_flags(struct mail *mail ATTR_UNUSED,
		       enum modify_type modify_type ATTR_UNUSED,
		       enum mail_flags flags ATTR_UNUSED)
{
}

static void
fail_mail_update_keywords(struct mail *mail ATTR_UNUSED,
			  enum modify_type modify_type ATTR_UNUSED,
			  struct mail_keywords *keywords ATTR_UNUSED)
{
}

static void fail_mail_update_modseq(struct mail *mail ATTR_UNUSED,
				    uint64_t min_modseq ATTR_UNUSED)
{
}

static void fail_mail_expunge(struct mail *mail ATTR_UNUSED)
{
}

static void
fail_mail_set_cache_corrupted(struct mail *mail ATTR_UNUSED,
			      enum mail_fetch_field field ATTR_UNUSED)
{
}

struct mail_vfuncs fail_mail_vfuncs = {
	NULL,
	fail_mail_free,
	fail_mail_set_seq,
	fail_mail_set_uid,
	fail_mail_set_uid_cache_updates,
	fail_mail_prefetch,
	fail_mail_precache,
	fail_mail_add_temp_wanted_fields,

	fail_mail_get_flags,
	fail_mail_get_keywords,
	fail_mail_get_keyword_indexes,
	fail_mail_get_modseq,
	fail_mail_get_modseq,
	fail_mail_get_parts,
	fail_mail_get_date,
	fail_mail_get_received_date,
	fail_mail_get_save_date,
	fail_mail_get_fail_mail_size,
	fail_mail_get_physical_size,
	fail_mail_get_first_header,
	fail_mail_get_headers,
	fail_mail_get_header_stream,
	fail_mail_get_stream,
	fail_mail_get_binary_stream,
	fail_mail_get_special,
	fail_mail_get_real_mail,
	fail_mail_update_flags,
	fail_mail_update_keywords,
	fail_mail_update_modseq,
	fail_mail_update_modseq,
	NULL,
	fail_mail_expunge,
	fail_mail_set_cache_corrupted,
	NULL
};
