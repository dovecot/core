/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "mail-storage-private.h"
#include "test-mail-storage.h"

extern struct mail_vfuncs test_mail_vfuncs;

struct mail *
test_mailbox_mail_alloc(struct mailbox_transaction_context *t,
			enum mail_fetch_field wanted_fields ATTR_UNUSED,
			struct mailbox_header_lookup_ctx *wanted_headers ATTR_UNUSED)
{
	struct mail_private *mail;
	pool_t pool;

	pool = pool_alloconly_create("test mail", 1024);
	mail = p_new(pool, struct mail_private, 1);
	mail->mail.box = t->box;
	mail->mail.transaction = t;
	mail->v = test_mail_vfuncs;
	mail->pool = pool;
	p_array_init(&mail->module_contexts, pool, 5);
	return &mail->mail;
}

static void test_mail_free(struct mail *mail)
{
	struct mail_private *pmail = (struct mail_private *)mail;

	pool_unref(&pmail->pool);
}

static void test_mail_set_seq(struct mail *mail, uint32_t seq)
{
	mail->seq = seq;
	mail->uid = seq;

	mail->expunged = TRUE;
	mail->has_nuls = FALSE;
	mail->has_no_nuls = FALSE;
}

static bool test_mail_set_uid(struct mail *mail, uint32_t uid)
{
	test_mail_set_seq(mail, uid);
	return TRUE;
}

static void test_mail_set_uid_cache_updates(struct mail *mail ATTR_UNUSED,
					    bool set ATTR_UNUSED)
{
}

static enum mail_flags test_mail_get_flags(struct mail *mail ATTR_UNUSED)
{
	return 0;
}

static const char *const *
test_mail_get_keywords(struct mail *mail ATTR_UNUSED)
{
	return t_new(const char *, 1);
}

static const ARRAY_TYPE(keyword_indexes) *
test_mail_get_keyword_indexes(struct mail *mail ATTR_UNUSED)
{
	ARRAY_TYPE(keyword_indexes) *kw_indexes;

	kw_indexes = t_new(ARRAY_TYPE(keyword_indexes), 1);
	t_array_init(kw_indexes, 1);
	(void)array_append_space(kw_indexes);
	return kw_indexes;
}

static uint64_t test_mail_get_modseq(struct mail *mail ATTR_UNUSED)
{
	return 0;
}

static int
test_mail_get_parts(struct mail *mail ATTR_UNUSED,
		    struct message_part **parts_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_date(struct mail *mail ATTR_UNUSED,
		   time_t *date_r ATTR_UNUSED, int *timezone_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_received_date(struct mail *mail ATTR_UNUSED,
			    time_t *date_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_save_date(struct mail *mail ATTR_UNUSED,
			time_t *date_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_test_mail_size(struct mail *mail ATTR_UNUSED,
			     uoff_t *size_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_physical_size(struct mail *mail ATTR_UNUSED,
			    uoff_t *size_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_first_header(struct mail *mail ATTR_UNUSED,
			   const char *field ATTR_UNUSED,
			   bool decode_to_utf8 ATTR_UNUSED,
			   const char **value_r)
{
	*value_r = NULL;
	return 0;
}

static int
test_mail_get_headers(struct mail *mail ATTR_UNUSED,
		      const char *field ATTR_UNUSED,
		      bool decode_to_utf8 ATTR_UNUSED,
		      const char *const **value_r)
{
	*value_r = NULL;
	return 0;
}

static int
test_mail_get_header_stream(struct mail *mail ATTR_UNUSED,
			    struct mailbox_header_lookup_ctx *headers ATTR_UNUSED,
			    struct istream **stream_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_stream(struct mail *mail ATTR_UNUSED,
		     struct message_size *hdr_size ATTR_UNUSED,
		     struct message_size *body_size ATTR_UNUSED,
		     struct istream **stream_r ATTR_UNUSED)
{
	return -1;
}

static int
test_mail_get_special(struct mail *mail ATTR_UNUSED,
		      enum mail_fetch_field field ATTR_UNUSED,
		      const char **value_r ATTR_UNUSED)
{
	return -1;
}

static struct mail *test_mail_get_real_mail(struct mail *mail)
{
	return mail;
}

static void
test_mail_update_flags(struct mail *mail ATTR_UNUSED,
		       enum modify_type modify_type ATTR_UNUSED,
		       enum mail_flags flags ATTR_UNUSED)
{
}

static void
test_mail_update_keywords(struct mail *mail ATTR_UNUSED,
			  enum modify_type modify_type ATTR_UNUSED,
			  struct mail_keywords *keywords ATTR_UNUSED)
{
}

static void test_mail_update_modseq(struct mail *mail ATTR_UNUSED,
				    uint64_t min_modseq ATTR_UNUSED)
{
}

static void test_mail_expunge(struct mail *mail ATTR_UNUSED)
{
}

static void test_mail_parse(struct mail *mail ATTR_UNUSED,
			    bool parse_body ATTR_UNUSED)
{
}

static void
test_mail_set_cache_corrupted(struct mail *mail ATTR_UNUSED,
			      enum mail_fetch_field field ATTR_UNUSED)
{
}

struct mail_vfuncs test_mail_vfuncs = {
	NULL,
	test_mail_free,
	test_mail_set_seq,
	test_mail_set_uid,
	test_mail_set_uid_cache_updates,

	test_mail_get_flags,
	test_mail_get_keywords,
	test_mail_get_keyword_indexes,
	test_mail_get_modseq,
	test_mail_get_parts,
	test_mail_get_date,
	test_mail_get_received_date,
	test_mail_get_save_date,
	test_mail_get_test_mail_size,
	test_mail_get_physical_size,
	test_mail_get_first_header,
	test_mail_get_headers,
	test_mail_get_header_stream,
	test_mail_get_stream,
	test_mail_get_special,
	test_mail_get_real_mail,
	test_mail_update_flags,
	test_mail_update_keywords,
	test_mail_update_modseq,
	NULL,
	test_mail_expunge,
	test_mail_parse,
	test_mail_set_cache_corrupted,
	NULL
};
